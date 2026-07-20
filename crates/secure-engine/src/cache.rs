use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::graph::GRAPH_EXTRACTOR_VERSION;
use crate::parser::{
    ParseOutput, ParserMode, TREE_SITTER_VERSION, provenance, validate_cached_output,
};
use crate::workspace::{ReadOutcome, read_file_no_follow};
use crate::{CacheControl, CancellationToken, ScanConfiguration, ScanError};

const CACHE_FORMAT: &str = "secure-parse-cache-v15";
const MAX_CACHE_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CACHE_DIRECTORY_ENTRIES: usize = 100_000;
static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default)]
pub(crate) struct CacheStats {
    pub(crate) hits: usize,
    pub(crate) misses: usize,
    pub(crate) writes: usize,
    pub(crate) ignored: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct CacheEnvelope {
    format: String,
    key: String,
    output: ParseOutput,
}

struct CacheFile {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

pub(crate) struct ParseCache {
    directory: Option<PathBuf>,
    maximum_bytes: u64,
    stats: CacheStats,
}

impl ParseCache {
    pub(crate) fn open(
        repository: &Path,
        configuration: &ScanConfiguration,
        control: &CacheControl,
        cancellation: &CancellationToken,
    ) -> Result<Self, ScanError> {
        if !configuration.parse_cache_enabled && !control.clear_before_scan {
            return Ok(Self {
                directory: None,
                maximum_bytes: configuration.max_cache_bytes,
                stats: CacheStats::default(),
            });
        }
        check_cancelled(cancellation)?;
        let base = control.directory.clone().unwrap_or_else(default_cache_base);
        let repository_key = repository_cache_key(repository);
        let directory = base.join(CACHE_FORMAT).join(repository_key);
        let mut cache = Self {
            directory: None,
            maximum_bytes: configuration.max_cache_bytes,
            stats: CacheStats::default(),
        };
        if control.clear_before_scan {
            match retire_directory(&directory, cancellation) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    return Err(ScanError::Cancelled);
                }
                Err(_error) => cache.stats.ignored = cache.stats.ignored.saturating_add(1),
            }
        }
        if !configuration.parse_cache_enabled {
            check_cancelled(cancellation)?;
            return Ok(cache);
        }
        match create_private_directory(&directory) {
            Ok(()) if directory_is_safe(&directory) => cache.directory = Some(directory),
            Ok(()) | Err(_) => cache.stats.ignored = cache.stats.ignored.saturating_add(1),
        }
        check_cancelled(cancellation)?;
        Ok(cache)
    }

    pub(crate) fn key(
        path: &str,
        content_fingerprint: &str,
        mode: ParserMode,
        configuration: &ScanConfiguration,
    ) -> Result<String, ScanError> {
        let configuration = serde_json::to_vec(configuration)
            .map_err(|_| ScanError::Internal("cache configuration could not be encoded".into()))?;
        let parser_provenance = provenance(mode);
        let mut hasher = blake3::Hasher::new();
        for value in [
            CACHE_FORMAT.as_bytes(),
            path.as_bytes(),
            content_fingerprint.as_bytes(),
            mode.as_str().as_bytes(),
            parser_provenance.parser.as_bytes(),
            TREE_SITTER_VERSION.as_bytes(),
            parser_provenance.extractor_version.as_bytes(),
            GRAPH_EXTRACTOR_VERSION.as_bytes(),
            parser_provenance.grammar.as_bytes(),
            &configuration,
        ] {
            hash_value(&mut hasher, value);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    pub(crate) fn load(
        &mut self,
        key: &str,
        expected_path: &str,
        expected_mode: ParserMode,
        configuration: &ScanConfiguration,
        cancellation: &CancellationToken,
    ) -> Result<Option<ParseOutput>, ScanError> {
        let Some(directory) = &self.directory else {
            return Ok(None);
        };
        check_cancelled(cancellation)?;
        let path = directory.join(format!("{key}.json"));
        let maximum = self.maximum_bytes.min(MAX_CACHE_ENTRY_BYTES);
        let bytes = match read_file_no_follow(&path, maximum, maximum, Some(cancellation)) {
            Ok(ReadOutcome::Content(bytes)) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.stats.misses = self.stats.misses.saturating_add(1);
                return Ok(None);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                return Err(ScanError::Cancelled);
            }
            Ok(ReadOutcome::FileTooLarge | ReadOutcome::TotalLimit | ReadOutcome::NotRegular)
            | Err(_) => {
                self.ignore_entry(&path);
                self.stats.misses = self.stats.misses.saturating_add(1);
                return Ok(None);
            }
        };
        let envelope = serde_json::from_slice::<CacheEnvelope>(&bytes).ok();
        let Some(envelope) = envelope.filter(|entry| {
            entry.format == CACHE_FORMAT
                && entry.key == key
                && validate_cached_output(
                    &entry.output,
                    expected_path,
                    expected_mode,
                    configuration,
                )
        }) else {
            self.ignore_entry(&path);
            self.stats.misses = self.stats.misses.saturating_add(1);
            return Ok(None);
        };
        self.stats.hits = self.stats.hits.saturating_add(1);
        Ok(Some(envelope.output))
    }

    pub(crate) fn store(
        &mut self,
        key: &str,
        output: &ParseOutput,
        cancellation: &CancellationToken,
    ) -> Result<(), ScanError> {
        let Some(directory) = self.directory.clone() else {
            return Ok(());
        };
        check_cancelled(cancellation)?;
        let envelope = CacheEnvelope {
            format: CACHE_FORMAT.into(),
            key: key.into(),
            output: output.clone(),
        };
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|_| ScanError::Internal("parse cache entry could not be encoded".into()))?;
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if length > self.maximum_bytes.min(MAX_CACHE_ENTRY_BYTES) {
            self.stats.ignored = self.stats.ignored.saturating_add(1);
            return Ok(());
        }
        if !self.make_room(&directory, length, cancellation)? {
            self.stats.ignored = self.stats.ignored.saturating_add(1);
            return Ok(());
        }
        let target = directory.join(format!("{key}.json"));
        let temporary = temporary_path(&directory, key);
        let result = write_atomic(&temporary, &target, &bytes, cancellation);
        if result.is_err() {
            let _ignored = fs::remove_file(&temporary);
        }
        match result {
            Ok(()) => {
                self.stats.writes = self.stats.writes.saturating_add(1);
                let _bounded = self.make_room(&directory, 0, cancellation)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                return Err(ScanError::Cancelled);
            }
            Err(_error) => self.stats.ignored = self.stats.ignored.saturating_add(1),
        }
        Ok(())
    }

    pub(crate) fn stats(&self) -> CacheStats {
        self.stats.clone()
    }

    fn ignore_entry(&mut self, path: &Path) {
        self.stats.ignored = self.stats.ignored.saturating_add(1);
        let _ignored = fs::remove_file(path);
    }

    fn make_room(
        &mut self,
        directory: &Path,
        incoming: u64,
        cancellation: &CancellationToken,
    ) -> Result<bool, ScanError> {
        let mut files = Vec::new();
        let mut total = 0_u64;
        let Ok(entries) = fs::read_dir(directory) else {
            return Ok(false);
        };
        for entry in entries {
            check_cancelled(cancellation)?;
            if files.len() >= MAX_CACHE_DIRECTORY_ENTRIES {
                return Ok(false);
            }
            let Ok(entry) = entry else {
                self.stats.ignored = self.stats.ignored.saturating_add(1);
                continue;
            };
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                self.stats.ignored = self.stats.ignored.saturating_add(1);
                continue;
            }
            total = total.saturating_add(metadata.len());
            files.push(CacheFile {
                path,
                size: metadata.len(),
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
        files.sort_by(|left, right| {
            (&left.modified, &left.path).cmp(&(&right.modified, &right.path))
        });
        for file in files {
            if total.saturating_add(incoming) <= self.maximum_bytes {
                break;
            }
            check_cancelled(cancellation)?;
            if fs::remove_file(&file.path).is_ok() {
                total = total.saturating_sub(file.size);
            }
        }
        Ok(total.saturating_add(incoming) <= self.maximum_bytes)
    }
}

fn default_cache_base() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|value| !value.is_empty() && Path::new(value).is_absolute())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_RUNTIME_DIR")
                .filter(|value| !value.is_empty() && Path::new(value).is_absolute())
                .map(PathBuf::from)
        })
        .unwrap_or_else(std::env::temp_dir)
        .join("secure-engine")
}

fn repository_cache_key(repository: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_value(&mut hasher, repository.as_os_str().as_encoded_bytes());
    hasher.finalize().to_hex().to_string()
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

fn directory_is_safe(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

fn retire_directory(path: &Path, cancellation: &CancellationToken) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if cancellation.is_cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache has no parent"))?;
    let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let retired = parent.join(format!(".retired-{}-{counter}", std::process::id()));
    fs::rename(path, &retired)?;
    if cancellation.is_cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
    }
    fs::remove_dir_all(retired)
}

fn temporary_path(directory: &Path, key: &str) -> PathBuf {
    let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(".");
    name.push(key);
    name.push(format!(".tmp-{}-{counter}", std::process::id()));
    directory.join(name)
}

fn write_atomic(
    temporary: &Path,
    target: &Path,
    bytes: &[u8],
    cancellation: &CancellationToken,
) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options.open(temporary)?;
    for chunk in bytes.chunks(64 * 1024) {
        if cancellation.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
        }
        file.write_all(chunk)?;
    }
    file.sync_all()?;
    if cancellation.is_cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
    }
    fs::rename(temporary, target)
}

fn hash_value(hasher: &mut blake3::Hasher, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(&length.to_le_bytes());
    hasher.update(value);
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), ScanError> {
    if cancellation.is_cancelled() {
        Err(ScanError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn cache_reuses_valid_entries_and_ignores_corruption() -> Result<(), Box<dyn std::error::Error>>
    {
        let repository = tempdir()?;
        let cache_root = tempdir()?;
        let configuration = ScanConfiguration::default();
        let control = CacheControl {
            directory: Some(cache_root.path().into()),
            clear_before_scan: false,
        };
        let cancellation = CancellationToken::new();
        let mut cache =
            ParseCache::open(repository.path(), &configuration, &control, &cancellation)?;
        let key = ParseCache::key("app.ts", "abc", ParserMode::TypeScript, &configuration)?;
        let output = crate::parser::parse_source(
            "app.ts",
            b"export const value = 1;",
            ParserMode::TypeScript,
            &configuration,
            &cancellation,
        )?;
        assert!(
            cache
                .load(
                    &key,
                    "app.ts",
                    ParserMode::TypeScript,
                    &configuration,
                    &cancellation,
                )?
                .is_none()
        );
        cache.store(&key, &output, &cancellation)?;
        assert_eq!(
            cache.load(
                &key,
                "app.ts",
                ParserMode::TypeScript,
                &configuration,
                &cancellation,
            )?,
            Some(output.clone())
        );
        let directory = cache
            .directory
            .clone()
            .ok_or("cache directory unavailable")?;
        let entry_path = directory.join(format!("{key}.json"));
        let mut tampered: serde_json::Value = serde_json::from_slice(&fs::read(&entry_path)?)?;
        tampered["output"]["facts"][0]["name"] = serde_json::Value::String("tampered".into());
        fs::write(&entry_path, serde_json::to_vec(&tampered)?)?;
        assert!(
            cache
                .load(
                    &key,
                    "app.ts",
                    ParserMode::TypeScript,
                    &configuration,
                    &cancellation,
                )?
                .is_none()
        );
        fs::write(&entry_path, b"not json")?;
        assert!(
            cache
                .load(
                    &key,
                    "app.ts",
                    ParserMode::TypeScript,
                    &configuration,
                    &cancellation,
                )?
                .is_none()
        );
        assert!(cache.stats().ignored >= 1);
        Ok(())
    }

    #[test]
    fn cache_key_changes_with_content_mode_and_relevant_configuration() -> Result<(), ScanError> {
        let configuration = ScanConfiguration::default();
        let baseline = ParseCache::key("app.ts", "aaa", ParserMode::TypeScript, &configuration)?;
        let changed_content =
            ParseCache::key("app.ts", "bbb", ParserMode::TypeScript, &configuration)?;
        let changed_mode = ParseCache::key("app.ts", "aaa", ParserMode::Tsx, &configuration)?;
        let rust = ParseCache::key("app.ts", "aaa", ParserMode::Rust, &configuration)?;
        let python = ParseCache::key("app.ts", "aaa", ParserMode::Python, &configuration)?;
        let go = ParseCache::key("app.ts", "aaa", ParserMode::Go, &configuration)?;
        let mut changed_configuration = configuration.clone();
        changed_configuration.max_facts_per_file = 5;
        let changed_limit = ParseCache::key(
            "app.ts",
            "aaa",
            ParserMode::TypeScript,
            &changed_configuration,
        )?;
        assert_ne!(baseline, changed_content);
        assert_ne!(baseline, changed_mode);
        assert_ne!(baseline, rust);
        assert_ne!(rust, python);
        assert_ne!(python, go);
        assert_ne!(baseline, changed_limit);
        Ok(())
    }

    #[test]
    fn cache_writes_honor_bounds_and_cancellation_without_partial_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = tempdir()?;
        let cache_root = tempdir()?;
        let mut configuration = ScanConfiguration {
            max_cache_bytes: 1,
            ..ScanConfiguration::default()
        };
        let control = CacheControl {
            directory: Some(cache_root.path().into()),
            clear_before_scan: false,
        };
        let cancellation = CancellationToken::new();
        let mut cache =
            ParseCache::open(repository.path(), &configuration, &control, &cancellation)?;
        let output = crate::parser::parse_source(
            "app.js",
            b"export function app() { return fetch('/api'); }",
            ParserMode::JavaScript,
            &configuration,
            &cancellation,
        )?;
        let key = ParseCache::key("app.js", "content", ParserMode::JavaScript, &configuration)?;
        cache.store(&key, &output, &cancellation)?;
        assert_eq!(cache.stats().writes, 0);
        assert!(cache.stats().ignored >= 1);

        configuration.max_cache_bytes = 1024 * 1024;
        let mut cache = ParseCache::open(
            repository.path(),
            &configuration,
            &control,
            &CancellationToken::new(),
        )?;
        let key = ParseCache::key("app.js", "content", ParserMode::JavaScript, &configuration)?;
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            cache.store(&key, &output, &cancelled),
            Err(ScanError::Cancelled)
        ));
        let directory = cache.directory.ok_or("cache directory unavailable")?;
        assert!(
            fs::read_dir(directory)?
                .filter_map(Result::ok)
                .all(|entry| {
                    entry.path().extension().and_then(|value| value.to_str()) != Some("json")
                })
        );
        Ok(())
    }
}
