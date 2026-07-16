use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;

use crate::classify::{FileOrigin, is_generated_directory, is_vendor_directory, origin_for_path};
use crate::{
    BoundedError, CancellationToken, ExclusionSummary, ProgressEvent, ScanConfiguration, ScanError,
    SkippedFile,
};

const MAX_PATTERNS: usize = 256;
const MAX_PATTERN_BYTES: usize = 1024;
const DISCOVERY_PROGRESS_INTERVAL: usize = 512;

pub(crate) struct DiscoveredFile {
    pub(crate) absolute: PathBuf,
    pub(crate) relative: String,
    pub(crate) origin: FileOrigin,
}

pub(crate) struct DiscoveryResult {
    pub(crate) files: Vec<DiscoveredFile>,
    pub(crate) entries_seen: usize,
    pub(crate) candidate_files: usize,
    pub(crate) symlinks_skipped: usize,
    pub(crate) nested_repositories_skipped: usize,
    pub(crate) skipped_files: Vec<SkippedFile>,
    pub(crate) errors: Vec<BoundedError>,
    pub(crate) exclusions: Vec<ExclusionSummary>,
}

pub(crate) enum ReadOutcome {
    Content(Vec<u8>),
    FileTooLarge,
    TotalLimit,
    NotRegular,
}

pub(crate) struct PathFilters {
    includes: GlobSet,
    excludes: GlobSet,
    include_is_empty: bool,
    exclude_directory_prefixes: Vec<String>,
}

impl PathFilters {
    pub(crate) fn compile(configuration: &ScanConfiguration) -> Result<Self, ScanError> {
        let includes = compile_patterns(&configuration.include_patterns, "include")?;
        let excludes = compile_patterns(&configuration.exclude_patterns, "exclude")?;
        let mut exclude_directory_prefixes = configuration
            .exclude_patterns
            .iter()
            .filter_map(|pattern| normalize_pattern(pattern).ok())
            .filter_map(|pattern| pattern.strip_suffix("/**").map(str::to_owned))
            .collect::<Vec<_>>();
        exclude_directory_prefixes.sort();
        exclude_directory_prefixes.dedup();
        Ok(Self {
            includes,
            excludes,
            include_is_empty: configuration.include_patterns.is_empty(),
            exclude_directory_prefixes,
        })
    }

    fn includes(&self, relative: &str) -> bool {
        self.include_is_empty || self.includes.is_match(relative)
    }

    fn excludes(&self, relative: &str, is_directory: bool) -> bool {
        self.excludes.is_match(relative)
            || (is_directory
                && (self.excludes.is_match(format!("{relative}/"))
                    || self
                        .exclude_directory_prefixes
                        .iter()
                        .any(|prefix| relative == prefix)))
    }
}

#[derive(Default)]
struct PruneCounters {
    generated: AtomicUsize,
    vendor: AtomicUsize,
    nested: AtomicUsize,
    pattern: AtomicUsize,
    vcs_metadata: AtomicUsize,
    unsupported_path: AtomicUsize,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn discover_files<F>(
    root: &Path,
    configuration: &ScanConfiguration,
    filters: &Arc<PathFilters>,
    cancellation: &CancellationToken,
    progress: &mut F,
) -> Result<DiscoveryResult, ScanError>
where
    F: FnMut(ProgressEvent),
{
    let counters = Arc::new(PruneCounters::default());
    let filter_root = root.to_owned();
    let filter_configuration = configuration.clone();
    let filter_set = Arc::clone(filters);
    let filter_counters = Arc::clone(&counters);
    let filter_cancellation = cancellation.clone();

    let mut builder = WalkBuilder::new(root);
    builder
        .follow_links(false)
        .hidden(!configuration.include_hidden)
        .git_ignore(configuration.respect_ignore_files)
        .git_global(configuration.respect_ignore_files)
        .git_exclude(configuration.respect_ignore_files)
        .ignore(configuration.respect_ignore_files)
        .parents(configuration.respect_ignore_files)
        .require_git(false)
        .filter_entry(move |entry| {
            should_descend(
                entry,
                &filter_root,
                &filter_configuration,
                &filter_set,
                &filter_counters,
                &filter_cancellation,
            )
        });
    if let Some(max_depth) = configuration.max_depth {
        builder.max_depth(Some(max_depth));
    }

    let mut selected = BTreeMap::<String, DiscoveredFile>::new();
    let mut skipped = BTreeMap::<String, String>::new();
    let mut errors = Vec::new();
    let mut errors_truncated = false;
    let mut entries_seen = 0_usize;
    let mut candidate_files = 0_usize;
    let mut symlinks_skipped = 0_usize;
    let mut include_mismatches = 0_usize;

    for entry in builder.build() {
        check_cancelled(cancellation)?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(_error) => {
                push_error(
                    &mut errors,
                    &mut errors_truncated,
                    configuration.max_errors,
                    "traversal-error",
                    None,
                    "A repository entry could not be traversed",
                );
                continue;
            }
        };
        entries_seen = entries_seen.saturating_add(1);
        let Some(relative) = safe_relative(root, entry.path()) else {
            if entry.depth() != 0 {
                push_error(
                    &mut errors,
                    &mut errors_truncated,
                    configuration.max_errors,
                    "unsupported-path",
                    None,
                    "A repository path could not be represented safely",
                );
            }
            continue;
        };

        if entries_seen == 1 || entries_seen.is_multiple_of(DISCOVERY_PROGRESS_INTERVAL) {
            progress(ProgressEvent::DiscoveryProgress {
                entries_seen,
                candidate_files,
            });
        }

        let Some(file_type) = entry.file_type() else {
            insert_bounded_skip(
                &mut skipped,
                relative,
                "unknown-file-type",
                configuration.max_files,
            );
            continue;
        };
        if file_type.is_symlink() {
            if filters.includes(&relative) {
                symlinks_skipped = symlinks_skipped.saturating_add(1);
                insert_bounded_skip(
                    &mut skipped,
                    relative,
                    "symlink-not-followed",
                    configuration.max_files,
                );
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if !filters.includes(&relative) {
            include_mismatches = include_mismatches.saturating_add(1);
            continue;
        }

        candidate_files = candidate_files.saturating_add(1);
        let discovered = DiscoveredFile {
            absolute: entry.into_path(),
            origin: origin_for_path(&relative),
            relative: relative.clone(),
        };
        if selected.len() < configuration.max_files {
            selected.insert(relative, discovered);
        } else if selected
            .last_key_value()
            .is_some_and(|(largest, _)| relative < *largest)
        {
            selected.pop_last();
            selected.insert(relative, discovered);
        }
    }
    check_cancelled(cancellation)?;

    if errors_truncated {
        errors.push(BoundedError {
            code: "error-limit-reached".into(),
            path: None,
            message: "Additional non-fatal errors were omitted".into(),
        });
    }
    let mut exclusions = vec![
        exclusion("exclude-pattern", counters.pattern.load(Ordering::Relaxed)),
        exclusion(
            "generated-directory",
            counters.generated.load(Ordering::Relaxed),
        ),
        exclusion("include-pattern-mismatch", include_mismatches),
        exclusion("nested-repository", counters.nested.load(Ordering::Relaxed)),
        exclusion(
            "vcs-metadata",
            counters.vcs_metadata.load(Ordering::Relaxed),
        ),
        exclusion(
            "unsupported-path",
            counters.unsupported_path.load(Ordering::Relaxed),
        ),
        exclusion("vendor-directory", counters.vendor.load(Ordering::Relaxed)),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    exclusions.sort();
    errors.sort_by(|left, right| (&left.path, &left.code).cmp(&(&right.path, &right.code)));

    Ok(DiscoveryResult {
        files: selected.into_values().collect(),
        entries_seen,
        candidate_files,
        symlinks_skipped,
        nested_repositories_skipped: counters.nested.load(Ordering::Relaxed),
        skipped_files: skipped
            .into_iter()
            .map(|(path, reason)| SkippedFile { path, reason })
            .collect(),
        errors,
        exclusions,
    })
}

fn should_descend(
    entry: &ignore::DirEntry,
    root: &Path,
    configuration: &ScanConfiguration,
    filters: &PathFilters,
    counters: &PruneCounters,
    cancellation: &CancellationToken,
) -> bool {
    if cancellation.is_cancelled() || entry.depth() == 0 {
        return !cancellation.is_cancelled();
    }
    let Some(relative) = safe_relative(root, entry.path()) else {
        counters.unsupported_path.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    let is_directory = entry
        .file_type()
        .is_some_and(|file_type| file_type.is_dir());
    if filters.excludes(&relative, is_directory) {
        counters.pattern.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    if matches!(name.as_ref(), ".git" | ".hg" | ".svn") {
        counters.vcs_metadata.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if !is_directory {
        return true;
    }
    if !configuration.include_generated && is_generated_directory(&name) {
        counters.generated.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if !configuration.include_vendor && is_vendor_directory(&name) {
        counters.vendor.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if !configuration.include_nested_repositories
        && fs::symlink_metadata(entry.path().join(".git")).is_ok()
    {
        counters.nested.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    true
}

pub(crate) fn read_file_no_follow(
    path: &Path,
    max_file_bytes: u64,
    remaining_total_bytes: u64,
    cancellation: Option<&CancellationToken>,
) -> io::Result<ReadOutcome> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Ok(ReadOutcome::NotRegular);
    }

    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Ok(ReadOutcome::NotRegular);
    }
    if metadata.len() > max_file_bytes {
        return Ok(ReadOutcome::FileTooLarge);
    }
    if metadata.len() > remaining_total_bytes {
        return Ok(ReadOutcome::TotalLimit);
    }

    let read_limit = max_file_bytes.min(remaining_total_bytes).saturating_add(1);
    let capacity = usize::try_from(metadata.len().min(1024 * 1024)).unwrap_or(1024 * 1024);
    let mut content = Vec::with_capacity(capacity);
    let mut remaining = read_limit;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while remaining > 0 {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
        }
        let amount = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let bytes_read = file.read(&mut buffer[..amount])?;
        if bytes_read == 0 {
            break;
        }
        content.extend_from_slice(&buffer[..bytes_read]);
        remaining = remaining.saturating_sub(bytes_read as u64);
    }
    let content_length = u64::try_from(content.len()).unwrap_or(u64::MAX);
    if content_length > max_file_bytes {
        Ok(ReadOutcome::FileTooLarge)
    } else if content_length > remaining_total_bytes {
        Ok(ReadOutcome::TotalLimit)
    } else {
        Ok(ReadOutcome::Content(content))
    }
}

pub(crate) fn canonical_repository(path: &Path) -> Result<PathBuf, ScanError> {
    let canonical = fs::canonicalize(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => ScanError::InvalidRepository("path does not exist".into()),
        io::ErrorKind::PermissionDenied => {
            ScanError::InvalidRepository("path is not accessible".into())
        }
        _ => ScanError::InvalidRepository("path could not be resolved".into()),
    })?;
    if !canonical.is_dir() {
        return Err(ScanError::InvalidRepository(
            "path is not a directory".into(),
        ));
    }
    Ok(canonical)
}

pub(crate) fn safe_relative(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str()?;
                if value.contains('\\') || value.chars().any(char::is_control) {
                    return None;
                }
                parts.push(value.to_owned());
            }
            _ => return None,
        }
    }
    if parts.is_empty() {
        None
    } else {
        let relative = parts.join("/");
        if relative.as_bytes().get(1) == Some(&b':') {
            None
        } else {
            Some(relative)
        }
    }
}

fn compile_patterns(patterns: &[String], kind: &str) -> Result<GlobSet, ScanError> {
    if patterns.len() > MAX_PATTERNS {
        return Err(ScanError::InvalidConfiguration(format!(
            "at most {MAX_PATTERNS} {kind} patterns are allowed"
        )));
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let normalized = normalize_pattern(pattern).map_err(|message| {
            ScanError::InvalidConfiguration(format!("invalid {kind} pattern: {message}"))
        })?;
        add_glob(&mut builder, &normalized, kind)?;
        if !normalized.contains('/') {
            add_glob(&mut builder, &format!("**/{normalized}"), kind)?;
        }
    }
    builder.build().map_err(|_| {
        ScanError::InvalidConfiguration(format!("{kind} patterns could not be compiled"))
    })
}

fn add_glob(builder: &mut GlobSetBuilder, pattern: &str, kind: &str) -> Result<(), ScanError> {
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .backslash_escape(false)
        .build()
        .map_err(|_| ScanError::InvalidConfiguration(format!("invalid {kind} glob syntax")))?;
    builder.add(glob);
    Ok(())
}

fn normalize_pattern(pattern: &str) -> Result<String, &'static str> {
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    if pattern.is_empty() {
        return Err("patterns cannot be empty");
    }
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err("pattern is too long");
    }
    if pattern.contains(['\0', '\\'])
        || pattern.chars().any(char::is_control)
        || pattern.starts_with('/')
        || pattern.as_bytes().get(1) == Some(&b':')
    {
        return Err("patterns must be slash-normalized and repository-relative");
    }
    if pattern.split('/').any(|component| component == "..") {
        return Err("parent traversal is not allowed");
    }
    Ok(pattern.trim_end_matches('/').to_owned())
}

fn insert_bounded_skip(
    skipped: &mut BTreeMap<String, String>,
    path: String,
    reason: &str,
    maximum: usize,
) {
    if skipped.len() < maximum {
        skipped.insert(path, reason.into());
    } else if skipped
        .last_key_value()
        .is_some_and(|(largest, _)| path < *largest)
    {
        skipped.pop_last();
        skipped.insert(path, reason.into());
    }
}

fn push_error(
    errors: &mut Vec<BoundedError>,
    truncated: &mut bool,
    maximum: usize,
    code: &str,
    path: Option<String>,
    message: &str,
) {
    if errors.len() < maximum.saturating_sub(1) {
        errors.push(BoundedError {
            code: code.into(),
            path,
            message: message.into(),
        });
    } else {
        *truncated = true;
    }
}

fn exclusion(reason: &str, count: usize) -> Option<ExclusionSummary> {
    (count > 0).then(|| ExclusionSummary {
        reason: reason.into(),
        count,
    })
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
    use super::*;

    #[test]
    fn patterns_are_relative_bounded_and_match_nested_files() -> Result<(), ScanError> {
        let mut configuration = ScanConfiguration {
            include_patterns: vec!["*.rs".into()],
            exclude_patterns: vec!["src/private/**".into()],
            ..ScanConfiguration::default()
        };
        let filters = PathFilters::compile(&configuration)?;
        assert!(filters.includes("src/main.rs"));
        assert!(!filters.includes("README.md"));
        assert!(filters.excludes("src/private", true));
        assert!(filters.excludes("src/private/key.rs", false));

        configuration.include_patterns = vec!["../outside".into()];
        assert!(matches!(
            PathFilters::compile(&configuration),
            Err(ScanError::InvalidConfiguration(_))
        ));
        Ok(())
    }
}
