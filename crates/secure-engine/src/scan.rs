use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use ignore::WalkBuilder;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{
    BoundedError, CapabilityEvidence, ENGINE_VERSION, EntryPointEvidence, FileRecord, Finding,
    FrameworkEvidence, LanguageSummary, Limitation, ManifestEvidence, ProgressEvent,
    RepositoryIdentity, SCHEMA_VERSION, ScanMetadata, ScanReport, ScanRequest, SkippedFile,
    SourceLocation, SourceSpan, TrustBoundaryEvidence,
};

const MAX_ERRORS: usize = 100;

/// Cooperative cancellation shared safely across threads.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a token in the active state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Repeated calls are harmless.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Reports whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Fatal scan outcome. Partial reports are never carried by an error.
#[derive(Debug)]
pub enum ScanError {
    /// Repository input is absent, not a directory, or cannot be canonicalized.
    InvalidRepository(String),
    /// Cooperative cancellation was observed.
    Cancelled,
    /// Report construction failed unexpectedly.
    Internal(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRepository(message) => write!(formatter, "invalid repository: {message}"),
            Self::Cancelled => formatter.write_str("scan cancelled"),
            Self::Internal(message) => write!(formatter, "internal scan failure: {message}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Inventories a repository through the API shared by CLI and desktop.
///
/// The callback receives typed progress. Cancellation returns no report, which lets callers
/// publish results atomically and prevents incomplete output from appearing complete.
///
/// # Errors
///
/// Returns [`ScanError::InvalidRepository`] for unusable input, [`ScanError::Cancelled`] after a
/// cancellation request, or [`ScanError::Internal`] when a complete report cannot be finalized.
#[allow(clippy::too_many_lines)]
pub fn scan_repository<F>(
    request: &ScanRequest,
    cancellation: &CancellationToken,
    mut progress: F,
) -> Result<ScanReport, ScanError>
where
    F: FnMut(ProgressEvent),
{
    let started = OffsetDateTime::now_utc();
    let timer = Instant::now();
    if request.configuration.max_files == 0 || request.configuration.max_file_bytes == 0 {
        return Err(ScanError::InvalidRepository(
            "resource limits must be greater than zero".into(),
        ));
    }
    let root = canonical_repository(&request.repository)?;
    check_cancelled(cancellation)?;
    progress(ProgressEvent::Discovering);

    let (mut discovered, discovered_total, mut errors) = discover_files(&root, request);
    discovered.sort_by(|left, right| left.1.cmp(&right.1));

    let mut limitations = phase_zero_limitations();
    if !request.configuration.include_hidden {
        limitations.push(Limitation {
            code: "hidden-files-excluded".into(),
            message: "Hidden files and directories were excluded by configuration".into(),
        });
    }
    if request.configuration.respect_ignore_files {
        limitations.push(Limitation {
            code: "ignored-files-excluded".into(),
            message: "Inputs matched by repository ignore rules were excluded".into(),
        });
    }
    if discovered_total > request.configuration.max_files {
        limitations.push(Limitation {
            code: "file-limit-reached".into(),
            message: format!(
                "Only the first {} of {discovered_total} repository-relative files were considered",
                request.configuration.max_files,
            ),
        });
    }

    let total = discovered.len();
    let mut files = Vec::with_capacity(total);
    let mut skipped_files = Vec::new();
    let mut manifests = Vec::new();
    let mut frameworks = Vec::new();
    let mut entry_points = Vec::new();
    let mut capabilities = Vec::new();
    let mut trust_boundaries = Vec::new();
    let mut language_totals: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    let mut repository_hasher = blake3::Hasher::new();

    for (index, (absolute, relative)) in discovered.iter().enumerate() {
        check_cancelled(cancellation)?;
        progress(ProgressEvent::Inspecting {
            completed: index,
            total,
            path: relative.clone(),
        });

        let Ok(metadata) = fs::metadata(absolute) else {
            push_error(
                &mut errors,
                "metadata-unavailable",
                Some(relative.clone()),
                "File metadata could not be read",
            );
            continue;
        };
        if metadata.len() > request.configuration.max_file_bytes {
            skipped_files.push(SkippedFile {
                path: relative.clone(),
                reason: "file-too-large".into(),
            });
            continue;
        }

        let Ok(content) = fs::read(absolute) else {
            push_error(
                &mut errors,
                "read-failed",
                Some(relative.clone()),
                "File contents could not be read",
            );
            continue;
        };
        check_cancelled(cancellation)?;

        let content_fingerprint = blake3::hash(&content).to_hex().to_string();
        update_length_prefixed(&mut repository_hasher, relative.as_bytes());
        update_length_prefixed(&mut repository_hasher, &content);

        let language = detect_language(relative).map(str::to_owned);
        if let Some(name) = &language {
            let total_for_language = language_totals.entry(name.clone()).or_default();
            total_for_language.0 += 1;
            total_for_language.1 = total_for_language.1.saturating_add(metadata.len());
        }

        let manifest_kind = manifest_kind(relative);
        let kind = classify_file(relative, manifest_kind, language.as_deref());
        files.push(FileRecord {
            path: relative.clone(),
            kind: kind.into(),
            size_bytes: metadata.len(),
            content_fingerprint,
            language,
        });

        if let Some(manifest_kind) = manifest_kind {
            let location = start_location(relative);
            manifests.push(ManifestEvidence {
                kind: manifest_kind.into(),
                fingerprint: evidence_fingerprint("manifest", manifest_kind, &location),
                location: location.clone(),
            });
            capabilities.push(CapabilityEvidence {
                capability: "dependency-management".into(),
                reason: format!("Detected {manifest_kind} manifest"),
                fingerprint: evidence_fingerprint("capability", manifest_kind, &location),
                evidence: location.clone(),
            });
            trust_boundaries.push(TrustBoundaryEvidence {
                kind: "dependency-supply-chain".into(),
                description: "Declared third-party dependency boundary".into(),
                fingerprint: evidence_fingerprint("boundary", manifest_kind, &location),
                evidence: location,
            });
            detect_frameworks(relative, &content, &mut frameworks, &mut trust_boundaries);
        }

        if let Some(entry_kind) = entry_point_kind(relative) {
            let location = start_location(relative);
            entry_points.push(EntryPointEvidence {
                kind: entry_kind.into(),
                fingerprint: evidence_fingerprint("entry-point", entry_kind, &location),
                location: location.clone(),
            });
            capabilities.push(CapabilityEvidence {
                capability: "application-entry-point".into(),
                reason: format!("Detected conventional {entry_kind} entry point"),
                fingerprint: evidence_fingerprint("capability-entry", entry_kind, &location),
                evidence: location,
            });
        }

        if is_build_automation(relative) {
            let location = start_location(relative);
            capabilities.push(CapabilityEvidence {
                capability: "build-automation".into(),
                reason: "Detected build or continuous-integration configuration".into(),
                fingerprint: evidence_fingerprint("capability-build", relative, &location),
                evidence: location,
            });
        }
    }

    check_cancelled(cancellation)?;
    progress(ProgressEvent::Finalizing);
    sort_and_deduplicate(&mut manifests);
    sort_and_deduplicate(&mut frameworks);
    sort_and_deduplicate(&mut entry_points);
    sort_and_deduplicate(&mut capabilities);
    sort_and_deduplicate(&mut trust_boundaries);
    skipped_files.sort_by(|left, right| left.path.cmp(&right.path));
    errors.sort_by(|left, right| (&left.path, &left.code).cmp(&(&right.path, &right.code)));
    if errors.len() == MAX_ERRORS {
        limitations.push(Limitation {
            code: "error-limit-reached".into(),
            message: format!("Non-fatal errors are bounded to {MAX_ERRORS} entries"),
        });
    }

    let languages = language_totals
        .into_iter()
        .map(|(name, (file_count, bytes))| LanguageSummary {
            name,
            file_count,
            bytes,
        })
        .collect::<Vec<_>>();
    let content_fingerprint = repository_hasher.finalize().to_hex().to_string();
    let repository = repository_identity(&root, content_fingerprint);
    let finished = OffsetDateTime::now_utc();
    let started_at = format_timestamp(started)?;
    let finished_at = format_timestamp(finished)?;
    let duration_ms = u64::try_from(timer.elapsed().as_millis()).unwrap_or(u64::MAX);

    let mut report = ScanReport {
        schema_version: SCHEMA_VERSION.into(),
        engine_version: ENGINE_VERSION.into(),
        document_type: "scan-report".into(),
        repository,
        configuration: request.configuration.clone(),
        scan: ScanMetadata {
            started_at,
            finished_at,
            duration_ms,
            complete: true,
            files_discovered: total,
            files_scanned: files.len(),
        },
        files,
        languages,
        manifests,
        frameworks,
        entry_points,
        capabilities,
        trust_boundaries,
        findings: Vec::<Finding>::new(),
        limitations,
        skipped_files,
        errors,
        report_fingerprint: String::new(),
    };
    report.report_fingerprint = report_fingerprint(&report)?;
    progress(ProgressEvent::Complete {
        files_scanned: report.scan.files_scanned,
    });
    Ok(report)
}

fn canonical_repository(path: &Path) -> Result<PathBuf, ScanError> {
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

fn discover_files(
    root: &Path,
    request: &ScanRequest,
) -> (Vec<(PathBuf, String)>, usize, Vec<BoundedError>) {
    let mut builder = WalkBuilder::new(root);
    builder
        .follow_links(false)
        .hidden(!request.configuration.include_hidden)
        .git_ignore(request.configuration.respect_ignore_files)
        .git_global(request.configuration.respect_ignore_files)
        .git_exclude(request.configuration.respect_ignore_files)
        .ignore(request.configuration.respect_ignore_files)
        .parents(request.configuration.respect_ignore_files);

    let mut files = BTreeMap::<String, PathBuf>::new();
    let mut discovered_total = 0_usize;
    let mut errors = Vec::new();
    for entry in builder.build() {
        match entry {
            Ok(entry) if entry.file_type().is_some_and(|kind| kind.is_file()) => {
                if let Some(relative) = safe_relative(root, entry.path()) {
                    discovered_total = discovered_total.saturating_add(1);
                    if files.len() < request.configuration.max_files {
                        files.insert(relative, entry.into_path());
                    } else if files
                        .last_key_value()
                        .is_some_and(|(largest, _)| relative < *largest)
                    {
                        files.pop_last();
                        files.insert(relative, entry.into_path());
                    }
                } else {
                    push_error(
                        &mut errors,
                        "unsupported-path",
                        None,
                        "A file path could not be represented safely",
                    );
                }
            }
            Ok(_) => {}
            Err(_error) => {
                push_error(
                    &mut errors,
                    "traversal-error",
                    None,
                    "A repository entry could not be traversed",
                );
            }
        }
    }
    let files = files
        .into_iter()
        .map(|(relative, absolute)| (absolute, relative))
        .collect();
    (files, discovered_total, errors)
}

fn safe_relative(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_str()?.to_owned()),
            _ => return None,
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), ScanError> {
    if cancellation.is_cancelled() {
        Err(ScanError::Cancelled)
    } else {
        Ok(())
    }
}

fn push_error(errors: &mut Vec<BoundedError>, code: &str, path: Option<String>, message: &str) {
    if errors.len() < MAX_ERRORS {
        errors.push(BoundedError {
            code: code.into(),
            path,
            message: message.into(),
        });
    }
}

fn phase_zero_limitations() -> Vec<Limitation> {
    vec![
        Limitation {
            code: "inventory-only".into(),
            message: "Phase 0 classifies repository evidence and does not run vulnerability rules"
                .into(),
        },
        Limitation {
            code: "no-language-parser".into(),
            message: "Language detection is extension-based; source files are not parsed".into(),
        },
        Limitation {
            code: "framework-hints-only".into(),
            message: "Framework evidence is a manifest hint and not semantic proof".into(),
        },
        Limitation {
            code: "symlinks-not-followed".into(),
            message: "Symbolic links are not followed during repository traversal".into(),
        },
    ]
}

fn detect_language(path: &str) -> Option<&'static str> {
    let extension = path.rsplit_once('.').map(|(_, extension)| extension)?;
    match extension.to_ascii_lowercase().as_str() {
        "c" | "h" => Some("C"),
        "cc" | "cpp" | "cxx" | "hpp" => Some("C++"),
        "cs" => Some("C#"),
        "go" => Some("Go"),
        "java" => Some("Java"),
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "kt" | "kts" => Some("Kotlin"),
        "php" => Some("PHP"),
        "py" => Some("Python"),
        "rb" => Some("Ruby"),
        "rs" => Some("Rust"),
        "swift" => Some("Swift"),
        "ts" | "tsx" | "mts" | "cts" => Some("TypeScript"),
        _ => None,
    }
}

fn manifest_kind(path: &str) -> Option<&'static str> {
    let name = file_name(path).to_ascii_lowercase();
    match name.as_str() {
        "cargo.toml" => Some("cargo"),
        "package.json" => Some("npm"),
        "pnpm-lock.yaml" => Some("pnpm-lock"),
        "yarn.lock" => Some("yarn-lock"),
        "pyproject.toml" => Some("python"),
        "requirements.txt" => Some("python-requirements"),
        "go.mod" => Some("go-modules"),
        "pom.xml" => Some("maven"),
        "build.gradle" | "build.gradle.kts" => Some("gradle"),
        "gemfile" => Some("bundler"),
        "composer.json" => Some("composer"),
        _ => None,
    }
}

fn classify_file(path: &str, manifest: Option<&str>, language: Option<&str>) -> &'static str {
    if manifest.is_some() {
        "manifest"
    } else if language.is_some() {
        "source"
    } else if is_build_automation(path) {
        "build-configuration"
    } else {
        "other"
    }
}

fn entry_point_kind(path: &str) -> Option<&'static str> {
    let name = file_name(path).to_ascii_lowercase();
    match name.as_str() {
        "main.rs" | "main.go" | "main.py" | "main.ts" | "main.js" => Some("main"),
        "app.py" | "app.ts" | "app.js" => Some("application"),
        "server.py" | "server.ts" | "server.js" => Some("server"),
        "manage.py" => Some("framework-cli"),
        _ => None,
    }
}

fn is_build_automation(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    matches!(file_name(&lower), "dockerfile" | "makefile" | "justfile")
        || lower.starts_with(".github/workflows/")
        || lower == ".gitlab-ci.yml"
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn detect_frameworks(
    path: &str,
    content: &[u8],
    frameworks: &mut Vec<FrameworkEvidence>,
    boundaries: &mut Vec<TrustBoundaryEvidence>,
) {
    const FRAMEWORKS: &[(&str, &[u8])] = &[
        ("Actix Web", b"actix-web"),
        ("Axum", b"axum"),
        ("Django", b"django"),
        ("Express", b"express"),
        ("FastAPI", b"fastapi"),
        ("Flask", b"flask"),
        ("Next.js", b"next"),
    ];
    for (name, needle) in FRAMEWORKS {
        if let Some(offset) = find_bytes(content, needle) {
            let location = location_for_bytes(path, content, offset, needle.len());
            frameworks.push(FrameworkEvidence {
                name: (*name).into(),
                fingerprint: evidence_fingerprint("framework", name, &location),
                evidence: location.clone(),
            });
            boundaries.push(TrustBoundaryEvidence {
                kind: "network-request".into(),
                description: format!("{name} may expose network request entry points"),
                fingerprint: evidence_fingerprint("boundary-network", name, &location),
                evidence: location,
            });
        }
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn start_location(path: &str) -> SourceLocation {
    SourceLocation {
        path: path.into(),
        span: SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
        },
    }
}

fn location_for_bytes(path: &str, content: &[u8], start: usize, length: usize) -> SourceLocation {
    let before = String::from_utf8_lossy(&content[..start]);
    let matched = String::from_utf8_lossy(&content[start..start.saturating_add(length)]);
    let start_line_usize = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let start_column_usize = before.rsplit_once('\n').map_or_else(
        || before.chars().count() + 1,
        |(_, tail)| tail.chars().count() + 1,
    );
    let line_delta = matched.bytes().filter(|byte| *byte == b'\n').count();
    let end_column_usize = if line_delta == 0 {
        start_column_usize + matched.chars().count()
    } else {
        matched
            .rsplit_once('\n')
            .map_or(1, |(_, tail)| tail.chars().count() + 1)
    };
    SourceLocation {
        path: path.into(),
        span: SourceSpan {
            start_byte: u64::try_from(start).unwrap_or(u64::MAX),
            end_byte: u64::try_from(start.saturating_add(length)).unwrap_or(u64::MAX),
            start_line: u32::try_from(start_line_usize).unwrap_or(u32::MAX),
            start_column: u32::try_from(start_column_usize).unwrap_or(u32::MAX),
            end_line: u32::try_from(start_line_usize.saturating_add(line_delta))
                .unwrap_or(u32::MAX),
            end_column: u32::try_from(end_column_usize).unwrap_or(u32::MAX),
        },
    }
}

fn evidence_fingerprint(kind: &str, value: &str, location: &SourceLocation) -> String {
    let mut hasher = blake3::Hasher::new();
    update_length_prefixed(&mut hasher, kind.as_bytes());
    update_length_prefixed(&mut hasher, value.as_bytes());
    update_length_prefixed(&mut hasher, location.path.as_bytes());
    update_length_prefixed(&mut hasher, &location.span.start_byte.to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

fn repository_identity(root: &Path, content_fingerprint: String) -> RepositoryIdentity {
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("repository")
        .to_owned();
    let revision = git_revision(root);
    let vcs = root.join(".git").exists().then(|| "git".to_owned());
    let mut hasher = blake3::Hasher::new();
    update_length_prefixed(&mut hasher, name.as_bytes());
    update_length_prefixed(&mut hasher, vcs.as_deref().unwrap_or("").as_bytes());
    update_length_prefixed(&mut hasher, revision.as_deref().unwrap_or("").as_bytes());
    update_length_prefixed(&mut hasher, content_fingerprint.as_bytes());
    RepositoryIdentity {
        name,
        vcs,
        revision,
        content_fingerprint,
        identity_fingerprint: hasher.finalize().to_hex().to_string(),
    }
}

fn git_revision(root: &Path) -> Option<String> {
    let git_dir = root.join(".git");
    if !git_dir.is_dir() {
        return None;
    }
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        if reference
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        {
            return fs::read_to_string(git_dir.join(reference))
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| valid_object_id(value));
        }
        None
    } else {
        valid_object_id(head).then(|| head.to_owned())
    }
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn update_length_prefixed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}

fn format_timestamp(timestamp: OffsetDateTime) -> Result<String, ScanError> {
    timestamp
        .format(&Rfc3339)
        .map_err(|_| ScanError::Internal("UTC timestamp could not be formatted".into()))
}

fn report_fingerprint(report: &ScanReport) -> Result<String, ScanError> {
    #[derive(Serialize)]
    struct StableReport<'a> {
        schema_version: &'a str,
        engine_version: &'a str,
        document_type: &'a str,
        repository: &'a RepositoryIdentity,
        configuration: &'a crate::ScanConfiguration,
        files_discovered: usize,
        files_scanned: usize,
        files: &'a [FileRecord],
        languages: &'a [LanguageSummary],
        manifests: &'a [ManifestEvidence],
        frameworks: &'a [FrameworkEvidence],
        entry_points: &'a [EntryPointEvidence],
        capabilities: &'a [CapabilityEvidence],
        trust_boundaries: &'a [TrustBoundaryEvidence],
        findings: &'a [Finding],
        limitations: &'a [Limitation],
        skipped_files: &'a [SkippedFile],
        errors: &'a [BoundedError],
    }

    let stable = StableReport {
        schema_version: &report.schema_version,
        engine_version: &report.engine_version,
        document_type: &report.document_type,
        repository: &report.repository,
        configuration: &report.configuration,
        files_discovered: report.scan.files_discovered,
        files_scanned: report.scan.files_scanned,
        files: &report.files,
        languages: &report.languages,
        manifests: &report.manifests,
        frameworks: &report.frameworks,
        entry_points: &report.entry_points,
        capabilities: &report.capabilities,
        trust_boundaries: &report.trust_boundaries,
        findings: &report.findings,
        limitations: &report.limitations,
        skipped_files: &report.skipped_files,
        errors: &report.errors,
    };
    let bytes = serde_json::to_vec(&stable)
        .map_err(|_| ScanError::Internal("report fingerprint serialization failed".into()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn sort_and_deduplicate<T: Ord>(items: &mut Vec<T>) {
    items.sort();
    items.dedup();
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn unchanged_scans_have_stable_nonvolatile_fingerprints()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(
            directory.path().join("Cargo.toml"),
            "[dependencies]\naxum = \"0.8\"\n",
        )?;
        fs::write(directory.path().join("main.rs"), "fn main() {}\n")?;
        let request = ScanRequest::new(directory.path());
        let first = scan_repository(&request, &CancellationToken::new(), |_| {})?;
        let second = scan_repository(&request, &CancellationToken::new(), |_| {})?;
        assert_eq!(first.report_fingerprint, second.report_fingerprint);
        assert_eq!(first.repository, second.repository);
        assert_eq!(first.files, second.files);
        assert_eq!(first.frameworks, second.frameworks);
        assert!(first.findings.is_empty());
        Ok(())
    }

    #[test]
    fn exported_report_does_not_contain_the_absolute_root() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let secret = "phase-zero-test-secret-value";
        fs::write(
            directory.path().join("main.py"),
            format!("API_TOKEN = '{secret}'\n"),
        )?;
        let report = scan_repository(
            &ScanRequest::new(directory.path()),
            &CancellationToken::new(),
            |_| {},
        )?;
        let json = serde_json::to_string(&report)?;
        let absolute = directory.path().to_string_lossy();
        assert!(!json.contains(absolute.as_ref()));
        assert!(!json.contains(secret));
        assert!(report.files.iter().all(|file| !file.path.starts_with('/')));
        Ok(())
    }

    #[test]
    fn pre_cancelled_scan_returns_no_report() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = scan_repository(&ScanRequest::new(directory.path()), &cancellation, |_| {});
        assert!(matches!(result, Err(ScanError::Cancelled)));
        Ok(())
    }

    #[test]
    fn cancellation_during_inventory_returns_no_partial_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join("a.rs"), "fn a() {}\n")?;
        fs::write(directory.path().join("b.rs"), "fn b() {}\n")?;
        let cancellation = CancellationToken::new();
        let callback_token = cancellation.clone();
        let result = scan_repository(
            &ScanRequest::new(directory.path()),
            &cancellation,
            move |event| {
                if matches!(event, ProgressEvent::Inspecting { completed: 0, .. }) {
                    callback_token.cancel();
                }
            },
        );
        assert!(matches!(result, Err(ScanError::Cancelled)));
        Ok(())
    }

    #[test]
    fn oversized_files_are_reported_as_skipped() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join("large.txt"), b"12345")?;
        let mut request = ScanRequest::new(directory.path());
        request.configuration.max_file_bytes = 4;
        let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
        assert!(report.files.is_empty());
        assert_eq!(report.skipped_files[0].path, "large.txt");
        assert_eq!(report.skipped_files[0].reason, "file-too-large");
        Ok(())
    }

    #[test]
    fn file_limit_selects_the_first_relative_paths_deterministically()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join("c.rs"), "fn c() {}\n")?;
        fs::write(directory.path().join("a.rs"), "fn a() {}\n")?;
        fs::write(directory.path().join("b.rs"), "fn b() {}\n")?;
        let mut request = ScanRequest::new(directory.path());
        request.configuration.max_files = 2;
        let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
        let paths = report
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, ["a.rs", "b.rs"]);
        assert!(
            report
                .limitations
                .iter()
                .any(|limitation| limitation.code == "file-limit-reached")
        );
        Ok(())
    }
}
