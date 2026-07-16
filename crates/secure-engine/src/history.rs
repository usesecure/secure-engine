use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::storage::{create_private_directory, write_atomic};
use crate::workspace::{ReadOutcome, read_file_no_follow};
use crate::{CancellationToken, SCHEMA_VERSION, ScanReport};

/// Version identifier for local scan-history records.
pub const HISTORY_FORMAT: &str = "secure-history-v1";
const MAX_HISTORY_RECORD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HISTORY_ENTRIES: usize = 10_000;

/// Failure while managing local scan history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryError {
    /// Cooperative cancellation was observed.
    Cancelled,
    /// Input or stored data was invalid.
    Invalid(String),
    /// The requested scan was not found.
    NotFound,
    /// Local history storage was unavailable.
    Storage,
}

impl fmt::Display for HistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("history operation cancelled"),
            Self::Invalid(message) => write!(formatter, "invalid history data: {message}"),
            Self::NotFound => formatter.write_str("history scan was not found"),
            Self::Storage => formatter.write_str("history storage operation failed"),
        }
    }
}

impl std::error::Error for HistoryError {}

/// Safe history listing with corruption-recovery information.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HistoryListing {
    /// Valid scans ordered newest first.
    pub scans: Vec<HistorySummary>,
    /// Corrupt entries ignored and retired during this listing.
    pub corrupt_entries_recovered: usize,
}

/// Safe display metadata for one completed historical scan.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct HistorySummary {
    /// Stable local scan identifier.
    pub scan_id: String,
    /// RFC 3339 local-save timestamp.
    pub saved_at: String,
    /// User-facing project name.
    pub display_name: String,
    /// Safe repository name from the report.
    pub repository_name: String,
    /// Report fingerprint.
    pub report_fingerprint: String,
    /// Number of findings.
    pub findings: usize,
    /// Whether the originally scanned directory still exists.
    pub repository_available: bool,
    /// Completion state; only complete records are published.
    pub status: String,
}

/// Completed report reopened from local history without exporting its host path.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HistoryEntry {
    /// Safe display metadata.
    pub summary: HistorySummary,
    /// Complete immutable scan report.
    pub report: ScanReport,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredHistoryEntry {
    format: String,
    scan_id: String,
    saved_at: String,
    display_name: String,
    repository_path: Option<PathBuf>,
    report: ScanReport,
}

/// Bounded local history store using private directories and atomic files.
#[derive(Clone, Debug)]
pub struct HistoryStore {
    directory: PathBuf,
    retention: usize,
}

impl HistoryStore {
    /// Opens or creates a private history directory with a bounded retention count.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero/excessive bound or unavailable directory.
    pub fn open(directory: impl Into<PathBuf>, retention: usize) -> Result<Self, HistoryError> {
        if retention == 0 || retention > MAX_HISTORY_ENTRIES {
            return Err(HistoryError::Invalid(
                "retention must be between 1 and 10000".into(),
            ));
        }
        let directory = directory.into();
        if !directory.is_absolute() {
            return Err(HistoryError::Invalid(
                "history directory must be absolute".into(),
            ));
        }
        create_private_directory(&directory).map_err(|_| HistoryError::Storage)?;
        Ok(Self {
            directory,
            retention,
        })
    }

    /// Records one complete report and enforces retention atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete reports, cancellation, or storage failure.
    pub fn record(
        &self,
        report: &ScanReport,
        repository_path: Option<&Path>,
        display_name: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<HistorySummary, HistoryError> {
        check_cancelled(cancellation)?;
        if !report.scan.complete {
            return Err(HistoryError::Invalid(
                "partial scans cannot be recorded".into(),
            ));
        }
        let repository_path = repository_path
            .filter(|path| path.is_absolute() && path.is_dir())
            .and_then(|path| fs::canonicalize(path).ok());
        let saved_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| HistoryError::Storage)?;
        let scan_id = scan_id(report, &saved_at);
        let requested_name = display_name.unwrap_or(&report.repository.name);
        let mut display_name = bounded_display_name(requested_name);
        if display_name.is_empty() {
            display_name = bounded_display_name(&report.repository.name);
        }
        if display_name.is_empty() {
            display_name = "repository".into();
        }
        let stored = StoredHistoryEntry {
            format: HISTORY_FORMAT.into(),
            scan_id: scan_id.clone(),
            saved_at: saved_at.clone(),
            display_name,
            repository_path,
            report: report.clone(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| HistoryError::Storage)?;
        let target = self.directory.join(format!("{scan_id}.json"));
        write_atomic(&target, &bytes, cancellation).map_err(|error| history_io_error(&error))?;
        self.enforce_retention(cancellation)?;
        Ok(summary(&stored))
    }

    /// Lists valid scans newest first and retires corrupt entries.
    ///
    /// # Errors
    ///
    /// Returns an error when directory enumeration or cancellation fails.
    pub fn list(&self, cancellation: &CancellationToken) -> Result<HistoryListing, HistoryError> {
        check_cancelled(cancellation)?;
        let entries = fs::read_dir(&self.directory).map_err(|_| HistoryError::Storage)?;
        let mut scans = Vec::new();
        let mut corrupt_entries_recovered = 0_usize;
        for entry in entries.take(MAX_HISTORY_ENTRIES.saturating_add(1)) {
            check_cancelled(cancellation)?;
            let Ok(entry) = entry else {
                corrupt_entries_recovered = corrupt_entries_recovered.saturating_add(1);
                continue;
            };
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            match read_stored(&path, cancellation) {
                Ok(stored) => scans.push(summary(&stored)),
                Err(HistoryError::Cancelled) => return Err(HistoryError::Cancelled),
                Err(_) => {
                    corrupt_entries_recovered = corrupt_entries_recovered.saturating_add(1);
                    retire_corrupt(&path);
                }
            }
        }
        scans.sort_by(|left, right| {
            (&right.saved_at, &right.scan_id).cmp(&(&left.saved_at, &left.scan_id))
        });
        Ok(HistoryListing {
            scans,
            corrupt_entries_recovered,
        })
    }

    /// Reopens one complete historical report.
    ///
    /// # Errors
    ///
    /// Returns not-found, corruption, cancellation, or storage errors.
    pub fn show(
        &self,
        scan_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<HistoryEntry, HistoryError> {
        validate_scan_id(scan_id)?;
        let stored = read_stored(
            &self.directory.join(format!("{scan_id}.json")),
            cancellation,
        )?;
        Ok(HistoryEntry {
            summary: summary(&stored),
            report: stored.report,
        })
    }

    /// Returns the private local repository path for source preview.
    ///
    /// The path is never included in public history documents.
    ///
    /// # Errors
    ///
    /// Returns not-found, corruption, cancellation, or storage errors.
    pub fn repository_path(
        &self,
        scan_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<PathBuf>, HistoryError> {
        validate_scan_id(scan_id)?;
        let stored = read_stored(
            &self.directory.join(format!("{scan_id}.json")),
            cancellation,
        )?;
        Ok(stored.repository_path.filter(|path| path.is_dir()))
    }

    /// Explicitly deletes one history record.
    ///
    /// # Errors
    ///
    /// Returns not-found or storage errors.
    pub fn delete(&self, scan_id: &str) -> Result<(), HistoryError> {
        validate_scan_id(scan_id)?;
        fs::remove_file(self.directory.join(format!("{scan_id}.json"))).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                HistoryError::NotFound
            } else {
                HistoryError::Storage
            }
        })
    }

    fn enforce_retention(&self, cancellation: &CancellationToken) -> Result<(), HistoryError> {
        let listing = self.list(cancellation)?;
        for stale in listing.scans.iter().skip(self.retention) {
            check_cancelled(cancellation)?;
            self.delete(&stale.scan_id)?;
        }
        Ok(())
    }
}

/// Returns the platform-local default history directory without creating it.
#[must_use]
pub fn default_history_directory() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        })
        .or_else(|| {
            std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        })
        .unwrap_or_else(std::env::temp_dir)
        .join("secure-engine")
        .join(HISTORY_FORMAT)
}

fn read_stored(
    path: &Path,
    cancellation: &CancellationToken,
) -> Result<StoredHistoryEntry, HistoryError> {
    let bytes = match read_file_no_follow(
        path,
        MAX_HISTORY_RECORD_BYTES,
        MAX_HISTORY_RECORD_BYTES,
        Some(cancellation),
    ) {
        Ok(ReadOutcome::Content(bytes)) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(HistoryError::NotFound);
        }
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            return Err(HistoryError::Cancelled);
        }
        _ => return Err(HistoryError::Invalid("history record is unreadable".into())),
    };
    let stored = serde_json::from_slice::<StoredHistoryEntry>(&bytes)
        .map_err(|_| HistoryError::Invalid("history record is malformed".into()))?;
    validate_stored(&stored, path)?;
    Ok(stored)
}

fn validate_stored(stored: &StoredHistoryEntry, path: &Path) -> Result<(), HistoryError> {
    if stored.format != HISTORY_FORMAT
        || !stored.report.scan.complete
        || stored.report.schema_version != SCHEMA_VERSION
        || !fingerprint_is_valid(&stored.report.report_fingerprint)
        || !scan_id_is_valid(&stored.scan_id)
        || stored.scan_id != scan_id(&stored.report, &stored.saved_at)
        || OffsetDateTime::parse(&stored.saved_at, &Rfc3339).is_err()
        || path.file_stem().and_then(|value| value.to_str()) != Some(stored.scan_id.as_str())
        || stored.display_name.is_empty()
        || stored.display_name.len() > 256
        || stored.display_name.chars().any(char::is_control)
        || stored
            .repository_path
            .as_ref()
            .is_some_and(|repository| !repository.is_absolute())
    {
        return Err(HistoryError::Invalid(
            "history record failed validation".into(),
        ));
    }
    Ok(())
}

fn summary(stored: &StoredHistoryEntry) -> HistorySummary {
    HistorySummary {
        scan_id: stored.scan_id.clone(),
        saved_at: stored.saved_at.clone(),
        display_name: stored.display_name.clone(),
        repository_name: stored.report.repository.name.clone(),
        report_fingerprint: stored.report.report_fingerprint.clone(),
        findings: stored.report.findings.len(),
        repository_available: stored
            .repository_path
            .as_ref()
            .is_some_and(|path| path.is_dir()),
        status: "complete".into(),
    }
}

fn scan_id(report: &ScanReport, saved_at: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [report.report_fingerprint.as_bytes(), saved_at.as_bytes()] {
        hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(value);
    }
    format!("scan_{}", &hasher.finalize().to_hex()[..24])
}

fn validate_scan_id(scan_id: &str) -> Result<(), HistoryError> {
    if scan_id_is_valid(scan_id) {
        Ok(())
    } else {
        Err(HistoryError::Invalid("scan ID is malformed".into()))
    }
}

fn scan_id_is_valid(scan_id: &str) -> bool {
    scan_id.len() == 29
        && scan_id.starts_with("scan_")
        && scan_id.as_bytes().get(5..).is_some_and(|suffix| {
            suffix
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        })
}

fn bounded_display_name(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn retire_corrupt(path: &Path) {
    let mut retired = path.as_os_str().to_owned();
    retired.push(".corrupt");
    if fs::rename(path, PathBuf::from(&retired)).is_err() {
        let _ignored = fs::remove_file(path);
    }
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), HistoryError> {
    if cancellation.is_cancelled() {
        Err(HistoryError::Cancelled)
    } else {
        Ok(())
    }
}

fn history_io_error(error: &std::io::Error) -> HistoryError {
    if error.kind() == std::io::ErrorKind::Interrupted {
        HistoryError::Cancelled
    } else {
        HistoryError::Storage
    }
}

fn fingerprint_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
