use std::fmt;
use std::path::Path;

use serde::Serialize;

use crate::storage::write_atomic;
use crate::{CancellationToken, ScanReport, sarif_report};

/// Supported deterministic report export formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportFormat {
    /// Additive `secure-json-v1` report JSON.
    SecureJson,
    /// SARIF 2.1.0 JSON.
    Sarif,
}

/// Failure while serializing or atomically writing an export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportError {
    /// Cooperative cancellation was observed.
    Cancelled,
    /// Serialization failed.
    Serialization,
    /// The destination could not be written safely.
    Write,
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("export cancelled"),
            Self::Serialization => formatter.write_str("export serialization failed"),
            Self::Write => formatter.write_str("export could not be written atomically"),
        }
    }
}

impl std::error::Error for ExportError {}

/// Serializes a report into deterministic pretty-printed JSON bytes.
///
/// # Errors
///
/// Returns an error when serialization fails.
pub fn serialize_export(report: &ScanReport, format: ExportFormat) -> Result<Vec<u8>, ExportError> {
    match format {
        ExportFormat::SecureJson => serde_json::to_vec_pretty(report),
        ExportFormat::Sarif => serde_json::to_vec_pretty(&sarif_report(report)),
    }
    .map_err(|_| ExportError::Serialization)
}

/// Atomically writes a report export without publishing partial output.
///
/// # Errors
///
/// Returns a cancellation, serialization, or bounded write error.
pub fn write_export(
    report: &ScanReport,
    format: ExportFormat,
    path: &Path,
    cancellation: &CancellationToken,
) -> Result<(), ExportError> {
    let bytes = serialize_export(report, format)?;
    write_serialized(path, &bytes, cancellation)
}

/// Atomically writes any serializable versioned product artifact.
///
/// # Errors
///
/// Returns a cancellation, serialization, or bounded write error.
pub fn write_json_artifact<T: Serialize>(
    value: &T,
    path: &Path,
    cancellation: &CancellationToken,
) -> Result<(), ExportError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| ExportError::Serialization)?;
    write_serialized(path, &bytes, cancellation)
}

fn write_serialized(
    path: &Path,
    bytes: &[u8],
    cancellation: &CancellationToken,
) -> Result<(), ExportError> {
    write_atomic(path, bytes, cancellation).map_err(|error| {
        if error.kind() == std::io::ErrorKind::Interrupted {
            ExportError::Cancelled
        } else {
            ExportError::Write
        }
    })
}
