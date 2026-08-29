use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;

use crate::storage::{write_atomic, write_atomic_with};
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
    /// Deterministic serialization exceeded the explicit output budget.
    OutputBudgetExceeded {
        /// Maximum serialized JSON bytes configured by the caller.
        maximum_bytes: u64,
    },
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("export cancelled"),
            Self::Serialization => formatter.write_str("export serialization failed"),
            Self::Write => formatter.write_str("export could not be written atomically"),
            Self::OutputBudgetExceeded { maximum_bytes } => {
                write!(formatter, "export exceeded the {maximum_bytes}-byte output budget")
            }
        }
    }
}

impl std::error::Error for ExportError {}

impl ExportError {
    /// Stable machine-readable failure reason.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Cancelled => "export-cancelled",
            Self::Serialization => "export-serialization-failed",
            Self::Write => "export-atomic-write-failed",
            Self::OutputBudgetExceeded { .. } => "output-budget-exceeded",
        }
    }
}

/// Serializes a report into deterministic pretty-printed JSON bytes.
///
/// # Errors
///
/// Returns an error when serialization fails.
pub fn serialize_export(report: &ScanReport, format: ExportFormat) -> Result<Vec<u8>, ExportError> {
    serialize_export_bounded(report, format, u64::MAX)
}

/// Serializes deterministic pretty-printed JSON without exceeding an explicit byte budget.
///
/// # Errors
///
/// Returns `OutputBudgetExceeded` before returning any partial machine output.
pub fn serialize_export_bounded(
    report: &ScanReport,
    format: ExportFormat,
    maximum_bytes: u64,
) -> Result<Vec<u8>, ExportError> {
    let mut bytes = Vec::new();
    let mut writer = BudgetWriter::new(&mut bytes, maximum_bytes, None);
    serialize_to_writer(report, format, &mut writer, maximum_bytes)?;
    Ok(bytes)
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
    write_export_bounded(report, format, path, cancellation, u64::MAX)
}

/// Atomically streams a report export under an explicit serialized-output budget.
///
/// # Errors
///
/// Returns a cancellation, serialization, output-budget, or atomic-write error. A failed export
/// never replaces an existing destination and never leaves a partial destination document.
pub fn write_export_bounded(
    report: &ScanReport,
    format: ExportFormat,
    path: &Path,
    cancellation: &CancellationToken,
    maximum_bytes: u64,
) -> Result<(), ExportError> {
    write_atomic_with(path, cancellation, |file| {
        let mut writer = BudgetWriter::new(file, maximum_bytes, Some(cancellation));
        serialize_to_writer(report, format, &mut writer, maximum_bytes).map_err(|error| {
            let kind = match error {
                ExportError::Cancelled => io::ErrorKind::Interrupted,
                ExportError::OutputBudgetExceeded { .. } => io::ErrorKind::FileTooLarge,
                _ => io::ErrorKind::InvalidData,
            };
            io::Error::new(kind, error)
        })
    })
    .map_err(|error| match error.kind() {
        io::ErrorKind::Interrupted => ExportError::Cancelled,
        io::ErrorKind::FileTooLarge => ExportError::OutputBudgetExceeded { maximum_bytes },
        io::ErrorKind::InvalidData => ExportError::Serialization,
        _ => ExportError::Write,
    })
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

fn serialize_to_writer<W: Write>(
    report: &ScanReport,
    format: ExportFormat,
    writer: &mut W,
    maximum_bytes: u64,
) -> Result<(), ExportError> {
    let result = match format {
        ExportFormat::SecureJson => serde_json::to_writer_pretty(writer, report),
        ExportFormat::Sarif => serde_json::to_writer_pretty(writer, &sarif_report(report)),
    };
    result.map_err(|error| match error.io_error_kind() {
        Some(io::ErrorKind::Interrupted) => ExportError::Cancelled,
        Some(io::ErrorKind::FileTooLarge) => {
            ExportError::OutputBudgetExceeded { maximum_bytes }
        }
        _ => ExportError::Serialization,
    })
}

struct BudgetWriter<'a, W> {
    inner: W,
    written: u64,
    maximum: u64,
    cancellation: Option<&'a CancellationToken>,
}

impl<'a, W> BudgetWriter<'a, W> {
    fn new(inner: W, maximum: u64, cancellation: Option<&'a CancellationToken>) -> Self {
        Self {
            inner,
            written: 0,
            maximum,
            cancellation,
        }
    }
}

impl<W: Write> Write for BudgetWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let length = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        if self.written.saturating_add(length) > self.maximum {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        self.inner.write_all(buffer)?;
        self.written = self.written.saturating_add(length);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
