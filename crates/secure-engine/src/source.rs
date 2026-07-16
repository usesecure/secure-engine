use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::workspace::{ReadOutcome, read_file_no_follow};
use crate::{CancellationToken, SourceLocation};

const HARD_MAX_PREVIEW_BYTES: u64 = 1024 * 1024;
const HARD_MAX_CONTEXT_LINES: u32 = 200;

/// Bounded source excerpt centered on an exact repository-relative span.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourcePreview {
    /// Repository-relative file path.
    pub path: String,
    /// First one-based line included in `text`.
    pub first_line: u32,
    /// Last one-based line included in `text`.
    pub last_line: u32,
    /// UTF-8 source excerpt; callers must not retain it in history.
    pub text: String,
    /// Exact highlighted start line from the report.
    pub highlight_start_line: u32,
    /// Exact highlighted start column from the report.
    pub highlight_start_column: u32,
    /// Exact highlighted end line from the report.
    pub highlight_end_line: u32,
    /// Exact highlighted end column from the report.
    pub highlight_end_column: u32,
}

/// Failure while safely loading a bounded source preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourcePreviewError {
    /// Cooperative cancellation was observed.
    Cancelled,
    /// The repository, relative path, or exact span is invalid.
    Invalid,
    /// The source path is a symlink or escapes the repository.
    Containment,
    /// The source exceeds the configured bound or is not UTF-8 text.
    Unsupported,
    /// The source could not be read.
    Read,
}

impl fmt::Display for SourcePreviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("source preview cancelled"),
            Self::Invalid => formatter.write_str("source preview input is invalid"),
            Self::Containment => formatter.write_str("source path is outside the repository"),
            Self::Unsupported => formatter.write_str("source is too large or not UTF-8 text"),
            Self::Read => formatter.write_str("source preview could not be read"),
        }
    }
}

impl std::error::Error for SourcePreviewError {}

/// Loads a bounded source excerpt without following symlinks or escaping the repository.
///
/// # Errors
///
/// Returns an error for cancellation, unsafe paths, excessive size, non-UTF-8 content, or I/O.
pub fn load_source_preview(
    repository_root: &Path,
    location: &SourceLocation,
    context_lines: u32,
    max_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<SourcePreview, SourcePreviewError> {
    check_cancelled(cancellation)?;
    if context_lines > HARD_MAX_CONTEXT_LINES
        || max_bytes == 0
        || max_bytes > HARD_MAX_PREVIEW_BYTES
        || !location_is_valid(location)
    {
        return Err(SourcePreviewError::Invalid);
    }
    let root = fs::canonicalize(repository_root).map_err(|_| SourcePreviewError::Read)?;
    if !root.is_dir() {
        return Err(SourcePreviewError::Invalid);
    }
    let relative = safe_relative_path(&location.path)?;
    reject_symlink_components(&root, &relative, cancellation)?;
    let candidate = root.join(&relative);
    let canonical = fs::canonicalize(&candidate).map_err(|_| SourcePreviewError::Read)?;
    if !canonical.starts_with(&root) {
        return Err(SourcePreviewError::Containment);
    }
    check_cancelled(cancellation)?;
    let bytes = match read_file_no_follow(&canonical, max_bytes, max_bytes, Some(cancellation)) {
        Ok(ReadOutcome::Content(bytes)) => bytes,
        Ok(ReadOutcome::FileTooLarge | ReadOutcome::TotalLimit) => {
            return Err(SourcePreviewError::Unsupported);
        }
        Ok(ReadOutcome::NotRegular) => return Err(SourcePreviewError::Invalid),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            return Err(SourcePreviewError::Cancelled);
        }
        Err(_) => return Err(SourcePreviewError::Read),
    };
    let source = String::from_utf8(bytes).map_err(|_| SourcePreviewError::Unsupported)?;
    validate_exact_span(location, &source)?;
    excerpt(location, &source, context_lines)
}

fn validate_exact_span(location: &SourceLocation, source: &str) -> Result<(), SourcePreviewError> {
    let start =
        usize::try_from(location.span.start_byte).map_err(|_| SourcePreviewError::Invalid)?;
    let end = usize::try_from(location.span.end_byte).map_err(|_| SourcePreviewError::Invalid)?;
    if start > end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return Err(SourcePreviewError::Invalid);
    }
    let (start_line, start_column) = line_column(&source[..start]);
    let (end_line, end_column) = line_column(&source[..end]);
    if (start_line, start_column) != (location.span.start_line, location.span.start_column)
        || (end_line, end_column) != (location.span.end_line, location.span.end_column)
    {
        return Err(SourcePreviewError::Invalid);
    }
    Ok(())
}

fn line_column(prefix: &str) -> (u32, u32) {
    let line = u32::try_from(prefix.bytes().filter(|byte| *byte == b'\n').count())
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    let column = u32::try_from(
        prefix
            .rsplit('\n')
            .next()
            .map_or(0, |line| line.chars().count()),
    )
    .unwrap_or(u32::MAX)
    .saturating_add(1);
    (line, column)
}

fn excerpt(
    location: &SourceLocation,
    source: &str,
    context_lines: u32,
) -> Result<SourcePreview, SourcePreviewError> {
    let lines = source.lines().collect::<Vec<_>>();
    let line_count = u32::try_from(lines.len()).unwrap_or(u32::MAX).max(1);
    if location.span.start_line > line_count || location.span.end_line > line_count {
        return Err(SourcePreviewError::Invalid);
    }
    let first_line = location
        .span
        .start_line
        .saturating_sub(context_lines)
        .max(1);
    let last_line = location
        .span
        .end_line
        .saturating_add(context_lines)
        .min(line_count);
    let start =
        usize::try_from(first_line.saturating_sub(1)).map_err(|_| SourcePreviewError::Invalid)?;
    let end = usize::try_from(last_line).map_err(|_| SourcePreviewError::Invalid)?;
    let text = if lines.is_empty() {
        String::new()
    } else {
        lines
            .get(start..end)
            .ok_or(SourcePreviewError::Invalid)?
            .join("\n")
    };
    Ok(SourcePreview {
        path: location.path.clone(),
        first_line,
        last_line,
        text,
        highlight_start_line: location.span.start_line,
        highlight_start_column: location.span.start_column,
        highlight_end_line: location.span.end_line,
        highlight_end_column: location.span.end_column,
    })
}

fn safe_relative_path(value: &str) -> Result<PathBuf, SourcePreviewError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(SourcePreviewError::Containment);
    }
    let path = Path::new(value);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SourcePreviewError::Containment);
    }
    Ok(path.to_path_buf())
}

fn reject_symlink_components(
    root: &Path,
    relative: &Path,
    cancellation: &CancellationToken,
) -> Result<(), SourcePreviewError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        check_cancelled(cancellation)?;
        let Component::Normal(name) = component else {
            return Err(SourcePreviewError::Containment);
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current).map_err(|_| SourcePreviewError::Read)?;
        if metadata.file_type().is_symlink() {
            return Err(SourcePreviewError::Containment);
        }
    }
    Ok(())
}

fn location_is_valid(location: &SourceLocation) -> bool {
    location.span.start_byte <= location.span.end_byte
        && location.span.start_line > 0
        && location.span.end_line >= location.span.start_line
        && location.span.start_column > 0
        && location.span.end_column > 0
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), SourcePreviewError> {
    if cancellation.is_cancelled() {
        Err(SourcePreviewError::Cancelled)
    } else {
        Ok(())
    }
}
