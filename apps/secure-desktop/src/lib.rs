//! Native UI boundary for the shared Secure Engine inventory function.

use secure_engine::{CancellationToken, ProgressEvent, ScanError, ScanReport, ScanRequest};

/// Calls the exact shared scan API used by the command-line interface.
///
/// # Errors
///
/// Returns the core [`ScanError`] without converting it into UI prose or a partial report.
pub fn inventory_repository<F>(
    request: &ScanRequest,
    cancellation: &CancellationToken,
    progress: F,
) -> Result<ScanReport, ScanError>
where
    F: FnMut(ProgressEvent),
{
    secure_engine::scan_repository(request, cancellation, progress)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn desktop_boundary_preserves_the_core_result() -> Result<(), Box<dyn std::error::Error>> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/integration-project");
        let request = ScanRequest::new(repository);
        let desktop = inventory_repository(&request, &CancellationToken::new(), |_| {})?;
        let core = secure_engine::scan_repository(&request, &CancellationToken::new(), |_| {})?;
        assert_eq!(desktop.report_fingerprint, core.report_fingerprint);
        assert_eq!(desktop.repository, core.repository);
        assert_eq!(desktop.files, core.files);
        Ok(())
    }
}
