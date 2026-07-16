//! Native UI boundary for the shared Secure Engine inventory function.

use std::path::PathBuf;
use std::thread::{self, JoinHandle};

use secure_engine::{
    CacheControl, CancellationToken, ProgressEvent, ScanConfiguration, ScanError, ScanReport,
    ScanRequest,
};

/// Native UI representation of every Phase 2 inventory, parsing, and cache control.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct InventoryControls {
    /// Include hidden inputs, still subject to ignore and exclusion rules.
    pub include_hidden: bool,
    /// Honor Git and repository ignore rules.
    pub respect_ignore_files: bool,
    /// Include common generated/build directories.
    pub include_generated: bool,
    /// Include common vendored dependency directories.
    pub include_vendor: bool,
    /// Include nested repositories and submodules.
    pub include_nested_repositories: bool,
    /// Repeatable repository-relative include globs.
    pub include_patterns: Vec<String>,
    /// Repeatable repository-relative exclude globs.
    pub exclude_patterns: Vec<String>,
    /// Maximum selected files.
    pub max_files: usize,
    /// Maximum bytes read from one file.
    pub max_file_bytes: u64,
    /// Maximum total bytes read.
    pub max_total_bytes: u64,
    /// Optional maximum traversal depth.
    pub max_depth: Option<usize>,
    /// Maximum retained bounded errors.
    pub max_errors: usize,
    /// Enable the local parse cache for supported languages.
    pub parse_cache_enabled: bool,
    /// Optional local cache base directory; never exported in reports.
    pub cache_directory: Option<PathBuf>,
    /// Retire this repository's cache before the next scan.
    pub clear_cache_before_scan: bool,
    /// Maximum repository-specific cache bytes.
    pub max_cache_bytes: u64,
    /// Maximum parser diagnostics retained in the report.
    pub max_parser_diagnostics: usize,
    /// Maximum normalized facts retained per parsed file.
    pub max_facts_per_file: usize,
    /// Maximum normalized facts retained across the report.
    pub max_total_facts: usize,
}

impl Default for InventoryControls {
    fn default() -> Self {
        Self::from_configuration(ScanConfiguration::default())
    }
}

impl InventoryControls {
    /// Converts the UI state into the same typed request consumed by the CLI and engine.
    #[must_use]
    pub fn request(&self, repository: impl Into<PathBuf>) -> ScanRequest {
        ScanRequest {
            repository: repository.into(),
            configuration: ScanConfiguration {
                include_hidden: self.include_hidden,
                max_files: self.max_files,
                max_file_bytes: self.max_file_bytes,
                respect_ignore_files: self.respect_ignore_files,
                include_patterns: self.include_patterns.clone(),
                exclude_patterns: self.exclude_patterns.clone(),
                include_generated: self.include_generated,
                include_vendor: self.include_vendor,
                include_nested_repositories: self.include_nested_repositories,
                max_total_bytes: self.max_total_bytes,
                max_depth: self.max_depth,
                max_errors: self.max_errors,
                parse_cache_enabled: self.parse_cache_enabled,
                max_cache_bytes: self.max_cache_bytes,
                max_parser_diagnostics: self.max_parser_diagnostics,
                max_facts_per_file: self.max_facts_per_file,
                max_total_facts: self.max_total_facts,
            },
            cache: CacheControl {
                directory: self.cache_directory.clone(),
                clear_before_scan: self.clear_cache_before_scan,
            },
        }
    }

    fn from_configuration(configuration: ScanConfiguration) -> Self {
        Self {
            include_hidden: configuration.include_hidden,
            respect_ignore_files: configuration.respect_ignore_files,
            include_generated: configuration.include_generated,
            include_vendor: configuration.include_vendor,
            include_nested_repositories: configuration.include_nested_repositories,
            include_patterns: configuration.include_patterns,
            exclude_patterns: configuration.exclude_patterns,
            max_files: configuration.max_files,
            max_file_bytes: configuration.max_file_bytes,
            max_total_bytes: configuration.max_total_bytes,
            max_depth: configuration.max_depth,
            max_errors: configuration.max_errors,
            parse_cache_enabled: configuration.parse_cache_enabled,
            cache_directory: None,
            clear_cache_before_scan: false,
            max_cache_bytes: configuration.max_cache_bytes,
            max_parser_diagnostics: configuration.max_parser_diagnostics,
            max_facts_per_file: configuration.max_facts_per_file,
            max_total_facts: configuration.max_total_facts,
        }
    }
}

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

/// Starts a native inventory worker outside the render thread.
///
/// Progress and completion callbacks execute on the worker and should use a bounded channel to
/// hand messages back to the UI. Dropping the returned handle detaches the worker; cancellation
/// remains cooperative through the supplied token.
pub fn spawn_inventory_worker<P, C>(
    request: ScanRequest,
    cancellation: CancellationToken,
    progress: P,
    complete: C,
) -> JoinHandle<()>
where
    P: FnMut(ProgressEvent) + Send + 'static,
    C: FnOnce(Result<ScanReport, ScanError>) + Send + 'static,
{
    thread::spawn(move || {
        let result = inventory_repository(&request, &cancellation, progress);
        complete(result);
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;

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

    #[test]
    fn ui_controls_map_to_the_shared_configuration_without_drift() {
        let controls = InventoryControls {
            include_hidden: true,
            respect_ignore_files: false,
            include_generated: true,
            include_vendor: true,
            include_nested_repositories: true,
            include_patterns: vec!["src/**".into()],
            exclude_patterns: vec!["src/private/**".into()],
            max_files: 42,
            max_file_bytes: 1024,
            max_total_bytes: 4096,
            max_depth: Some(8),
            max_errors: 7,
            parse_cache_enabled: true,
            cache_directory: Some(PathBuf::from("cache")),
            clear_cache_before_scan: true,
            max_cache_bytes: 8192,
            max_parser_diagnostics: 6,
            max_facts_per_file: 5,
            max_total_facts: 20,
        };
        let request = controls.request("repository");
        assert!(request.configuration.include_hidden);
        assert!(!request.configuration.respect_ignore_files);
        assert_eq!(request.configuration.include_patterns, ["src/**"]);
        assert_eq!(request.configuration.exclude_patterns, ["src/private/**"]);
        assert_eq!(request.configuration.max_total_bytes, 4096);
        assert_eq!(request.configuration.max_depth, Some(8));
        assert_eq!(request.configuration.max_errors, 7);
        assert!(request.configuration.parse_cache_enabled);
        assert_eq!(request.cache.directory, Some(PathBuf::from("cache")));
        assert!(request.cache.clear_before_scan);
        assert_eq!(request.configuration.max_total_facts, 20);
    }

    #[test]
    fn inventory_worker_runs_off_the_calling_thread_and_returns_a_complete_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/integration-project");
        let caller = thread::current().id();
        let (progress_sender, progress_receiver) = mpsc::channel();
        let (result_sender, result_receiver) = mpsc::channel();
        let handle = spawn_inventory_worker(
            ScanRequest::new(repository),
            CancellationToken::new(),
            move |_event| {
                let _ignored = progress_sender.send(thread::current().id());
            },
            move |result| {
                let _ignored = result_sender.send(result);
            },
        );
        let worker = progress_receiver.recv()?;
        assert_ne!(caller, worker);
        let report = result_receiver.recv()??;
        assert!(report.scan.complete);
        handle.join().map_err(|_| "inventory worker panicked")?;
        Ok(())
    }

    #[test]
    fn desktop_and_core_preserve_identical_phase_two_facts()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/phase2-js-ts");
        let controls = InventoryControls {
            parse_cache_enabled: false,
            ..InventoryControls::default()
        };
        let request = controls.request(repository);
        let desktop = inventory_repository(&request, &CancellationToken::new(), |_| {})?;
        let core = secure_engine::scan_repository(&request, &CancellationToken::new(), |_| {})?;
        assert_eq!(desktop.report_fingerprint, core.report_fingerprint);
        assert_eq!(desktop.facts, core.facts);
        assert_eq!(desktop.parser_diagnostics, core.parser_diagnostics);
        assert_eq!(desktop.parser_coverage, core.parser_coverage);
        Ok(())
    }
}
