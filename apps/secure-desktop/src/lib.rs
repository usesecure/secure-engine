//! Native UI boundary for the shared Secure Engine inventory function.

use std::path::PathBuf;
use std::thread::{self, JoinHandle};

use secure_engine::{
    AiAssessment, AiCache, AiError, AiPreview, AiProjectConfiguration, AiProvider, CacheControl,
    CancellationToken, ExportError, ExportFormat, Finding, ProgressEvent, ScanConfiguration,
    ScanError, ScanReport, ScanRequest, SourceLocation, SourcePreview, SourcePreviewError,
    Suppression,
};

/// Native UI representation of shared inventory, parsing, graph, rule, and cache controls.
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
    /// Maximum evidence-graph nodes.
    pub max_graph_nodes: usize,
    /// Maximum evidence-graph edges.
    pub max_graph_edges: usize,
    /// Maximum bounded local call traversal depth.
    pub max_interprocedural_depth: usize,
    /// Maximum findings retained.
    pub max_findings: usize,
    /// Exact project suppressions.
    pub suppressions: Vec<Suppression>,
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
                max_graph_nodes: self.max_graph_nodes,
                max_graph_edges: self.max_graph_edges,
                max_interprocedural_depth: self.max_interprocedural_depth,
                max_findings: self.max_findings,
                suppressions: self.suppressions.clone(),
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
            max_graph_nodes: configuration.max_graph_nodes,
            max_graph_edges: configuration.max_graph_edges,
            max_interprocedural_depth: configuration.max_interprocedural_depth,
            max_findings: configuration.max_findings,
            suppressions: configuration.suppressions,
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

/// Starts one explicitly consented AI assessment outside the render thread.
pub fn spawn_ai_validation_worker<C>(
    report: ScanReport,
    preview: AiPreview,
    configuration: AiProjectConfiguration,
    provider: Box<dyn AiProvider>,
    cache: Option<AiCache>,
    cancellation: CancellationToken,
    complete: C,
) -> JoinHandle<()>
where
    C: FnOnce(Result<AiAssessment, AiError>) + Send + 'static,
{
    thread::spawn(move || {
        let result = secure_engine::validate_finding_with_ai(
            &report,
            &preview,
            &preview.consent_fingerprint,
            &configuration,
            provider.as_ref(),
            cache.as_ref(),
            &cancellation,
        );
        complete(result);
    })
}

/// Suppression-state choice exposed by the findings filter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SuppressionFilter {
    /// Include every finding visible in the completed report.
    #[default]
    Any,
    /// Include active, unsuppressed findings.
    Active,
    /// Include suppressed findings. Completed reports retain only diagnostics, so this is empty.
    Suppressed,
}

/// Pure, testable filters used by the native findings table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FindingFilter {
    /// Case-insensitive severity match.
    pub severity: String,
    /// Case-insensitive confidence match.
    pub confidence: String,
    /// Case-insensitive rule identifier match.
    pub rule: String,
    /// Case-insensitive repository-relative file substring.
    pub file: String,
    /// Case-insensitive category match.
    pub category: String,
    /// Suppression state.
    pub suppression: SuppressionFilter,
    /// Case-insensitive search across key finding text.
    pub search: String,
}

/// Stable finding-table sort modes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FindingSort {
    /// Highest impact severity first.
    #[default]
    Severity,
    /// Highest confidence first.
    Confidence,
    /// Stable rule identifier.
    Rule,
    /// Repository-relative sink file.
    File,
    /// Security category.
    Category,
}

/// Filters and sorts active findings without mutating the shared report.
#[must_use]
pub fn filter_findings<'a>(
    report: &'a ScanReport,
    filter: &FindingFilter,
    sort: FindingSort,
) -> Vec<&'a Finding> {
    if filter.suppression == SuppressionFilter::Suppressed {
        return Vec::new();
    }
    let mut findings = report
        .findings
        .iter()
        .filter(|finding| {
            text_matches(&finding.severity, &filter.severity)
                && text_matches(&finding.confidence, &filter.confidence)
                && text_matches(&finding.rule_id, &filter.rule)
                && text_matches(&finding.category, &filter.category)
                && text_matches(finding_file(finding), &filter.file)
                && (filter.search.trim().is_empty()
                    || [
                        finding.rule_id.as_str(),
                        finding.title.as_str(),
                        finding.category.as_str(),
                        finding.invariant.as_str(),
                        finding
                            .taxonomy
                            .as_ref()
                            .map_or("", |taxonomy| taxonomy.category_id.as_str()),
                        finding
                            .taxonomy
                            .as_ref()
                            .map_or("", |taxonomy| taxonomy.invariant_id.as_str()),
                        finding
                            .primary_cwe
                            .as_ref()
                            .map_or("", |cwe| cwe.id.as_str()),
                        finding.semantic_fingerprint.as_deref().unwrap_or(""),
                        finding_file(finding),
                    ]
                    .iter()
                    .any(|value| text_matches(value, &filter.search))
                    || finding.evidence_path.iter().any(|step| {
                        step.semantic.as_ref().is_some_and(|semantic| {
                            text_matches(&semantic.identity, &filter.search)
                                || semantic
                                    .policy
                                    .as_deref()
                                    .is_some_and(|policy| text_matches(policy, &filter.search))
                        })
                    }))
        })
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        let primary = match sort {
            FindingSort::Severity => {
                severity_rank(&right.severity).cmp(&severity_rank(&left.severity))
            }
            FindingSort::Confidence => {
                confidence_rank(&right.confidence).cmp(&confidence_rank(&left.confidence))
            }
            FindingSort::Rule => left.rule_id.cmp(&right.rule_id),
            FindingSort::File => finding_file(left).cmp(finding_file(right)),
            FindingSort::Category => left.category.cmp(&right.category),
        };
        primary.then_with(|| left.finding_id.cmp(&right.finding_id))
    });
    findings
}

/// Starts a bounded source-preview load outside the render thread.
pub fn spawn_source_preview_worker<C>(
    repository: PathBuf,
    location: SourceLocation,
    cancellation: CancellationToken,
    complete: C,
) -> JoinHandle<()>
where
    C: FnOnce(Result<SourcePreview, SourcePreviewError>) + Send + 'static,
{
    thread::spawn(move || {
        complete(secure_engine::load_source_preview(
            &repository,
            &location,
            4,
            1024 * 1024,
            &cancellation,
        ));
    })
}

/// Starts one atomic report export outside the render thread.
pub fn spawn_export_worker<C>(
    report: ScanReport,
    format: ExportFormat,
    output: PathBuf,
    cancellation: CancellationToken,
    complete: C,
) -> JoinHandle<()>
where
    C: FnOnce(Result<(), ExportError>) + Send + 'static,
{
    thread::spawn(move || {
        complete(secure_engine::write_export(
            &report,
            format,
            &output,
            &cancellation,
        ));
    })
}

fn text_matches(value: &str, filter: &str) -> bool {
    filter.trim().is_empty() || value.to_lowercase().contains(&filter.trim().to_lowercase())
}

fn finding_file(finding: &Finding) -> &str {
    finding
        .sink
        .as_ref()
        .or_else(|| finding.evidence.last())
        .map_or("", |location| location.path.as_str())
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn confidence_rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
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
            max_graph_nodes: 30,
            max_graph_edges: 40,
            max_interprocedural_depth: 3,
            max_findings: 4,
            suppressions: Vec::new(),
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
        assert_eq!(request.configuration.max_graph_nodes, 30);
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

    #[test]
    fn desktop_and_core_preserve_identical_phase_three_graph_and_findings()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/phase3-rules");
        let controls = InventoryControls {
            parse_cache_enabled: false,
            ..InventoryControls::default()
        };
        let request = controls.request(repository);
        let desktop = inventory_repository(&request, &CancellationToken::new(), |_| {})?;
        let core = secure_engine::scan_repository(&request, &CancellationToken::new(), |_| {})?;
        assert_eq!(desktop.report_fingerprint, core.report_fingerprint);
        assert_eq!(desktop.graph, core.graph);
        assert_eq!(desktop.findings, core.findings);
        assert_eq!(
            desktop.suppression_diagnostics,
            core.suppression_diagnostics
        );
        Ok(())
    }

    #[test]
    fn desktop_and_core_preserve_identical_phase_five_languages()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/phase5-multilang");
        let controls = InventoryControls {
            parse_cache_enabled: false,
            ..InventoryControls::default()
        };
        let request = controls.request(repository);
        let desktop = inventory_repository(&request, &CancellationToken::new(), |_| {})?;
        let core = secure_engine::scan_repository(&request, &CancellationToken::new(), |_| {})?;
        assert_eq!(desktop.report_fingerprint, core.report_fingerprint);
        assert_eq!(desktop.parser_coverage, core.parser_coverage);
        assert_eq!(desktop.facts, core.facts);
        assert_eq!(desktop.graph, core.graph);
        assert_eq!(desktop.findings, core.findings);
        for mode in ["rust", "python", "go"] {
            assert!(
                desktop
                    .parser_coverage
                    .iter()
                    .any(|coverage| coverage.parser_mode == mode)
            );
        }
        Ok(())
    }

    #[test]
    fn finding_filters_and_sorts_are_stable_and_cover_every_dimension()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/phase3-rules");
        let mut request = ScanRequest::new(repository);
        request.configuration.parse_cache_enabled = false;
        let report = inventory_repository(&request, &CancellationToken::new(), |_| {})?;
        let expected = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "SE1006")
            .ok_or("missing SE1006 finding")?;
        let filter = FindingFilter {
            severity: expected.severity.clone(),
            confidence: expected.confidence.clone(),
            rule: expected.rule_id.clone(),
            file: expected
                .sink
                .as_ref()
                .map_or(String::new(), |sink| sink.path.clone()),
            category: expected.category.clone(),
            suppression: SuppressionFilter::Active,
            search: expected.title.clone(),
        };
        let filtered = filter_findings(&report, &filter, FindingSort::File);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_id, "SE1006");
        let taxonomy_search = FindingFilter {
            search: expected
                .primary_cwe
                .as_ref()
                .map_or(String::new(), |cwe| cwe.id.clone()),
            ..FindingFilter::default()
        };
        assert!(
            filter_findings(&report, &taxonomy_search, FindingSort::Rule)
                .iter()
                .any(|finding| finding.rule_id == "SE1006")
        );

        let all = filter_findings(&report, &FindingFilter::default(), FindingSort::Severity);
        assert_eq!(all.len(), 13);
        assert_eq!(
            all.first().map(|finding| finding.severity.as_str()),
            Some("critical")
        );
        let suppressed = FindingFilter {
            suppression: SuppressionFilter::Suppressed,
            ..FindingFilter::default()
        };
        assert!(filter_findings(&report, &suppressed, FindingSort::Rule).is_empty());
        Ok(())
    }

    #[test]
    fn source_and_export_workers_run_outside_the_calling_thread()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/phase3-rules");
        let mut request = ScanRequest::new(&repository);
        request.configuration.parse_cache_enabled = false;
        let report = inventory_repository(&request, &CancellationToken::new(), |_| {})?;
        let location = report
            .findings
            .first()
            .and_then(|finding| finding.sink.clone())
            .ok_or("missing finding sink")?;
        let expected_path = location.path.clone();
        let caller = thread::current().id();
        let (sender, receiver) = mpsc::channel();
        let source_handle = spawn_source_preview_worker(
            repository,
            location,
            CancellationToken::new(),
            move |result| {
                let _ignored = sender.send((thread::current().id(), result));
            },
        );
        let (worker, preview) = receiver.recv()?;
        assert_ne!(caller, worker);
        let preview = preview?;
        assert_eq!(preview.path, expected_path);
        assert!(!preview.text.is_empty());
        source_handle.join().map_err(|_| "source worker panicked")?;

        let output_directory = tempfile::tempdir()?;
        let output = output_directory.path().join("report.sarif");
        let (sender, receiver) = mpsc::channel();
        let export_handle = spawn_export_worker(
            report,
            ExportFormat::Sarif,
            output.clone(),
            CancellationToken::new(),
            move |result| {
                let _ignored = sender.send((thread::current().id(), result));
            },
        );
        let (worker, result) = receiver.recv()?;
        assert_ne!(caller, worker);
        result?;
        assert!(output.is_file());
        export_handle.join().map_err(|_| "export worker panicked")?;
        Ok(())
    }

    #[test]
    fn ai_validation_worker_is_explicit_bounded_and_off_the_render_thread()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/phase3-rules");
        let report = inventory_repository(
            &ScanRequest::new(repository),
            &CancellationToken::new(),
            |_| {},
        )?;
        let finding_id = report
            .findings
            .first()
            .map(|finding| finding.finding_id.clone())
            .ok_or("missing finding")?;
        let configuration = secure_engine::AiProjectConfiguration {
            format: secure_engine::AI_CONFIG_FORMAT.into(),
            enabled: true,
            provider: "mock".into(),
            model: "fixture-model".into(),
            endpoint: None,
            api_key_env: None,
            recorded_response: None,
            pricing: None,
            limits: secure_engine::AiLimits::default(),
        };
        let preview = secure_engine::preview_finding(&report, &finding_id, &configuration)?;
        let response = serde_json::json!({
            "status": "insufficient-evidence",
            "evidence_assessment": "missing",
            "prerequisites": [],
            "confidence_explanation": "The bounded payload is incomplete.",
            "remediation_proposal": "Collect deterministic evidence first.",
            "verification_suggestions": ["Inspect locally"],
            "limitations": ["No tools were available"],
            "uncertainty": "No conclusion can be supported."
        });
        let caller = thread::current().id();
        let (sender, receiver) = mpsc::channel();
        let handle = spawn_ai_validation_worker(
            report,
            preview,
            configuration,
            secure_engine::mock_provider(response),
            None,
            CancellationToken::new(),
            move |result| {
                let _ignored = sender.send((thread::current().id(), result));
            },
        );
        let (worker, result) = receiver.recv()?;
        assert_ne!(caller, worker);
        assert_eq!(
            result?.assessment.status,
            secure_engine::AiAssessmentStatus::InsufficientEvidence
        );
        handle.join().map_err(|_| "AI worker panicked")?;
        Ok(())
    }
}
