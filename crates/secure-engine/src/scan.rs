use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cache::ParseCache;
use crate::classify::{
    FileOrigin, classify_file, detect_language, entry_point_kind, framework_matches, is_binary,
    is_build_automation, manifest_info,
};
use crate::graph::{ProgramUnit, analyze};
use crate::parser::{ParserMode, parse_source};
use crate::workspace::{
    PathFilters, ReadOutcome, canonical_repository, discover_files, read_file_no_follow,
};
use crate::{
    BoundedError, CapabilityEvidence, ENGINE_VERSION, EntryPointEvidence, ExclusionSummary,
    FileRecord, Finding, FrameworkEvidence, InventorySummary, LanguageSummary, Limitation,
    ManifestEvidence, NormalizedFact, ParserCoverage, ParserDiagnostic, ParsingSummary,
    ProgressEvent, RepositoryIdentity, SCHEMA_VERSION, ScanConfiguration, ScanMetadata, ScanReport,
    ScanRequest, SkippedFile, SourceLocation, SourceSpan, TrustBoundaryEvidence,
};

const MAX_CONFIGURED_ERRORS: usize = 1000;
const MAX_CONFIGURED_FILES: usize = 10_000_000;
const MAX_CONFIGURED_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CONFIGURED_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;
const MAX_CONFIGURED_DEPTH: usize = 1024;
const MAX_CONFIGURED_CACHE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_CONFIGURED_PARSER_DIAGNOSTICS: usize = 100_000;
const MAX_CONFIGURED_FACTS_PER_FILE: usize = 100_000;
const MAX_CONFIGURED_TOTAL_FACTS: usize = 10_000_000;
const MAX_CONFIGURED_GRAPH_NODES: usize = 10_000_000;
const MAX_CONFIGURED_GRAPH_EDGES: usize = 20_000_000;
const MAX_CONFIGURED_INTERPROCEDURAL_DEPTH: usize = 32;
const MAX_CONFIGURED_FINDINGS: usize = 1_000_000;
const GIT_METADATA_LIMIT: u64 = 4 * 1024 * 1024;

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
    /// Include/exclude patterns or resource limits are invalid.
    InvalidConfiguration(String),
    /// Cooperative cancellation was observed.
    Cancelled,
    /// Report construction failed unexpectedly.
    Internal(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRepository(message) => write!(formatter, "invalid repository: {message}"),
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid scan configuration: {message}")
            }
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
/// Returns `InvalidRepository` for unusable input, `InvalidConfiguration` for malformed controls,
/// `Cancelled` after a cancellation request, or `Internal` when finalization fails.
#[allow(clippy::too_many_lines)]
pub fn scan_repository<F>(
    request: &ScanRequest,
    cancellation: &CancellationToken,
    mut progress: F,
) -> Result<ScanReport, ScanError>
where
    F: FnMut(ProgressEvent),
{
    validate_configuration(&request.configuration)?;
    let filters = Arc::new(PathFilters::compile(&request.configuration)?);
    let started = OffsetDateTime::now_utc();
    let timer = Instant::now();
    let root = canonical_repository(&request.repository)?;
    check_cancelled(cancellation)?;
    progress(ProgressEvent::Discovering);

    let discovery = discover_files(
        &root,
        &request.configuration,
        &filters,
        cancellation,
        &mut progress,
    )?;
    let mut parse_cache =
        ParseCache::open(&root, &request.configuration, &request.cache, cancellation)?;
    let total = discovery.files.len();
    let parsing_candidates = discovery
        .files
        .iter()
        .filter(|file| ParserMode::for_path(&file.relative).is_some())
        .count();
    let mut limitations = inventory_limitations(&request.configuration, &discovery);
    let mut files = Vec::with_capacity(total);
    let mut skipped_files = discovery.skipped_files;
    let mut errors = discovery.errors;
    let mut errors_truncated = errors
        .iter()
        .any(|error| error.code == "error-limit-reached");
    let mut manifests = Vec::new();
    let mut frameworks = Vec::new();
    let mut entry_points = Vec::new();
    let mut capabilities = Vec::new();
    let mut trust_boundaries = Vec::new();
    let mut language_totals: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    let mut repository_hasher = blake3::Hasher::new();
    let mut bytes_scanned = 0_u64;
    let mut text_files = 0_usize;
    let mut binary_files = 0_usize;
    let mut generated_files = 0_usize;
    let mut vendor_files = 0_usize;
    let mut total_limit_reached = false;
    let mut facts = Vec::<NormalizedFact>::new();
    let mut parser_diagnostics = Vec::<ParserDiagnostic>::new();
    let mut coverage = BTreeMap::<String, (usize, usize, usize, usize)>::new();
    let mut files_eligible_for_parsing = 0_usize;
    let mut files_parsed = 0_usize;
    let mut files_with_diagnostics = 0_usize;
    let mut parsing_completed = 0_usize;
    let mut parsing_duration = Duration::ZERO;
    let mut facts_truncated = false;
    let mut diagnostics_truncated = false;
    let mut programs = Vec::<ProgramUnit>::new();
    let mut program_records = 0_usize;

    for (index, discovered) in discovery.files.iter().enumerate() {
        check_cancelled(cancellation)?;
        progress(ProgressEvent::Inspecting {
            completed: index,
            total,
            path: discovered.relative.clone(),
        });

        if total_limit_reached {
            skipped_files.push(SkippedFile {
                path: discovered.relative.clone(),
                reason: "total-byte-limit".into(),
            });
            continue;
        }
        let remaining_total = request
            .configuration
            .max_total_bytes
            .saturating_sub(bytes_scanned);
        let content = match read_file_no_follow(
            &discovered.absolute,
            request.configuration.max_file_bytes,
            remaining_total,
            Some(cancellation),
        ) {
            Ok(ReadOutcome::Content(content)) => content,
            Ok(ReadOutcome::FileTooLarge) => {
                skipped_files.push(SkippedFile {
                    path: discovered.relative.clone(),
                    reason: "file-too-large".into(),
                });
                continue;
            }
            Ok(ReadOutcome::TotalLimit) => {
                total_limit_reached = true;
                skipped_files.push(SkippedFile {
                    path: discovered.relative.clone(),
                    reason: "total-byte-limit".into(),
                });
                continue;
            }
            Ok(ReadOutcome::NotRegular) => {
                skipped_files.push(SkippedFile {
                    path: discovered.relative.clone(),
                    reason: "changed-or-special-file".into(),
                });
                continue;
            }
            Err(_error) if cancellation.is_cancelled() => return Err(ScanError::Cancelled),
            Err(_error) => {
                push_bounded_error(
                    &mut errors,
                    &mut errors_truncated,
                    request.configuration.max_errors,
                    "read-failed",
                    Some(discovered.relative.clone()),
                    "File contents could not be read safely",
                );
                continue;
            }
        };
        check_cancelled(cancellation)?;

        let size_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
        bytes_scanned = bytes_scanned.saturating_add(size_bytes);
        let binary = is_binary(&content);
        if binary {
            binary_files = binary_files.saturating_add(1);
        } else {
            text_files = text_files.saturating_add(1);
        }
        match discovered.origin {
            FileOrigin::Project => {}
            FileOrigin::Generated => generated_files = generated_files.saturating_add(1),
            FileOrigin::Vendor => vendor_files = vendor_files.saturating_add(1),
        }

        let language = (!binary)
            .then(|| detect_language(&discovered.relative))
            .flatten()
            .map(str::to_owned);
        if let Some(name) = &language {
            let total_for_language = language_totals.entry(name.clone()).or_default();
            total_for_language.0 = total_for_language.0.saturating_add(1);
            total_for_language.1 = total_for_language.1.saturating_add(size_bytes);
        }
        let manifest = (!binary)
            .then(|| manifest_info(&discovered.relative))
            .flatten();
        let kind = classify_file(&discovered.relative, manifest, language.as_deref(), binary);
        let content_fingerprint = blake3::hash(&content).to_hex().to_string();
        update_length_prefixed(&mut repository_hasher, discovered.relative.as_bytes());
        update_length_prefixed(&mut repository_hasher, &content);
        files.push(FileRecord {
            path: discovered.relative.clone(),
            kind: kind.into(),
            size_bytes,
            content_fingerprint: content_fingerprint.clone(),
            language,
            origin: discovered.origin.as_str().into(),
            is_binary: binary,
        });

        if !binary && let Some(parser_mode) = ParserMode::for_path(&discovered.relative) {
            files_eligible_for_parsing = files_eligible_for_parsing.saturating_add(1);
            progress(ProgressEvent::Parsing {
                completed: parsing_completed,
                total: parsing_candidates,
                path: discovered.relative.clone(),
                parser_mode: parser_mode.as_str().into(),
            });
            let parse_started = Instant::now();
            let key = ParseCache::key(
                &discovered.relative,
                &content_fingerprint,
                parser_mode,
                &request.configuration,
            )?;
            let cached = if request.configuration.parse_cache_enabled {
                parse_cache.load(
                    &key,
                    &discovered.relative,
                    parser_mode,
                    &request.configuration,
                    cancellation,
                )?
            } else {
                None
            };
            let output = if let Some(output) = cached {
                output
            } else {
                let output = parse_source(
                    &discovered.relative,
                    &content,
                    parser_mode,
                    &request.configuration,
                    cancellation,
                )?;
                if request.configuration.parse_cache_enabled {
                    parse_cache.store(&key, &output, cancellation)?;
                }
                output
            };
            parsing_duration = parsing_duration.saturating_add(parse_started.elapsed());
            parsing_completed = parsing_completed.saturating_add(1);
            let mode_coverage = coverage.entry(parser_mode.as_str().into()).or_default();
            mode_coverage.0 = mode_coverage.0.saturating_add(1);
            if output.parsed {
                files_parsed = files_parsed.saturating_add(1);
                mode_coverage.1 = mode_coverage.1.saturating_add(1);
            }
            if !output.diagnostics.is_empty() {
                files_with_diagnostics = files_with_diagnostics.saturating_add(1);
                mode_coverage.2 = mode_coverage.2.saturating_add(1);
            }

            let fact_capacity = request
                .configuration
                .max_total_facts
                .saturating_sub(facts.len());
            let retained_facts = output.facts.len().min(fact_capacity);
            if retained_facts < output.facts.len() {
                facts_truncated = true;
            }
            mode_coverage.3 = mode_coverage.3.saturating_add(retained_facts);
            facts.extend(output.facts.into_iter().take(retained_facts));

            let diagnostic_capacity = request
                .configuration
                .max_parser_diagnostics
                .saturating_sub(parser_diagnostics.len());
            let retained_diagnostics = output.diagnostics.len().min(diagnostic_capacity);
            if retained_diagnostics < output.diagnostics.len() {
                diagnostics_truncated = true;
            }
            parser_diagnostics.extend(output.diagnostics.into_iter().take(retained_diagnostics));
            let mut program = output.program;
            let remaining_records = request
                .configuration
                .max_graph_nodes
                .saturating_sub(program_records);
            if program.records.len() > remaining_records {
                program.records.truncate(remaining_records);
                program.truncated = true;
            }
            program_records = program_records.saturating_add(program.records.len());
            programs.push(program);
        }

        if let Some(manifest) = manifest {
            let location = start_location(&discovered.relative);
            manifests.push(ManifestEvidence {
                kind: manifest.kind.into(),
                fingerprint: evidence_fingerprint("manifest", manifest.kind, &location),
                location: location.clone(),
            });
            capabilities.push(CapabilityEvidence {
                capability: "dependency-management".into(),
                reason: format!("Detected {} manifest", manifest.kind),
                fingerprint: evidence_fingerprint("capability", manifest.kind, &location),
                evidence: location.clone(),
            });
            trust_boundaries.push(TrustBoundaryEvidence {
                kind: "dependency-supply-chain".into(),
                description: "Declared third-party dependency boundary".into(),
                fingerprint: evidence_fingerprint("boundary", manifest.kind, &location),
                evidence: location,
            });
            detect_framework_evidence(
                &discovered.relative,
                &content,
                &mut frameworks,
                &mut trust_boundaries,
            );
        }

        if !binary && let Some(entry_kind) = entry_point_kind(&discovered.relative) {
            let location = start_location(&discovered.relative);
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

        if !binary && is_build_automation(&discovered.relative) {
            let location = start_location(&discovered.relative);
            capabilities.push(CapabilityEvidence {
                capability: "build-automation".into(),
                reason: "Detected build or continuous-integration configuration".into(),
                fingerprint: evidence_fingerprint(
                    "capability-build",
                    &discovered.relative,
                    &location,
                ),
                evidence: location,
            });
        }
    }

    check_cancelled(cancellation)?;
    progress(ProgressEvent::Finalizing);
    finalize_errors(
        &mut errors,
        errors_truncated,
        request.configuration.max_errors,
    );
    sort_and_deduplicate(&mut manifests);
    sort_and_deduplicate(&mut frameworks);
    sort_and_deduplicate(&mut entry_points);
    sort_and_deduplicate(&mut capabilities);
    sort_and_deduplicate(&mut trust_boundaries);
    facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
    facts.dedup_by(|left, right| left.fact_id == right.fact_id);
    parser_diagnostics.sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
    parser_diagnostics.dedup_by(|left, right| left.diagnostic_id == right.diagnostic_id);
    skipped_files
        .sort_by(|left, right| (&left.path, &left.reason).cmp(&(&right.path, &right.reason)));
    skipped_files.dedup();
    skipped_files.truncate(request.configuration.max_files);
    errors.sort_by(|left, right| (&left.path, &left.code).cmp(&(&right.path, &right.code)));
    if total_limit_reached {
        limitations.push(Limitation {
            code: "total-byte-limit-reached".into(),
            message: format!(
                "Content reads stopped at {} total bytes",
                request.configuration.max_total_bytes
            ),
        });
    }
    if facts_truncated {
        limitations.push(Limitation {
            code: "normalized-fact-limit-reached".into(),
            message: format!(
                "Only the first {} normalized facts were retained",
                request.configuration.max_total_facts
            ),
        });
    }
    if diagnostics_truncated {
        limitations.push(Limitation {
            code: "parser-diagnostic-limit-reached".into(),
            message: format!(
                "Only the first {} parser diagnostics were retained",
                request.configuration.max_parser_diagnostics
            ),
        });
    }

    progress(ProgressEvent::Analyzing { facts: facts.len() });
    let analysis_result = analyze(&facts, &programs, &request.configuration, cancellation)?;
    limitations.extend(analysis_result.limitations);

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
    let files_scanned = files.len();
    let inventory = InventorySummary {
        entries_seen: discovery.entries_seen,
        candidate_files: discovery.candidate_files,
        files_selected: total,
        files_scanned,
        text_files,
        binary_files,
        generated_files,
        vendor_files,
        bytes_scanned,
        symlinks_skipped: discovery.symlinks_skipped,
        nested_repositories_skipped: discovery.nested_repositories_skipped,
        hit_file_limit: discovery.candidate_files > request.configuration.max_files,
        hit_total_byte_limit: total_limit_reached,
    };
    let cache_stats = parse_cache.stats();
    let parser_coverage = coverage
        .into_iter()
        .map(
            |(
                parser_mode,
                (files_eligible, files_parsed, files_with_diagnostics, facts_extracted),
            )| {
                ParserCoverage {
                    parser_mode,
                    files_eligible,
                    files_parsed,
                    files_with_diagnostics,
                    facts_extracted,
                }
            },
        )
        .collect::<Vec<_>>();
    let parsing = ParsingSummary {
        files_eligible: files_eligible_for_parsing,
        files_parsed,
        files_with_diagnostics,
        facts_extracted: facts.len(),
        duration_ms: u64::try_from(parsing_duration.as_millis()).unwrap_or(u64::MAX),
        cache_enabled: request.configuration.parse_cache_enabled,
        cache_hits: cache_stats.hits,
        cache_misses: cache_stats.misses,
        cache_writes: cache_stats.writes,
        cache_entries_ignored: cache_stats.ignored,
    };

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
            files_scanned,
        },
        inventory,
        parsing,
        facts,
        parser_diagnostics,
        parser_coverage,
        graph: analysis_result.graph,
        analysis: analysis_result.summary,
        suppression_diagnostics: analysis_result.suppression_diagnostics,
        taxonomy_catalog: vec![crate::taxonomy_descriptor()],
        files,
        languages,
        manifests,
        frameworks,
        entry_points,
        capabilities,
        trust_boundaries,
        findings: analysis_result.findings,
        limitations,
        skipped_files,
        exclusions: discovery.exclusions,
        errors,
        report_fingerprint: String::new(),
    };
    report.report_fingerprint = report_fingerprint(&report)?;
    progress(ProgressEvent::Complete { files_scanned });
    Ok(report)
}

fn validate_configuration(configuration: &ScanConfiguration) -> Result<(), ScanError> {
    if configuration.max_files == 0
        || configuration.max_file_bytes == 0
        || configuration.max_total_bytes == 0
        || configuration.max_errors == 0
    {
        return Err(ScanError::InvalidConfiguration(
            "resource limits must be greater than zero".into(),
        ));
    }
    if configuration.max_errors > MAX_CONFIGURED_ERRORS {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_errors cannot exceed {MAX_CONFIGURED_ERRORS}"
        )));
    }
    if configuration.max_files > MAX_CONFIGURED_FILES {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_files cannot exceed {MAX_CONFIGURED_FILES}"
        )));
    }
    if configuration.max_file_bytes > MAX_CONFIGURED_FILE_BYTES {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_file_bytes cannot exceed {MAX_CONFIGURED_FILE_BYTES}"
        )));
    }
    if configuration.max_total_bytes > MAX_CONFIGURED_TOTAL_BYTES {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_total_bytes cannot exceed {MAX_CONFIGURED_TOTAL_BYTES}"
        )));
    }
    if configuration
        .max_depth
        .is_some_and(|depth| depth > MAX_CONFIGURED_DEPTH)
    {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_depth cannot exceed {MAX_CONFIGURED_DEPTH}"
        )));
    }
    if configuration.max_cache_bytes == 0
        || configuration.max_cache_bytes > MAX_CONFIGURED_CACHE_BYTES
    {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_cache_bytes must be between 1 and {MAX_CONFIGURED_CACHE_BYTES}"
        )));
    }
    if configuration.max_parser_diagnostics == 0
        || configuration.max_parser_diagnostics > MAX_CONFIGURED_PARSER_DIAGNOSTICS
    {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_parser_diagnostics must be between 1 and {MAX_CONFIGURED_PARSER_DIAGNOSTICS}"
        )));
    }
    if configuration.max_facts_per_file == 0
        || configuration.max_facts_per_file > MAX_CONFIGURED_FACTS_PER_FILE
    {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_facts_per_file must be between 1 and {MAX_CONFIGURED_FACTS_PER_FILE}"
        )));
    }
    if configuration.max_total_facts == 0
        || configuration.max_total_facts > MAX_CONFIGURED_TOTAL_FACTS
    {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_total_facts must be between 1 and {MAX_CONFIGURED_TOTAL_FACTS}"
        )));
    }
    if configuration.max_graph_nodes == 0
        || configuration.max_graph_nodes > MAX_CONFIGURED_GRAPH_NODES
    {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_graph_nodes must be between 1 and {MAX_CONFIGURED_GRAPH_NODES}"
        )));
    }
    if configuration.max_graph_edges == 0
        || configuration.max_graph_edges > MAX_CONFIGURED_GRAPH_EDGES
    {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_graph_edges must be between 1 and {MAX_CONFIGURED_GRAPH_EDGES}"
        )));
    }
    if configuration.max_interprocedural_depth == 0
        || configuration.max_interprocedural_depth > MAX_CONFIGURED_INTERPROCEDURAL_DEPTH
    {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_interprocedural_depth must be between 1 and {MAX_CONFIGURED_INTERPROCEDURAL_DEPTH}"
        )));
    }
    if configuration.max_findings == 0 || configuration.max_findings > MAX_CONFIGURED_FINDINGS {
        return Err(ScanError::InvalidConfiguration(format!(
            "max_findings must be between 1 and {MAX_CONFIGURED_FINDINGS}"
        )));
    }
    validate_suppressions(configuration)?;
    Ok(())
}

fn validate_suppressions(configuration: &ScanConfiguration) -> Result<(), ScanError> {
    if configuration.suppressions.len() > 10_000 {
        return Err(ScanError::InvalidConfiguration(
            "suppressions cannot exceed 10000 entries".into(),
        ));
    }
    if configuration.suppressions.iter().any(|suppression| {
        suppression.rule_id.is_empty()
            || suppression.rule_id.len() > 32
            || suppression.path.is_empty()
            || suppression.path.len() > 1024
            || suppression.path.starts_with('/')
            || suppression.path.contains('\\')
            || suppression
                .path
                .split('/')
                .any(|component| component == "..")
            || suppression.path.chars().any(char::is_control)
            || suppression.reason.is_empty()
            || suppression.reason.len() > 1024
            || suppression.reason.chars().any(char::is_control)
    }) {
        return Err(ScanError::InvalidConfiguration(
            "suppression values must be bounded and repository-relative".into(),
        ));
    }
    Ok(())
}

fn inventory_limitations(
    configuration: &ScanConfiguration,
    discovery: &crate::workspace::DiscoveryResult,
) -> Vec<Limitation> {
    let mut limitations = vec![
        Limitation {
            code: "deterministic-rules-limited".into(),
            message:
                "Phase 3 runs only the documented high-confidence JavaScript and TypeScript rules"
                    .into(),
        },
        Limitation {
            code: "parser-coverage-limited".into(),
            message: "Language-aware parsing is limited to JavaScript, JSX, TypeScript, and TSX"
                .into(),
        },
        Limitation {
            code: "framework-hints-only".into(),
            message: "Framework evidence is a manifest hint and not semantic proof".into(),
        },
        Limitation {
            code: "symlinks-not-followed".into(),
            message: "Symbolic links are recorded but never followed".into(),
        },
        Limitation {
            code: "vcs-metadata-excluded".into(),
            message: "Version-control metadata directories are never inventoried".into(),
        },
    ];
    if !configuration.include_hidden {
        limitations.push(Limitation {
            code: "hidden-files-excluded".into(),
            message: "Hidden files and directories were excluded by configuration".into(),
        });
    }
    if configuration.respect_ignore_files {
        limitations.push(Limitation {
            code: "ignored-files-excluded".into(),
            message: "Inputs matched by repository ignore rules were excluded before reading"
                .into(),
        });
    }
    if !configuration.include_generated {
        limitations.push(Limitation {
            code: "generated-directories-excluded".into(),
            message: "Common generated and build directories were excluded before reading".into(),
        });
    }
    if !configuration.include_vendor {
        limitations.push(Limitation {
            code: "vendor-directories-excluded".into(),
            message: "Common vendored dependency directories were excluded before reading".into(),
        });
    }
    if !configuration.include_nested_repositories {
        limitations.push(Limitation {
            code: "nested-repositories-excluded".into(),
            message: "Nested repositories, worktrees, and submodules were excluded".into(),
        });
    }
    if let Some(max_depth) = configuration.max_depth {
        limitations.push(Limitation {
            code: "depth-limit-configured".into(),
            message: format!("Traversal was bounded to repository depth {max_depth}"),
        });
    }
    if discovery.candidate_files > configuration.max_files {
        limitations.push(Limitation {
            code: "file-limit-reached".into(),
            message: format!(
                "Only the first {} of {} matching files were selected",
                configuration.max_files, discovery.candidate_files
            ),
        });
    }
    limitations
}

fn detect_framework_evidence(
    path: &str,
    content: &[u8],
    frameworks: &mut Vec<FrameworkEvidence>,
    boundaries: &mut Vec<TrustBoundaryEvidence>,
) {
    for framework_match in framework_matches(content) {
        let location = location_for_bytes(
            path,
            content,
            framework_match.offset,
            framework_match.length,
        );
        frameworks.push(FrameworkEvidence {
            name: framework_match.name.into(),
            fingerprint: evidence_fingerprint("framework", framework_match.name, &location),
            evidence: location.clone(),
        });
        boundaries.push(TrustBoundaryEvidence {
            kind: "network-request".into(),
            description: format!(
                "{} may expose network request entry points",
                framework_match.name
            ),
            fingerprint: evidence_fingerprint("boundary-network", framework_match.name, &location),
            evidence: location,
        });
    }
}

fn repository_identity(root: &Path, content_fingerprint: String) -> RepositoryIdentity {
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("repository")
        .to_owned();
    let git = git_metadata(root);
    let mut hasher = blake3::Hasher::new();
    update_length_prefixed(&mut hasher, name.as_bytes());
    update_length_prefixed(&mut hasher, git.vcs.as_deref().unwrap_or("").as_bytes());
    update_length_prefixed(
        &mut hasher,
        git.revision.as_deref().unwrap_or("").as_bytes(),
    );
    update_length_prefixed(&mut hasher, git.repository_kind.as_bytes());
    update_length_prefixed(&mut hasher, content_fingerprint.as_bytes());
    RepositoryIdentity {
        name,
        vcs: git.vcs,
        revision: git.revision,
        repository_kind: git.repository_kind,
        content_fingerprint,
        identity_fingerprint: hasher.finalize().to_hex().to_string(),
    }
}

struct GitMetadata {
    vcs: Option<String>,
    revision: Option<String>,
    repository_kind: String,
}

fn git_metadata(root: &Path) -> GitMetadata {
    let marker = root.join(".git");
    let Ok(marker_metadata) = fs::symlink_metadata(&marker) else {
        return GitMetadata {
            vcs: None,
            revision: None,
            repository_kind: "directory".into(),
        };
    };
    if marker_metadata.file_type().is_symlink() {
        return GitMetadata {
            vcs: None,
            revision: None,
            repository_kind: "directory".into(),
        };
    }
    let (git_directory, repository_kind) = if marker_metadata.is_dir() {
        (fs::canonicalize(&marker).ok(), "git-repository")
    } else if marker_metadata.is_file() {
        let directory = read_small_text(&marker, 4096)
            .and_then(|content| content.trim().strip_prefix("gitdir: ").map(str::to_owned))
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    root.join(path)
                }
            })
            .and_then(|path| fs::canonicalize(path).ok())
            .filter(|path| path.is_dir());
        (directory, "git-worktree")
    } else {
        (None, "directory")
    };
    let Some(git_directory) = git_directory else {
        return GitMetadata {
            vcs: None,
            revision: None,
            repository_kind: "directory".into(),
        };
    };
    GitMetadata {
        vcs: Some("git".into()),
        revision: git_revision(&git_directory),
        repository_kind: repository_kind.into(),
    }
}

fn git_revision(git_directory: &Path) -> Option<String> {
    let head = read_small_text(&git_directory.join("HEAD"), GIT_METADATA_LIMIT)?;
    let head = head.trim();
    if valid_object_id(head) {
        return Some(head.to_ascii_lowercase());
    }
    let reference = head.strip_prefix("ref: ")?;
    if !valid_git_reference(reference) {
        return None;
    }
    let common_directory = read_small_text(&git_directory.join("commondir"), 4096)
        .map(|value| PathBuf::from(value.trim()))
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                git_directory.join(path)
            }
        })
        .and_then(|path| fs::canonicalize(path).ok())
        .filter(|path| path.is_dir())
        .unwrap_or_else(|| git_directory.to_owned());
    read_small_text(&git_directory.join(reference), GIT_METADATA_LIMIT)
        .or_else(|| read_small_text(&common_directory.join(reference), GIT_METADATA_LIMIT))
        .map(|value| value.trim().to_owned())
        .filter(|value| valid_object_id(value))
        .map(|value| value.to_ascii_lowercase())
        .or_else(|| packed_reference(&common_directory.join("packed-refs"), reference))
}

fn packed_reference(path: &Path, reference: &str) -> Option<String> {
    let packed = read_small_text(path, GIT_METADATA_LIMIT)?;
    packed.lines().find_map(|line| {
        if line.starts_with(['#', '^']) {
            return None;
        }
        let (object_id, candidate) = line.split_once(' ')?;
        (candidate == reference && valid_object_id(object_id))
            .then(|| object_id.to_ascii_lowercase())
    })
}

fn read_small_text(path: &Path, maximum: u64) -> Option<String> {
    match read_file_no_follow(path, maximum, maximum, None).ok()? {
        ReadOutcome::Content(content) => String::from_utf8(content).ok(),
        ReadOutcome::FileTooLarge | ReadOutcome::TotalLimit | ReadOutcome::NotRegular => None,
    }
}

fn valid_git_reference(reference: &str) -> bool {
    reference.starts_with("refs/")
        && reference
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !reference.contains(['\0', '\\'])
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), ScanError> {
    if cancellation.is_cancelled() {
        Err(ScanError::Cancelled)
    } else {
        Ok(())
    }
}

fn push_bounded_error(
    errors: &mut Vec<BoundedError>,
    truncated: &mut bool,
    maximum: usize,
    code: &str,
    path: Option<String>,
    message: &str,
) {
    let retained = errors
        .iter()
        .filter(|error| error.code != "error-limit-reached")
        .count();
    if retained < maximum.saturating_sub(1) {
        errors.push(BoundedError {
            code: code.into(),
            path,
            message: message.into(),
        });
    } else {
        *truncated = true;
    }
}

fn finalize_errors(errors: &mut Vec<BoundedError>, truncated: bool, maximum: usize) {
    errors.retain(|error| error.code != "error-limit-reached");
    if truncated {
        errors.truncate(maximum.saturating_sub(1));
        errors.push(BoundedError {
            code: "error-limit-reached".into(),
            path: None,
            message: "Additional non-fatal errors were omitted".into(),
        });
    } else {
        errors.truncate(maximum);
    }
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
    struct StableParsing {
        files_eligible: usize,
        files_parsed: usize,
        files_with_diagnostics: usize,
        facts_extracted: usize,
        cache_enabled: bool,
    }

    #[derive(Serialize)]
    struct StableAnalysis {
        nodes: usize,
        edges: usize,
        candidate_paths: usize,
        rules_evaluated: usize,
        findings: usize,
        findings_suppressed: usize,
        truncated: bool,
    }

    #[derive(Serialize)]
    struct StableReport<'a> {
        schema_version: &'a str,
        engine_version: &'a str,
        document_type: &'a str,
        repository: &'a RepositoryIdentity,
        configuration: &'a ScanConfiguration,
        files_discovered: usize,
        files_scanned: usize,
        inventory: &'a InventorySummary,
        parsing: StableParsing,
        facts: &'a [NormalizedFact],
        parser_diagnostics: &'a [ParserDiagnostic],
        parser_coverage: &'a [ParserCoverage],
        graph: &'a crate::EvidenceGraph,
        analysis: StableAnalysis,
        suppression_diagnostics: &'a [crate::SuppressionDiagnostic],
        taxonomy_catalog: &'a [crate::TaxonomyDescriptor],
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
        exclusions: &'a [ExclusionSummary],
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
        inventory: &report.inventory,
        parsing: StableParsing {
            files_eligible: report.parsing.files_eligible,
            files_parsed: report.parsing.files_parsed,
            files_with_diagnostics: report.parsing.files_with_diagnostics,
            facts_extracted: report.parsing.facts_extracted,
            cache_enabled: report.parsing.cache_enabled,
        },
        facts: &report.facts,
        parser_diagnostics: &report.parser_diagnostics,
        parser_coverage: &report.parser_coverage,
        graph: &report.graph,
        analysis: StableAnalysis {
            nodes: report.analysis.nodes,
            edges: report.analysis.edges,
            candidate_paths: report.analysis.candidate_paths,
            rules_evaluated: report.analysis.rules_evaluated,
            findings: report.analysis.findings,
            findings_suppressed: report.analysis.findings_suppressed,
            truncated: report.analysis.truncated,
        },
        suppression_diagnostics: &report.suppression_diagnostics,
        taxonomy_catalog: &report.taxonomy_catalog,
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
        exclusions: &report.exclusions,
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
