#![allow(missing_docs)]

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use secure_engine::{
    AiCache, AiError, AiProjectConfiguration, AiValidationDocument, Baseline, CacheControl,
    CancellationToken, DoctorCheck, DoctorReport, ENGINE_VERSION, ExportFormat, HistoryStore,
    ProgressEvent, SCHEMA_VERSION, SECURE_AI_ASSESSMENT_V1_SCHEMA, SECURE_JSON_V1_SCHEMA,
    ScanError, ScanReport, ScanRequest, Suppression, compare_baseline, configured_provider,
    create_baseline, default_ai_cache_directory, default_history_directory, explain_finding,
    preview_finding, provider_descriptors, read_ai_configuration, rules, scan_repository,
    serialize_export, validate_baseline, validate_finding_with_ai, validation_document,
    write_export, write_json_artifact,
};

const EXIT_POLICY_FINDINGS: u8 = 1;
const EXIT_INVALID_INPUT: u8 = 2;
const EXIT_UNSUPPORTED_SCHEMA: u8 = 3;
const EXIT_CANCELLED: u8 = 4;
const EXIT_INTERNAL_FAILURE: u8 = 5;

#[derive(Debug, Parser)]
#[command(
    name = "secure",
    version,
    about = "Local-first security analysis for entire codebases"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inventory a local repository and emit a versioned report.
    Scan(Box<ScanArgs>),
    /// Check the local engine contract and runtime.
    Doctor(FormatArgs),
    /// Inspect public integration schemas.
    Schema {
        #[command(subcommand)]
        command: SchemaCommand,
    },
    /// Inspect deterministic built-in rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Explain one finding from a completed secure-json-v1 report.
    Explain(ExplainArgs),
    /// Create or compare deterministic finding baselines.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// List, reopen, or delete completed local scans.
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    /// Preview and run optional AI-assisted finding validation.
    Ai {
        #[command(subcommand)]
        command: AiCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AiCommand {
    /// List built-in provider capabilities without contacting a provider.
    Providers,
    /// Emit the exact redacted request scope and consent fingerprint.
    Preview(AiPreviewArgs),
    /// Validate one finding or a bounded selected set after exact consent.
    Validate(AiValidateArgs),
    /// Manage the private local AI response cache.
    Cache {
        #[command(subcommand)]
        command: AiCacheCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AiCacheCommand {
    /// Delete all locally cached AI assessments.
    Clear(AiCacheOptions),
}

#[derive(Debug, Args)]
struct AiCacheOptions {
    /// Override the private local AI cache directory.
    #[arg(long, value_name = "DIRECTORY")]
    cache_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct AiPreviewArgs {
    /// Stable finding identifier; omit only with --all.
    finding_id: Option<String>,
    /// Preview every finding, still bounded by --max-findings and project limits.
    #[arg(long, conflicts_with = "finding_id")]
    all: bool,
    /// Completed secure-json-v1 report.
    #[arg(long, value_name = "REPORT")]
    report: PathBuf,
    /// Provider identifier, which must match project configuration.
    #[arg(long)]
    provider: String,
    /// Explicit project AI configuration.
    #[arg(long, value_name = "CONFIG")]
    config: PathBuf,
    /// Maximum findings included when --all is used.
    #[arg(long, default_value_t = 10)]
    max_findings: usize,
}

#[derive(Debug, Args)]
struct AiValidateArgs {
    /// Stable finding identifier; omit only with --all.
    finding_id: Option<String>,
    /// Validate a bounded set of all findings.
    #[arg(long, conflicts_with = "finding_id")]
    all: bool,
    /// Completed secure-json-v1 report.
    #[arg(long, value_name = "REPORT")]
    report: PathBuf,
    /// Provider identifier, which must match project configuration.
    #[arg(long)]
    provider: String,
    /// Explicit project AI configuration.
    #[arg(long, value_name = "CONFIG")]
    config: PathBuf,
    /// Exact consent fingerprint from preview; repeat once per selected finding.
    #[arg(long = "consent", required = true)]
    consents: Vec<String>,
    /// Maximum findings included when --all is used.
    #[arg(long, default_value_t = 10)]
    max_findings: usize,
    /// Override the private local AI cache directory.
    #[arg(long, value_name = "DIRECTORY")]
    cache_dir: Option<PathBuf>,
    /// Atomically write the versioned AI validation document here.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Bypass a matching cache entry and contact the configured provider.
    #[arg(long)]
    no_cache: bool,
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
struct ScanArgs {
    /// Local repository directory.
    repository: PathBuf,
    /// Machine format. Phase 3 preserves secure-json-v1 additively.
    #[arg(long, default_value = SCHEMA_VERSION)]
    format: String,
    /// Atomically write the report here instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Include hidden files unless excluded by ignore rules.
    #[arg(long)]
    include_hidden: bool,
    /// Maximum number of files to inspect.
    #[arg(long, default_value_t = 100_000)]
    max_files: usize,
    /// Maximum bytes read from one file.
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    max_file_bytes: u64,
    /// Maximum total bytes read across all selected files.
    #[arg(long, default_value_t = 512 * 1024 * 1024)]
    max_total_bytes: u64,
    /// Optional maximum traversal depth; repository root is depth zero.
    #[arg(long)]
    max_depth: Option<usize>,
    /// Maximum bounded errors retained in the report.
    #[arg(long, default_value_t = 100)]
    max_errors: usize,
    /// Include only repository-relative paths matching this glob; repeatable.
    #[arg(long = "include", value_name = "GLOB")]
    include_patterns: Vec<String>,
    /// Exclude repository-relative paths matching this glob; repeatable.
    #[arg(long = "exclude", value_name = "GLOB")]
    exclude_patterns: Vec<String>,
    /// Traverse common generated and build directories.
    #[arg(long)]
    include_generated: bool,
    /// Traverse common vendored dependency directories.
    #[arg(long)]
    include_vendor: bool,
    /// Traverse nested repositories and submodules.
    #[arg(long)]
    include_nested_repositories: bool,
    /// Do not honor .gitignore and related repository ignore files.
    #[arg(long)]
    no_ignore: bool,
    /// Disable local reuse of supported-language parse results.
    #[arg(long)]
    no_cache: bool,
    /// Retire this repository's parse cache before scanning.
    #[arg(long)]
    clear_cache: bool,
    /// Local parse-cache base directory; never exported in the report.
    #[arg(long, value_name = "DIRECTORY")]
    cache_dir: Option<PathBuf>,
    /// Maximum repository-specific parse-cache bytes.
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    max_cache_bytes: u64,
    /// Maximum parser diagnostics retained in the report.
    #[arg(long, default_value_t = 1_000)]
    max_parser_diagnostics: usize,
    /// Maximum normalized facts retained per parsed file.
    #[arg(long, default_value_t = 10_000)]
    max_facts_per_file: usize,
    /// Maximum normalized facts retained across the report.
    #[arg(long, default_value_t = 100_000)]
    max_total_facts: usize,
    /// Maximum evidence-graph nodes retained.
    #[arg(long, default_value_t = 250_000)]
    max_graph_nodes: usize,
    /// Maximum evidence-graph edges retained.
    #[arg(long, default_value_t = 500_000)]
    max_graph_edges: usize,
    /// Maximum bounded local inter-procedural traversal depth.
    #[arg(long, default_value_t = 4)]
    max_interprocedural_depth: usize,
    /// Maximum findings retained after deduplication.
    #[arg(long, default_value_t = 10_000)]
    max_findings: usize,
    /// Exact suppression: `RULE_ID:RELATIVE_PATH:START_BYTE:REASON`. Repeatable.
    #[arg(long = "suppress", value_name = "RULE:PATH:BYTE:REASON")]
    suppressions: Vec<String>,
    /// Suppress progress and human-readable summaries on stderr.
    #[arg(long, conflicts_with = "verbose")]
    quiet: bool,
    /// Emit detailed progress on stderr.
    #[arg(long, conflicts_with = "quiet")]
    verbose: bool,
    /// Disable ANSI color. Output is currently color-free in every mode.
    #[arg(long)]
    no_color: bool,
    /// Save the completed scan to local history.
    #[arg(long)]
    save_history: bool,
    /// Override the private local history directory.
    #[arg(long, value_name = "DIRECTORY")]
    history_dir: Option<PathBuf>,
    /// Maximum completed scans retained when saving history.
    #[arg(long, default_value_t = 50)]
    history_retention: usize,
}

#[derive(Debug, Args)]
struct FormatArgs {
    /// Machine format. Phase 3 preserves secure-json-v1 additively.
    #[arg(long, default_value = SCHEMA_VERSION)]
    format: String,
}

#[derive(Debug, Subcommand)]
enum SchemaCommand {
    /// Print a canonical JSON Schema to stdout.
    Print {
        /// Schema identifier.
        schema: String,
    },
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// Print the stable deterministic rule catalog as JSON.
    List,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Stable finding identifier.
    finding_id: String,
    /// Completed secure-json-v1 scan report to inspect.
    #[arg(long, value_name = "REPORT")]
    report: PathBuf,
}

#[derive(Debug, Subcommand)]
enum BaselineCommand {
    /// Create a versioned baseline from a complete report.
    Create {
        /// Complete secure-json-v1 report.
        report: PathBuf,
        /// Atomically written baseline destination.
        #[arg(long)]
        output: PathBuf,
    },
    /// Compare a baseline with a complete current report.
    Compare {
        /// Versioned baseline file.
        baseline: PathBuf,
        /// Complete current secure-json-v1 report.
        report: PathBuf,
        /// Optional atomic JSON destination; stdout is used otherwise.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    /// List safe completed-scan metadata newest first.
    List(HistoryOptions),
    /// Reopen one complete historical report.
    Show {
        /// Local scan identifier.
        scan_id: String,
        #[command(flatten)]
        options: HistoryOptions,
    },
    /// Explicitly delete one local history record.
    Delete {
        /// Local scan identifier.
        scan_id: String,
        #[command(flatten)]
        options: HistoryOptions,
    },
}

#[derive(Debug, Args)]
struct HistoryOptions {
    /// Override the private local history directory.
    #[arg(long, value_name = "DIRECTORY")]
    history_dir: Option<PathBuf>,
    /// Maximum completed scans retained by this store.
    #[arg(long, default_value_t = 50)]
    retention: usize,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err((code, message)) => {
            eprintln!("secure: {message}");
            ExitCode::from(code)
        }
    }
}

fn run(cli: Cli) -> Result<u8, (u8, String)> {
    match cli.command {
        Command::Scan(arguments) => run_scan(*arguments),
        Command::Doctor(arguments) => run_doctor(&arguments.format),
        Command::Schema {
            command: SchemaCommand::Print { schema },
        } => print_schema(&schema),
        Command::Rules {
            command: RulesCommand::List,
        } => list_rules(),
        Command::Explain(arguments) => explain(&arguments),
        Command::Baseline { command } => run_baseline(command),
        Command::History { command } => run_history(command),
        Command::Ai { command } => run_ai(command),
    }
}

#[allow(clippy::too_many_lines)]
fn run_scan(arguments: ScanArgs) -> Result<u8, (u8, String)> {
    let export_format = require_scan_format(&arguments.format)?;
    if arguments.max_files == 0
        || arguments.max_file_bytes == 0
        || arguments.max_total_bytes == 0
        || arguments.max_errors == 0
        || arguments.max_cache_bytes == 0
        || arguments.max_parser_diagnostics == 0
        || arguments.max_facts_per_file == 0
        || arguments.max_total_facts == 0
        || arguments.max_graph_nodes == 0
        || arguments.max_graph_edges == 0
        || arguments.max_interprocedural_depth == 0
        || arguments.max_findings == 0
        || arguments.history_retention == 0
        || arguments.history_retention > 10_000
    {
        return Err((
            EXIT_INVALID_INPUT,
            "resource limits must be greater than zero".into(),
        ));
    }

    let cancellation = CancellationToken::new();
    install_cancellation(&cancellation)?;

    let mut request = ScanRequest::new(arguments.repository);
    request.configuration.include_hidden = arguments.include_hidden;
    request.configuration.max_files = arguments.max_files;
    request.configuration.max_file_bytes = arguments.max_file_bytes;
    request.configuration.max_total_bytes = arguments.max_total_bytes;
    request.configuration.max_depth = arguments.max_depth;
    request.configuration.max_errors = arguments.max_errors;
    request.configuration.respect_ignore_files = !arguments.no_ignore;
    request.configuration.include_patterns = arguments.include_patterns;
    request.configuration.exclude_patterns = arguments.exclude_patterns;
    request.configuration.include_generated = arguments.include_generated;
    request.configuration.include_vendor = arguments.include_vendor;
    request.configuration.include_nested_repositories = arguments.include_nested_repositories;
    request.configuration.parse_cache_enabled = !arguments.no_cache;
    request.configuration.max_cache_bytes = arguments.max_cache_bytes;
    request.configuration.max_parser_diagnostics = arguments.max_parser_diagnostics;
    request.configuration.max_facts_per_file = arguments.max_facts_per_file;
    request.configuration.max_total_facts = arguments.max_total_facts;
    request.configuration.max_graph_nodes = arguments.max_graph_nodes;
    request.configuration.max_graph_edges = arguments.max_graph_edges;
    request.configuration.max_interprocedural_depth = arguments.max_interprocedural_depth;
    request.configuration.max_findings = arguments.max_findings;
    request.configuration.suppressions = arguments
        .suppressions
        .iter()
        .map(|value| parse_suppression(value))
        .collect::<Result<Vec<_>, _>>()?;
    request.cache = CacheControl {
        directory: arguments.cache_dir,
        clear_before_scan: arguments.clear_cache,
    };
    let quiet = arguments.quiet;
    let verbose = arguments.verbose;
    let repository_path = request.repository.clone();
    let report = scan_repository(&request, &cancellation, |event| {
        print_progress(&event, quiet, verbose);
    })
    .map_err(scan_error)?;
    if cancellation.is_cancelled() {
        return Err((EXIT_CANCELLED, "scan cancelled".into()));
    }

    if let Some(output) = arguments.output {
        write_export(&report, export_format, &output, &cancellation)
            .map_err(|error| export_error(&error, "report"))?;
        if !quiet {
            eprintln!("secure: wrote complete report to {}", output.display());
        }
    } else {
        let bytes = serialize_export(&report, export_format).map_err(|_| {
            (
                EXIT_INTERNAL_FAILURE,
                "complete report could not be serialized".into(),
            )
        })?;
        write_stdout(&bytes).map_err(|message| (EXIT_INTERNAL_FAILURE, message))?;
    }
    if arguments.save_history {
        let directory = arguments
            .history_dir
            .unwrap_or_else(default_history_directory);
        let store = HistoryStore::open(directory, arguments.history_retention)
            .map_err(|error| (EXIT_INVALID_INPUT, error.to_string()))?;
        let saved = store
            .record(&report, Some(&repository_path), None, &cancellation)
            .map_err(|error| history_error(&error))?;
        if !quiet {
            eprintln!("secure: saved history {}", saved.scan_id);
        }
    }
    if !quiet {
        eprintln!(
            "secure: {} findings, {} files, {} facts, {} graph nodes, {} cache hits, {} ms",
            report.findings.len(),
            report.inventory.files_scanned,
            report.facts.len(),
            report.analysis.nodes,
            report.parsing.cache_hits,
            report.scan.duration_ms
        );
    }
    Ok(if report.findings.is_empty() {
        0
    } else {
        EXIT_POLICY_FINDINGS
    })
}

fn run_doctor(format: &str) -> Result<u8, (u8, String)> {
    require_schema(format)?;
    let report = DoctorReport {
        schema_version: SCHEMA_VERSION.into(),
        engine_version: ENGINE_VERSION.into(),
        document_type: "doctor-report".into(),
        healthy: true,
        checks: vec![
            DoctorCheck {
                name: "schema".into(),
                status: "pass".into(),
                detail: "secure-json-v1 is bundled".into(),
            },
            DoctorCheck {
                name: "local-analysis".into(),
                status: "pass".into(),
                detail: "repository inventory requires no network service".into(),
            },
            DoctorCheck {
                name: "advanced-rules".into(),
                status: "warn".into(),
                detail: "Phase 3 provides a bounded evidence graph and seven deterministic JavaScript and TypeScript rules".into(),
            },
        ],
    };
    let bytes = serde_json::to_vec_pretty(&report).map_err(|_| {
        (
            EXIT_INTERNAL_FAILURE,
            "doctor report could not be serialized".into(),
        )
    })?;
    write_stdout(&bytes).map_err(|message| (EXIT_INTERNAL_FAILURE, message))?;
    Ok(0)
}

fn list_rules() -> Result<u8, (u8, String)> {
    let bytes = serde_json::to_vec_pretty(&rules()).map_err(|_| {
        (
            EXIT_INTERNAL_FAILURE,
            "rule catalog could not be serialized".into(),
        )
    })?;
    write_stdout(&bytes).map_err(|message| (EXIT_INTERNAL_FAILURE, message))?;
    Ok(0)
}

fn explain(arguments: &ExplainArgs) -> Result<u8, (u8, String)> {
    let report = read_report(&arguments.report)?;
    require_schema(&report.schema_version)?;
    let finding = explain_finding(&report, &arguments.finding_id).ok_or_else(|| {
        (
            EXIT_INVALID_INPUT,
            "finding ID was not present in the report".into(),
        )
    })?;
    let output = serde_json::to_vec_pretty(finding).map_err(|_| {
        (
            EXIT_INTERNAL_FAILURE,
            "finding explanation could not be serialized".into(),
        )
    })?;
    write_stdout(&output).map_err(|message| (EXIT_INTERNAL_FAILURE, message))?;
    Ok(0)
}

fn run_baseline(command: BaselineCommand) -> Result<u8, (u8, String)> {
    let cancellation = CancellationToken::new();
    install_cancellation(&cancellation)?;
    match command {
        BaselineCommand::Create { report, output } => {
            let report = read_report(&report)?;
            let baseline = create_baseline(&report)
                .map_err(|error| (EXIT_INVALID_INPUT, error.to_string()))?;
            write_json_artifact(&baseline, &output, &cancellation)
                .map_err(|error| export_error(&error, "baseline"))?;
            eprintln!(
                "secure: wrote deterministic baseline to {}",
                output.display()
            );
            Ok(0)
        }
        BaselineCommand::Compare {
            baseline,
            report,
            output,
        } => {
            let baseline = read_baseline(&baseline)?;
            let report = read_report(&report)?;
            let comparison = compare_baseline(&baseline, &report)
                .map_err(|error| (EXIT_INVALID_INPUT, error.to_string()))?;
            if let Some(output) = output {
                write_json_artifact(&comparison, &output, &cancellation)
                    .map_err(|error| export_error(&error, "baseline comparison"))?;
            } else {
                let bytes = serde_json::to_vec_pretty(&comparison).map_err(|_| {
                    (
                        EXIT_INTERNAL_FAILURE,
                        "baseline comparison could not be serialized".into(),
                    )
                })?;
                write_stdout(&bytes).map_err(|message| (EXIT_INTERNAL_FAILURE, message))?;
            }
            eprintln!(
                "secure: baseline {} new, {} changed, {} resolved, {} unchanged",
                comparison.new.len(),
                comparison.changed.len(),
                comparison.resolved.len(),
                comparison.unchanged.len()
            );
            Ok(if comparison.has_changes() {
                EXIT_POLICY_FINDINGS
            } else {
                0
            })
        }
    }
}

fn run_history(command: HistoryCommand) -> Result<u8, (u8, String)> {
    let cancellation = CancellationToken::new();
    install_cancellation(&cancellation)?;
    match command {
        HistoryCommand::List(options) => {
            let store = history_store(options)?;
            let listing = store
                .list(&cancellation)
                .map_err(|error| history_error(&error))?;
            write_json_stdout(&listing)?;
        }
        HistoryCommand::Show { scan_id, options } => {
            let store = history_store(options)?;
            let entry = store
                .show(&scan_id, &cancellation)
                .map_err(|error| history_error(&error))?;
            write_json_stdout(&entry)?;
        }
        HistoryCommand::Delete { scan_id, options } => {
            let store = history_store(options)?;
            store
                .delete(&scan_id)
                .map_err(|error| history_error(&error))?;
            write_json_stdout(&serde_json::json!({"deleted": scan_id}))?;
        }
    }
    Ok(0)
}

fn run_ai(command: AiCommand) -> Result<u8, (u8, String)> {
    match command {
        AiCommand::Providers => {
            write_json_stdout(&provider_descriptors())?;
            Ok(0)
        }
        AiCommand::Preview(arguments) => run_ai_preview(&arguments),
        AiCommand::Validate(arguments) => run_ai_validate(arguments),
        AiCommand::Cache {
            command: AiCacheCommand::Clear(options),
        } => {
            let cancellation = CancellationToken::new();
            install_cancellation(&cancellation)?;
            let cache = AiCache::open(options.cache_dir.unwrap_or_else(default_ai_cache_directory))
                .map_err(ai_error)?;
            let removed = cache.clear(&cancellation).map_err(ai_error)?;
            write_json_stdout(&serde_json::json!({"removed": removed}))?;
            eprintln!("secure: deleted {removed} local AI cache entries");
            Ok(0)
        }
    }
}

fn run_ai_preview(arguments: &AiPreviewArgs) -> Result<u8, (u8, String)> {
    let report = read_report(&arguments.report)?;
    let configuration = ai_configuration(&arguments.config, &arguments.provider)?;
    let finding_ids = selected_ai_findings(
        &report,
        arguments.finding_id.as_deref(),
        arguments.all,
        arguments.max_findings,
        &configuration,
    )?;
    let previews = finding_ids
        .iter()
        .map(|finding_id| preview_finding(&report, finding_id, &configuration).map_err(ai_error))
        .collect::<Result<Vec<_>, _>>()?;
    write_json_stdout(&previews)?;
    eprintln!(
        "secure: previewed {} redacted AI request(s); validation requires every exact consent fingerprint",
        previews.len()
    );
    Ok(0)
}

fn run_ai_validate(arguments: AiValidateArgs) -> Result<u8, (u8, String)> {
    let report = read_report(&arguments.report)?;
    let configuration = ai_configuration(&arguments.config, &arguments.provider)?;
    let finding_ids = selected_ai_findings(
        &report,
        arguments.finding_id.as_deref(),
        arguments.all,
        arguments.max_findings,
        &configuration,
    )?;
    let previews = finding_ids
        .iter()
        .map(|finding_id| preview_finding(&report, finding_id, &configuration).map_err(ai_error))
        .collect::<Result<Vec<_>, _>>()?;
    if previews.len() != arguments.consents.len()
        || previews
            .iter()
            .any(|preview| !arguments.consents.contains(&preview.consent_fingerprint))
    {
        return Err((
            EXIT_INVALID_INPUT,
            "validation refused: supply each exact consent fingerprint from the current preview"
                .into(),
        ));
    }
    let recorded = read_recorded_response(&configuration)?;
    let provider = configured_provider(&configuration, recorded).map_err(ai_error)?;
    let cancellation = CancellationToken::new();
    install_cancellation(&cancellation)?;
    let cache = if arguments.no_cache {
        None
    } else {
        Some(
            AiCache::open(
                arguments
                    .cache_dir
                    .unwrap_or_else(default_ai_cache_directory),
            )
            .map_err(ai_error)?,
        )
    };
    let mut assessments = Vec::with_capacity(previews.len());
    for preview in &previews {
        eprintln!(
            "secure: validating {} with provider {} and model {}",
            preview.finding_id, preview.provider, preview.model
        );
        let assessment = validate_finding_with_ai(
            &report,
            preview,
            &preview.consent_fingerprint,
            &configuration,
            provider.as_ref(),
            cache.as_ref(),
            &cancellation,
        )
        .map_err(ai_error)?;
        assessments.push(assessment);
    }
    let document = validation_document(&report, assessments).map_err(ai_error)?;
    write_ai_document(&document, arguments.output.as_ref(), &cancellation)?;
    eprintln!(
        "secure: completed {} separate AI assessment(s); deterministic findings were unchanged",
        document.assessments.len()
    );
    Ok(0)
}

fn ai_configuration(path: &Path, provider: &str) -> Result<AiProjectConfiguration, (u8, String)> {
    let configuration = read_ai_configuration(path).map_err(ai_error)?;
    if configuration.provider != provider {
        return Err((
            EXIT_INVALID_INPUT,
            "provider argument does not match explicit project configuration".into(),
        ));
    }
    Ok(configuration)
}

fn selected_ai_findings(
    report: &ScanReport,
    finding_id: Option<&str>,
    all: bool,
    requested_limit: usize,
    configuration: &AiProjectConfiguration,
) -> Result<Vec<String>, (u8, String)> {
    if requested_limit == 0 || requested_limit > configuration.limits.max_findings {
        return Err((
            EXIT_INVALID_INPUT,
            "max-findings must be positive and within the configured project limit".into(),
        ));
    }
    if all {
        let findings = report
            .findings
            .iter()
            .take(requested_limit)
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>();
        if findings.is_empty() {
            return Err((
                EXIT_INVALID_INPUT,
                "report has no findings to validate".into(),
            ));
        }
        Ok(findings)
    } else {
        finding_id.map(|id| vec![id.to_owned()]).ok_or_else(|| {
            (
                EXIT_INVALID_INPUT,
                "provide one finding ID or select --all".into(),
            )
        })
    }
}

fn read_recorded_response(
    configuration: &AiProjectConfiguration,
) -> Result<Option<serde_json::Value>, (u8, String)> {
    let Some(path) = configuration.recorded_response.as_ref() else {
        return Ok(None);
    };
    if configuration.provider == "openai-responses" {
        return Err((
            EXIT_INVALID_INPUT,
            "remote providers cannot use a recorded response file".into(),
        ));
    }
    let bytes = read_bounded_json(path, "recorded response")?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| (EXIT_INVALID_INPUT, "recorded response is malformed".into()))
}

fn write_ai_document(
    document: &AiValidationDocument,
    output: Option<&PathBuf>,
    cancellation: &CancellationToken,
) -> Result<(), (u8, String)> {
    if let Some(output) = output {
        write_json_artifact(document, output, cancellation)
            .map_err(|error| export_error(&error, "AI validation document"))
    } else {
        write_json_stdout(document)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn ai_error(error: AiError) -> (u8, String) {
    match error {
        AiError::Cancelled => (EXIT_CANCELLED, error.to_string()),
        AiError::Timeout | AiError::Provider(_) | AiError::MalformedResponse => {
            (EXIT_INTERNAL_FAILURE, error.to_string())
        }
        AiError::Storage => (EXIT_INTERNAL_FAILURE, error.to_string()),
        AiError::Disabled | AiError::Invalid(_) | AiError::ConsentRequired => {
            (EXIT_INVALID_INPUT, error.to_string())
        }
    }
}

fn history_store(options: HistoryOptions) -> Result<HistoryStore, (u8, String)> {
    let directory = options
        .history_dir
        .unwrap_or_else(default_history_directory);
    HistoryStore::open(directory, options.retention)
        .map_err(|error| (EXIT_INVALID_INPUT, error.to_string()))
}

fn read_report(path: &PathBuf) -> Result<ScanReport, (u8, String)> {
    let bytes = read_bounded_json(path, "report")?;
    let report = serde_json::from_slice::<ScanReport>(&bytes).map_err(|_| {
        (
            EXIT_INVALID_INPUT,
            "report is not a compatible scan report".into(),
        )
    })?;
    require_schema(&report.schema_version)?;
    if !report.scan.complete {
        return Err((EXIT_INVALID_INPUT, "report is not complete".into()));
    }
    Ok(report)
}

fn read_baseline(path: &PathBuf) -> Result<Baseline, (u8, String)> {
    let bytes = read_bounded_json(path, "baseline")?;
    let baseline = serde_json::from_slice::<Baseline>(&bytes)
        .map_err(|_| (EXIT_INVALID_INPUT, "baseline is malformed".into()))?;
    validate_baseline(&baseline).map_err(|error| (EXIT_INVALID_INPUT, error.to_string()))?;
    Ok(baseline)
}

fn read_bounded_json(path: &PathBuf, kind: &str) -> Result<Vec<u8>, (u8, String)> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| (EXIT_INVALID_INPUT, format!("{kind} could not be read")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1024 * 1024
    {
        return Err((
            EXIT_INVALID_INPUT,
            format!("{kind} must be a regular file no larger than 64 MiB"),
        ));
    }
    fs::read(path).map_err(|_| (EXIT_INVALID_INPUT, format!("{kind} could not be read")))
}

fn write_json_stdout<T: serde::Serialize>(value: &T) -> Result<(), (u8, String)> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| (EXIT_INTERNAL_FAILURE, "JSON output failed".into()))?;
    write_stdout(&bytes).map_err(|message| (EXIT_INTERNAL_FAILURE, message))
}

fn parse_suppression(value: &str) -> Result<Suppression, (u8, String)> {
    let mut fields = value.splitn(4, ':');
    let rule_id = fields.next().unwrap_or_default();
    let path = fields.next().unwrap_or_default();
    let start_byte = fields.next().and_then(|field| field.parse::<u64>().ok());
    let reason = fields.next().unwrap_or_default();
    if rule_id.is_empty() || path.is_empty() || start_byte.is_none() || reason.is_empty() {
        return Err((
            EXIT_INVALID_INPUT,
            "suppression must be RULE_ID:RELATIVE_PATH:START_BYTE:REASON".into(),
        ));
    }
    Ok(Suppression {
        rule_id: rule_id.into(),
        path: path.into(),
        start_byte: start_byte.unwrap_or_default(),
        reason: reason.into(),
    })
}

fn print_schema(schema: &str) -> Result<u8, (u8, String)> {
    let document = match schema {
        SCHEMA_VERSION => SECURE_JSON_V1_SCHEMA,
        secure_engine::AI_SCHEMA_VERSION => SECURE_AI_ASSESSMENT_V1_SCHEMA,
        _ => {
            return Err((
                EXIT_UNSUPPORTED_SCHEMA,
                format!(
                    "unsupported schema '{schema}'; expected {SCHEMA_VERSION} or {}",
                    secure_engine::AI_SCHEMA_VERSION
                ),
            ));
        }
    };
    write_stdout(document.as_bytes()).map_err(|message| (EXIT_INTERNAL_FAILURE, message))?;
    Ok(0)
}

fn require_schema(schema: &str) -> Result<(), (u8, String)> {
    if schema == SCHEMA_VERSION {
        Ok(())
    } else {
        Err((
            EXIT_UNSUPPORTED_SCHEMA,
            format!("unsupported schema '{schema}'; expected {SCHEMA_VERSION}"),
        ))
    }
}

fn require_scan_format(format: &str) -> Result<ExportFormat, (u8, String)> {
    match format {
        SCHEMA_VERSION => Ok(ExportFormat::SecureJson),
        "sarif" | "sarif-2.1.0" => Ok(ExportFormat::Sarif),
        _ => Err((
            EXIT_UNSUPPORTED_SCHEMA,
            format!("unsupported scan format '{format}'; expected {SCHEMA_VERSION} or sarif"),
        )),
    }
}

fn print_progress(event: &ProgressEvent, quiet: bool, verbose: bool) {
    if quiet {
        return;
    }
    match event {
        ProgressEvent::Discovering => eprintln!("secure: discovering repository files"),
        ProgressEvent::DiscoveryProgress {
            entries_seen,
            candidate_files,
        } => {
            eprintln!("secure: discovery {entries_seen} entries, {candidate_files} matching files");
        }
        ProgressEvent::Inspecting {
            completed, total, ..
        } => {
            if verbose
                || *completed == 0
                || completed.saturating_add(1) == *total
                || completed % 250 == 0
            {
                eprintln!("secure: inventory {completed}/{total}");
            }
        }
        ProgressEvent::Parsing {
            completed,
            total,
            parser_mode,
            ..
        } => {
            if verbose
                || *completed == 0
                || completed.saturating_add(1) == *total
                || completed % 100 == 0
            {
                eprintln!("secure: parsing {completed}/{total} ({parser_mode})");
            }
        }
        ProgressEvent::Analyzing { facts } => {
            eprintln!("secure: building evidence graph from {facts} facts");
        }
        ProgressEvent::Finalizing => eprintln!("secure: finalizing deterministic report"),
        ProgressEvent::Complete { files_scanned } => {
            eprintln!("secure: complete ({files_scanned} files)");
        }
    }
}

fn scan_error(error: ScanError) -> (u8, String) {
    match error {
        ScanError::InvalidRepository(message) | ScanError::InvalidConfiguration(message) => {
            (EXIT_INVALID_INPUT, message)
        }
        ScanError::Cancelled => (EXIT_CANCELLED, "scan cancelled".into()),
        ScanError::Internal(message) => (EXIT_INTERNAL_FAILURE, message),
    }
}

fn install_cancellation(cancellation: &CancellationToken) -> Result<(), (u8, String)> {
    let signal_token = cancellation.clone();
    ctrlc::set_handler(move || signal_token.cancel()).map_err(|_| {
        (
            EXIT_INTERNAL_FAILURE,
            "cancellation handler could not be installed".into(),
        )
    })
}

fn export_error(error: &secure_engine::ExportError, artifact: &str) -> (u8, String) {
    match error {
        secure_engine::ExportError::Cancelled => (EXIT_CANCELLED, error.to_string()),
        secure_engine::ExportError::Serialization => (EXIT_INTERNAL_FAILURE, error.to_string()),
        secure_engine::ExportError::Write => (
            EXIT_INVALID_INPUT,
            format!("{artifact} could not be written atomically"),
        ),
    }
}

fn history_error(error: &secure_engine::HistoryError) -> (u8, String) {
    match error {
        secure_engine::HistoryError::Cancelled => (EXIT_CANCELLED, error.to_string()),
        secure_engine::HistoryError::Invalid(_) | secure_engine::HistoryError::NotFound => {
            (EXIT_INVALID_INPUT, error.to_string())
        }
        secure_engine::HistoryError::Storage => (EXIT_INTERNAL_FAILURE, error.to_string()),
    }
}

fn write_stdout(bytes: &[u8]) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.write_all(b"\n"))
        .map_err(|_| "machine output could not be written".into())
}
