#![allow(missing_docs)]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use secure_engine::{
    CacheControl, CancellationToken, DoctorCheck, DoctorReport, ENGINE_VERSION, ProgressEvent,
    SCHEMA_VERSION, SECURE_JSON_V1_SCHEMA, ScanError, ScanReport, ScanRequest, Suppression,
    explain_finding, rules, scan_repository,
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
    }
}

fn run_scan(arguments: ScanArgs) -> Result<u8, (u8, String)> {
    require_schema(&arguments.format)?;
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
    {
        return Err((
            EXIT_INVALID_INPUT,
            "resource limits must be greater than zero".into(),
        ));
    }

    let cancellation = CancellationToken::new();
    let signal_token = cancellation.clone();
    ctrlc::set_handler(move || signal_token.cancel()).map_err(|_| {
        (
            EXIT_INTERNAL_FAILURE,
            "cancellation handler could not be installed".into(),
        )
    })?;

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
    let report = scan_repository(&request, &cancellation, |event| print_progress(&event))
        .map_err(scan_error)?;
    let bytes = serde_json::to_vec_pretty(&report).map_err(|_| {
        (
            EXIT_INTERNAL_FAILURE,
            "complete report could not be serialized".into(),
        )
    })?;
    if cancellation.is_cancelled() {
        return Err((EXIT_CANCELLED, "scan cancelled".into()));
    }

    if let Some(output) = arguments.output {
        atomic_write(&output, &bytes).map_err(|message| (EXIT_INVALID_INPUT, message))?;
        eprintln!("secure: wrote complete report");
    } else {
        write_stdout(&bytes).map_err(|message| (EXIT_INTERNAL_FAILURE, message))?;
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
    let metadata = fs::metadata(&arguments.report)
        .map_err(|_| (EXIT_INVALID_INPUT, "report could not be read".into()))?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
        return Err((
            EXIT_INVALID_INPUT,
            "report must be a regular file no larger than 64 MiB".into(),
        ));
    }
    let bytes = fs::read(&arguments.report)
        .map_err(|_| (EXIT_INVALID_INPUT, "report could not be read".into()))?;
    let report = serde_json::from_slice::<ScanReport>(&bytes).map_err(|_| {
        (
            EXIT_INVALID_INPUT,
            "report is not a compatible scan report".into(),
        )
    })?;
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
    require_schema(schema)?;
    write_stdout(SECURE_JSON_V1_SCHEMA.as_bytes())
        .map_err(|message| (EXIT_INTERNAL_FAILURE, message))?;
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

fn print_progress(event: &ProgressEvent) {
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
            if *completed == 0 || completed.saturating_add(1) == *total || completed % 250 == 0 {
                eprintln!("secure: inventory {completed}/{total}");
            }
        }
        ProgressEvent::Parsing {
            completed,
            total,
            parser_mode,
            ..
        } => {
            if *completed == 0 || completed.saturating_add(1) == *total || completed % 100 == 0 {
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

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err("output parent is not a directory".into());
    }
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "output path must name a file".to_owned())?;
    let mut temporary_name = OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".secure-tmp-{}", std::process::id()));
    let temporary = parent.join(temporary_name);

    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    result.map_err(|_| "report could not be written atomically".into())
}

fn write_stdout(bytes: &[u8]) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.write_all(b"\n"))
        .map_err(|_| "machine output could not be written".into())
}
