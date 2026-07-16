#![allow(missing_docs)]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use secure_engine::{
    CancellationToken, DoctorCheck, DoctorReport, ENGINE_VERSION, ProgressEvent, SCHEMA_VERSION,
    SECURE_JSON_V1_SCHEMA, ScanError, ScanRequest, scan_repository,
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
    Scan(ScanArgs),
    /// Check the local engine contract and runtime.
    Doctor(FormatArgs),
    /// Inspect public integration schemas.
    Schema {
        #[command(subcommand)]
        command: SchemaCommand,
    },
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Local repository directory.
    repository: PathBuf,
    /// Machine format. Phase 0 supports secure-json-v1.
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
    /// Do not honor .gitignore and related repository ignore files.
    #[arg(long)]
    no_ignore: bool,
}

#[derive(Debug, Args)]
struct FormatArgs {
    /// Machine format. Phase 0 supports secure-json-v1.
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
        Command::Scan(arguments) => run_scan(arguments),
        Command::Doctor(arguments) => run_doctor(&arguments.format),
        Command::Schema {
            command: SchemaCommand::Print { schema },
        } => print_schema(&schema),
    }
}

fn run_scan(arguments: ScanArgs) -> Result<u8, (u8, String)> {
    require_schema(&arguments.format)?;
    if arguments.max_files == 0 || arguments.max_file_bytes == 0 {
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
    request.configuration.respect_ignore_files = !arguments.no_ignore;
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
                detail: "Phase 0 provides inventory evidence; vulnerability rules are not enabled"
                    .into(),
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
        ProgressEvent::Inspecting {
            completed, total, ..
        } => {
            if *completed == 0 || completed.saturating_add(1) == *total || completed % 250 == 0 {
                eprintln!("secure: inventory {completed}/{total}");
            }
        }
        ProgressEvent::Finalizing => eprintln!("secure: finalizing deterministic report"),
        ProgressEvent::Complete { files_scanned } => {
            eprintln!("secure: complete ({files_scanned} files)");
        }
    }
}

fn scan_error(error: ScanError) -> (u8, String) {
    match error {
        ScanError::InvalidRepository(message) => (EXIT_INVALID_INPUT, message),
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
