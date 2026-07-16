//! Standalone local consumer that models Secure Skill's validation boundary.

use std::env;
use std::fs;
use std::process::ExitCode;

use secure_engine::{SCHEMA_VERSION, ScanReport};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("mock consumer rejected report: {message}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let schema_path = arguments
        .next()
        .ok_or_else(|| "expected <schema.json> <report.json>".to_owned())?;
    let report_path = arguments
        .next()
        .ok_or_else(|| "expected <schema.json> <report.json>".to_owned())?;
    if arguments.next().is_some() {
        return Err("expected exactly two arguments".into());
    }

    let schema_bytes = fs::read(schema_path).map_err(|_| "schema could not be read".to_owned())?;
    let report_bytes = fs::read(report_path).map_err(|_| "report could not be read".to_owned())?;
    let schema: serde_json::Value =
        serde_json::from_slice(&schema_bytes).map_err(|_| "schema is not JSON".to_owned())?;
    let document: serde_json::Value =
        serde_json::from_slice(&report_bytes).map_err(|_| "report is not JSON".to_owned())?;
    if document
        .get("schema_version")
        .and_then(|value| value.as_str())
        != Some(SCHEMA_VERSION)
    {
        return Err("unsupported schema version".into());
    }
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| format!("schema could not be compiled: {error}"))?;
    if !validator.is_valid(&document) {
        return Err("JSON Schema validation failed".into());
    }

    let report: ScanReport =
        serde_json::from_value(document).map_err(|_| "scan report shape is invalid".to_owned())?;
    println!(
        "validated {} files, {} facts, {} parser diagnostics, {} capabilities, {} exclusions, and {} findings from {}",
        report
            .inventory
            .files_scanned
            .max(report.scan.files_scanned),
        report.facts.len(),
        report.parser_diagnostics.len(),
        report.capabilities.len(),
        report.exclusions.len(),
        report.findings.len(),
        report.repository.name
    );
    Ok(())
}
