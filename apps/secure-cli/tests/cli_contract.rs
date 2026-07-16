//! Black-box tests for stable machine output and documented exit behavior.

use std::fs;
use std::process::Command;

use tempfile::tempdir;

fn secure() -> Command {
    Command::new(env!("CARGO_BIN_EXE_secure"))
}

#[test]
fn scan_output_is_valid_and_stdout_stays_empty_for_file_output()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let report_path = directory.path().join("report.json");
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/integration-project"
    );
    let output = secure()
        .args(["scan", fixture, "--format", "secure-json-v1", "--output"])
        .arg(&report_path)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let document: serde_json::Value = serde_json::from_slice(&fs::read(report_path)?)?;
    let schema: serde_json::Value = serde_json::from_str(secure_engine::SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&document));
    Ok(())
}

#[test]
fn doctor_and_schema_are_machine_readable() -> Result<(), Box<dyn std::error::Error>> {
    let doctor = secure()
        .args(["doctor", "--format", "secure-json-v1"])
        .output()?;
    assert!(doctor.status.success());
    let doctor_document: serde_json::Value = serde_json::from_slice(&doctor.stdout)?;
    let schema: serde_json::Value = serde_json::from_str(secure_engine::SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&doctor_document));

    let printed = secure()
        .args(["schema", "print", "secure-json-v1"])
        .output()?;
    assert!(printed.status.success());
    let printed_schema: serde_json::Value = serde_json::from_slice(&printed.stdout)?;
    assert_eq!(printed_schema, schema);
    Ok(())
}

#[test]
fn scan_stdout_contains_only_the_json_document() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/integration-project"
    );
    let output = secure()
        .args(["scan", fixture, "--format", "secure-json-v1"])
        .output()?;
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["document_type"], "scan-report");
    assert!(String::from_utf8_lossy(&output.stderr).contains("secure: complete"));
    Ok(())
}

#[test]
fn unsupported_schema_has_documented_exit_code() -> Result<(), Box<dyn std::error::Error>> {
    let output = secure()
        .args(["doctor", "--format", "secure-json-v2"])
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());

    let missing = secure()
        .args(["scan", "/path/that/does/not/exist"])
        .output()?;
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    Ok(())
}

#[test]
fn phase_one_controls_are_exposed_and_recorded_consistently()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/integration-project"
    );
    let output = secure()
        .args([
            "scan",
            fixture,
            "--include",
            "**/*.rs",
            "--exclude",
            "src/main.rs",
            "--include-hidden",
            "--include-generated",
            "--include-vendor",
            "--include-nested-repositories",
            "--max-files",
            "10",
            "--max-file-bytes",
            "100",
            "--max-total-bytes",
            "12345",
            "--max-depth",
            "5",
            "--max-errors",
            "7",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["configuration"]["include_patterns"][0], "**/*.rs");
    assert_eq!(
        report["configuration"]["exclude_patterns"][0],
        "src/main.rs"
    );
    assert_eq!(report["configuration"]["max_total_bytes"], 12345);
    assert_eq!(report["configuration"]["max_depth"], 5);
    assert_eq!(report["configuration"]["max_errors"], 7);
    assert_eq!(report["inventory"]["files_scanned"], 0);
    Ok(())
}

#[test]
fn malformed_phase_one_controls_use_invalid_input_exit_code()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/integration-project"
    );
    let malformed = secure()
        .args(["scan", fixture, "--include", "["])
        .output()?;
    assert_eq!(malformed.status.code(), Some(2));
    assert!(malformed.stdout.is_empty());

    let help = secure().args(["scan", "--help"]).output()?;
    assert!(help.status.success());
    let help_text = String::from_utf8(help.stdout)?;
    for flag in [
        "--include",
        "--exclude",
        "--include-generated",
        "--include-vendor",
        "--include-nested-repositories",
        "--max-total-bytes",
        "--max-depth",
        "--max-errors",
    ] {
        assert!(help_text.contains(flag), "missing {flag}");
    }
    Ok(())
}
