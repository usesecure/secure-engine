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
        "--no-cache",
        "--clear-cache",
        "--cache-dir",
        "--max-cache-bytes",
        "--max-parser-diagnostics",
        "--max-facts-per-file",
        "--max-total-facts",
        "--max-graph-nodes",
        "--max-graph-edges",
        "--max-interprocedural-depth",
        "--max-findings",
        "--suppress",
    ] {
        assert!(help_text.contains(flag), "missing {flag}");
    }
    Ok(())
}

#[test]
fn phase_three_rule_catalog_is_stable_machine_output() -> Result<(), Box<dyn std::error::Error>> {
    let output = secure().args(["rules", "list"]).output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let catalog: Vec<secure_engine::RuleMetadata> = serde_json::from_slice(&output.stdout)?;
    assert_eq!(catalog.len(), 7);
    assert_eq!(
        catalog.first().map(|rule| rule.rule_id.as_str()),
        Some("SE1001")
    );
    assert_eq!(
        catalog.last().map(|rule| rule.rule_id.as_str()),
        Some("SE1007")
    );
    Ok(())
}

#[test]
fn policy_exit_and_finding_explanation_use_the_shared_report()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let report_path = temporary.path().join("phase3.json");
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/phase3-rules");
    let scan = secure()
        .args(["scan", fixture, "--no-cache", "--output"])
        .arg(&report_path)
        .output()?;
    assert_eq!(scan.status.code(), Some(1));
    assert!(scan.stdout.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&fs::read(&report_path)?)?;
    let finding_id = report["findings"][0]["finding_id"]
        .as_str()
        .ok_or("missing finding ID")?;
    let explained = secure()
        .args(["explain", finding_id, "--report"])
        .arg(&report_path)
        .output()?;
    assert!(explained.status.success());
    let finding: serde_json::Value = serde_json::from_slice(&explained.stdout)?;
    assert_eq!(finding["finding_id"], finding_id);
    assert!(
        finding["evidence_path"]
            .as_array()
            .is_some_and(|path| path.len() >= 2)
    );

    let missing = secure()
        .args(["explain", "fd_000000000000000000000000", "--report"])
        .arg(&report_path)
        .output()?;
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    Ok(())
}

#[test]
fn phase_two_cli_reports_cold_and_warm_cache_results_without_path_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let cache = temporary.path().join("cache");
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/phase2-js-ts");
    let cold = secure()
        .args(["scan", fixture, "--cache-dir"])
        .arg(&cache)
        .args(["--clear-cache", "--format", "secure-json-v1"])
        .output()?;
    assert_eq!(cold.status.code(), Some(1));
    let cold_report: serde_json::Value = serde_json::from_slice(&cold.stdout)?;
    assert_eq!(cold_report["parsing"]["cache_hits"], 0);
    assert_eq!(cold_report["parsing"]["cache_misses"], 9);
    assert!(
        cold_report["facts"]
            .as_array()
            .is_some_and(|facts| !facts.is_empty())
    );
    assert!(String::from_utf8_lossy(&cold.stderr).contains("secure: parsing"));

    let warm = secure()
        .args(["scan", fixture, "--cache-dir"])
        .arg(&cache)
        .output()?;
    assert_eq!(warm.status.code(), Some(1));
    let warm_report: serde_json::Value = serde_json::from_slice(&warm.stdout)?;
    assert_eq!(warm_report["parsing"]["cache_hits"], 9);
    assert_eq!(warm_report["parsing"]["cache_misses"], 0);
    assert_eq!(cold_report["facts"], warm_report["facts"]);
    assert_eq!(
        cold_report["report_fingerprint"],
        warm_report["report_fingerprint"]
    );
    assert!(!String::from_utf8(cold.stdout)?.contains(&cache.to_string_lossy().to_string()));

    let invalid = secure()
        .args(["scan", fixture, "--max-total-facts", "0"])
        .output()?;
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    Ok(())
}
