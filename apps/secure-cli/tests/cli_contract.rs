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
fn phase_five_languages_share_json_and_sarif_cli_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/phase5-multilang"
    );
    let json = secure()
        .args([
            "scan",
            fixture,
            "--format",
            "secure-json-v1",
            "--no-cache",
            "--quiet",
        ])
        .output()?;
    assert_eq!(json.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout)?;
    let schema: serde_json::Value = serde_json::from_str(secure_engine::SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&report));
    for mode in ["rust", "python", "go"] {
        assert!(
            report["parser_coverage"]
                .as_array()
                .is_some_and(|coverage| {
                    coverage.iter().any(|item| item["parser_mode"] == mode)
                })
        );
    }

    let sarif = secure()
        .args([
            "scan",
            fixture,
            "--format",
            "sarif",
            "--no-cache",
            "--quiet",
        ])
        .output()?;
    assert_eq!(sarif.status.code(), Some(1));
    let sarif: serde_json::Value = serde_json::from_slice(&sarif.stdout)?;
    assert_eq!(sarif["version"], "2.1.0");
    assert!(
        sarif["runs"][0]["results"]
            .as_array()
            .is_some_and(|results| !results.is_empty())
    );
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
    assert_eq!(catalog.len(), 10);
    assert!(catalog.iter().take(7).all(|rule| {
        rule.taxonomy.is_some() && rule.primary_cwe.is_some() && rule.taxonomy_provenance.is_some()
    }));
    assert!(catalog.iter().skip(7).all(|rule| {
        rule.taxonomy.is_none() && rule.primary_cwe.is_none() && rule.taxonomy_provenance.is_none()
    }));
    assert_eq!(
        catalog.first().map(|rule| rule.rule_id.as_str()),
        Some("SE1001")
    );
    assert_eq!(
        catalog.last().map(|rule| rule.rule_id.as_str()),
        Some("SE1010")
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
    let finding_id = report["findings"]
        .as_array()
        .and_then(|findings| {
            findings
                .iter()
                .find(|finding| finding["taxonomy"].is_object())
        })
        .and_then(|finding| finding["finding_id"].as_str())
        .ok_or("missing finding ID")?;
    let explained = secure()
        .args(["explain", finding_id, "--report"])
        .arg(&report_path)
        .output()?;
    assert!(explained.status.success());
    let finding: serde_json::Value = serde_json::from_slice(&explained.stdout)?;
    assert_eq!(finding["finding_id"], finding_id);
    assert_eq!(finding["taxonomy"]["taxonomy_version"], "1.0.0");
    assert!(
        finding["primary_cwe"]["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("CWE-"))
    );
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

#[test]
fn sarif_quiet_verbose_and_no_color_preserve_machine_output()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/phase3-rules");
    let sarif = secure()
        .args([
            "scan",
            fixture,
            "--no-cache",
            "--format",
            "sarif",
            "--quiet",
            "--no-color",
        ])
        .output()?;
    assert_eq!(sarif.status.code(), Some(1));
    assert!(sarif.stderr.is_empty());
    let document: serde_json::Value = serde_json::from_slice(&sarif.stdout)?;
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/sarif-schema-2.1.0.json"))?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&document));
    assert_eq!(document["version"], "2.1.0");

    let verbose = secure()
        .args(["scan", fixture, "--no-cache", "--verbose"])
        .output()?;
    assert_eq!(verbose.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&verbose.stderr).contains("secure: parsing"));
    serde_json::from_slice::<serde_json::Value>(&verbose.stdout)?;
    Ok(())
}

#[test]
fn baseline_cli_creates_compares_and_rejects_malformed_input()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let report_path = temporary.path().join("report.json");
    let clean_report_path = temporary.path().join("clean.json");
    let baseline_path = temporary.path().join("baseline.json");
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/phase3-rules");
    assert_eq!(
        secure()
            .args(["scan", fixture, "--no-cache", "--quiet", "--output"])
            .arg(&report_path)
            .status()?
            .code(),
        Some(1)
    );
    let mut clean_report: serde_json::Value = serde_json::from_slice(&fs::read(&report_path)?)?;
    clean_report["findings"] = serde_json::json!([]);
    clean_report["report_fingerprint"] = serde_json::json!("c".repeat(64));
    fs::write(
        &clean_report_path,
        serde_json::to_vec_pretty(&clean_report)?,
    )?;
    let created = secure()
        .args(["baseline", "create"])
        .arg(&report_path)
        .arg("--output")
        .arg(&baseline_path)
        .output()?;
    assert!(created.status.success());
    let baseline: serde_json::Value = serde_json::from_slice(&fs::read(&baseline_path)?)?;
    assert_eq!(baseline["format"], "secure-baseline-v1");
    assert!(baseline.get("saved_at").is_none());
    let baseline_count = baseline["findings"]
        .as_array()
        .map(Vec::len)
        .ok_or("baseline findings missing")?;

    let unchanged = secure()
        .args(["baseline", "compare"])
        .arg(&baseline_path)
        .arg(&report_path)
        .output()?;
    assert!(unchanged.status.success());
    let comparison: serde_json::Value = serde_json::from_slice(&unchanged.stdout)?;
    assert_eq!(comparison["new"].as_array().map(Vec::len), Some(0));

    let changed = secure()
        .args(["baseline", "compare"])
        .arg(&baseline_path)
        .arg(&clean_report_path)
        .output()?;
    assert_eq!(changed.status.code(), Some(1));
    let comparison: serde_json::Value = serde_json::from_slice(&changed.stdout)?;
    assert_eq!(
        comparison["resolved"].as_array().map(Vec::len),
        Some(baseline_count)
    );

    fs::write(&baseline_path, "{}")?;
    let malformed = secure()
        .args(["baseline", "compare"])
        .arg(&baseline_path)
        .arg(&report_path)
        .output()?;
    assert_eq!(malformed.status.code(), Some(2));
    assert!(malformed.stdout.is_empty());
    Ok(())
}

#[test]
fn history_cli_lists_reopens_and_deletes_private_completed_scans()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let history = temporary.path().join("history");
    let report_path = temporary.path().join("report.json");
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/integration-project"
    );
    let scan = secure()
        .args([
            "scan",
            fixture,
            "--quiet",
            "--save-history",
            "--history-dir",
        ])
        .arg(&history)
        .arg("--output")
        .arg(&report_path)
        .output()?;
    assert!(scan.status.success());
    assert!(scan.stderr.is_empty());

    let listed = secure()
        .args(["history", "list", "--history-dir"])
        .arg(&history)
        .output()?;
    assert!(listed.status.success());
    let listing: serde_json::Value = serde_json::from_slice(&listed.stdout)?;
    let scan_id = listing["scans"][0]["scan_id"]
        .as_str()
        .ok_or("missing scan ID")?;
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(fixture));

    let shown = secure()
        .args(["history", "show", scan_id, "--history-dir"])
        .arg(&history)
        .output()?;
    assert!(shown.status.success());
    let entry: serde_json::Value = serde_json::from_slice(&shown.stdout)?;
    assert_eq!(entry["summary"]["status"], "complete");
    assert!(!String::from_utf8_lossy(&shown.stdout).contains(fixture));

    let deleted = secure()
        .args(["history", "delete", scan_id, "--history-dir"])
        .arg(&history)
        .output()?;
    assert!(deleted.status.success());
    let missing = secure()
        .args(["history", "show", scan_id, "--history-dir"])
        .arg(&history)
        .output()?;
    assert_eq!(missing.status.code(), Some(2));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn ai_cli_previews_requires_exact_consent_and_uses_only_recorded_data()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let report_path = temporary.path().join("report.json");
    let config_path = temporary.path().join("secure-ai.json");
    let assessment_path = temporary.path().join("assessment.json");
    let cache_path = temporary.path().join("ai-cache");
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/phase3-rules");
    let response = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/phase6-ai/supported.json"
    );
    assert_eq!(
        secure()
            .args(["scan", fixture, "--no-cache", "--quiet", "--output"])
            .arg(&report_path)
            .status()?
            .code(),
        Some(1)
    );
    let report_before = fs::read(&report_path)?;
    let report: serde_json::Value = serde_json::from_slice(&report_before)?;
    let finding_id = report["findings"][0]["finding_id"]
        .as_str()
        .ok_or("missing finding ID")?;
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "format": "secure-ai-config-v1",
            "enabled": true,
            "provider": "recorded",
            "model": "fixture-model",
            "endpoint": null,
            "api_key_env": null,
            "recorded_response": response,
            "limits": {
                "max_findings": 10,
                "max_payload_bytes": 32768,
                "max_output_tokens": 1200,
                "timeout_seconds": 30,
                "max_evidence_locations": 24,
                "max_string_chars": 4000,
                "max_cost_microunits": null
            }
        }))?,
    )?;

    let providers = secure().args(["ai", "providers"]).output()?;
    assert!(providers.status.success());
    let descriptors: serde_json::Value = serde_json::from_slice(&providers.stdout)?;
    assert!(
        descriptors
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["id"] == "openai-responses"))
    );

    let previewed = secure()
        .args(["ai", "preview", finding_id, "--report"])
        .arg(&report_path)
        .args(["--provider", "recorded", "--config"])
        .arg(&config_path)
        .output()?;
    assert!(
        previewed.status.success(),
        "{}",
        String::from_utf8_lossy(&previewed.stderr)
    );
    let previews: serde_json::Value = serde_json::from_slice(&previewed.stdout)?;
    let consent = previews[0]["consent_fingerprint"]
        .as_str()
        .ok_or("missing consent fingerprint")?;
    assert_eq!(previews[0]["network_request"], false);
    assert!(String::from_utf8_lossy(&previewed.stderr).contains("exact consent"));

    let refused = secure()
        .args(["ai", "validate", finding_id, "--report"])
        .arg(&report_path)
        .args(["--provider", "recorded", "--config"])
        .arg(&config_path)
        .output()?;
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());

    let validated = secure()
        .args(["ai", "validate", finding_id, "--report"])
        .arg(&report_path)
        .args(["--provider", "recorded", "--config"])
        .arg(&config_path)
        .args(["--consent", consent, "--cache-dir"])
        .arg(&cache_path)
        .arg("--output")
        .arg(&assessment_path)
        .output()?;
    assert!(
        validated.status.success(),
        "{}",
        String::from_utf8_lossy(&validated.stderr)
    );
    assert!(validated.stdout.is_empty());
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&assessment_path)?)?;
    assert_eq!(document["format"], "secure-ai-validation-v1");
    assert_eq!(
        document["assessments"][0]["assessment"]["status"],
        "supported"
    );
    assert_eq!(fs::read(&report_path)?, report_before);

    let cleared = secure()
        .args(["ai", "cache", "clear", "--cache-dir"])
        .arg(&cache_path)
        .output()?;
    assert!(cleared.status.success());
    Ok(())
}
