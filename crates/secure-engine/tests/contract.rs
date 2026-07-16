//! Public schema and representative fixture compatibility tests.

use std::fs;
use std::path::PathBuf;

use secure_engine::{
    CancellationToken, SECURE_JSON_V1_SCHEMA, ScanReport, ScanRequest, scan_repository,
};

fn workspace_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

#[test]
fn committed_fixtures_enforce_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    let schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    let validator = jsonschema::validator_for(&schema)?;
    let valid: serde_json::Value = serde_json::from_slice(&fs::read(workspace_path(
        "fixtures/secure-json-v1/valid-report.json",
    ))?)?;
    let malformed: serde_json::Value = serde_json::from_slice(&fs::read(workspace_path(
        "fixtures/secure-json-v1/malformed-report.json",
    ))?)?;
    let incompatible: serde_json::Value = serde_json::from_slice(&fs::read(workspace_path(
        "fixtures/secure-json-v1/incompatible-report.json",
    ))?)?;
    let phase_one: serde_json::Value = serde_json::from_slice(&fs::read(workspace_path(
        "fixtures/secure-json-v1/phase1-report.json",
    ))?)?;
    assert!(validator.is_valid(&valid));
    assert!(validator.is_valid(&phase_one));
    assert!(!validator.is_valid(&malformed));
    assert!(!validator.is_valid(&incompatible));
    let legacy_report: ScanReport = serde_json::from_value(valid)?;
    assert_eq!(
        legacy_report.configuration.max_total_bytes,
        512 * 1024 * 1024
    );
    assert_eq!(legacy_report.repository.repository_kind, "directory");
    assert_eq!(legacy_report.inventory.files_scanned, 0);
    assert_eq!(legacy_report.files[0].origin, "project");
    assert!(!legacy_report.files[0].is_binary);
    Ok(())
}

#[test]
fn real_inventory_validates_and_honors_ignore_files() -> Result<(), Box<dyn std::error::Error>> {
    let repository = workspace_path("fixtures/integration-project");
    let report = scan_repository(
        &ScanRequest::new(repository),
        &CancellationToken::new(),
        |_| {},
    )?;
    let document = serde_json::to_value(&report)?;
    let schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    let validator = jsonschema::validator_for(&schema)?;
    assert!(validator.is_valid(&document));
    assert!(
        report
            .files
            .iter()
            .all(|file| file.path != "ignored-secret.txt")
    );
    let Some(axum) = report.frameworks.iter().find(|item| item.name == "Axum") else {
        return Err("expected Axum framework evidence".into());
    };
    assert_eq!(axum.evidence.path, "Cargo.toml");
    assert!(axum.evidence.span.end_byte > axum.evidence.span.start_byte);
    assert!(axum.evidence.span.start_line >= 1);
    assert!(axum.evidence.span.start_column >= 1);
    assert!(report.findings.is_empty());
    Ok(())
}

#[test]
fn repeated_json_differs_only_in_documented_volatile_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let request = ScanRequest::new(workspace_path("fixtures/integration-project"));
    let first = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let second = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let mut first_json = serde_json::to_value(first)?;
    let mut second_json = serde_json::to_value(second)?;
    for report in [&mut first_json, &mut second_json] {
        let Some(scan) = report
            .get_mut("scan")
            .and_then(serde_json::Value::as_object_mut)
        else {
            return Err("scan metadata was not an object".into());
        };
        scan.remove("started_at");
        scan.remove("finished_at");
        scan.remove("duration_ms");
    }
    assert_eq!(first_json, second_json);
    Ok(())
}
