//! Neutral parser, filesystem-identity, actor-boundary, and projection regressions.

use std::path::{Path, PathBuf};

use secure_engine::{
    CancellationToken, EvidenceDisposition, ExportError, ExportFormat, FilesystemIdentityState,
    SECURE_JSON_V1_SCHEMA, ScanReport, ScanRequest, compact_report, scan_repository,
    serialize_export_bounded, write_export_bounded,
};

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/evidence-calibration-reporting")
}

fn scan_fixture() -> Result<ScanReport, Box<dyn std::error::Error>> {
    let mut request = ScanRequest::new(fixture_path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

#[test]
fn valid_nested_spread_has_no_diagnostic_and_malformed_control_remains_diagnosed()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    assert!(report.parser_diagnostics.iter().all(|diagnostic| {
        diagnostic.location.path != "syntax-valid.js"
    }));
    assert!(report.parser_diagnostics.iter().any(|diagnostic| {
        diagnostic.location.path == "syntax-malformed.js"
            && matches!(diagnostic.code.as_str(), "syntax-error" | "missing-syntax")
    }));
    Ok(())
}

#[test]
fn neutral_matrix_is_repository_independent() {
    for prohibited in ["npm", "oidc", "patcheddependencies", "pacote", "github"] {
        for file in [
            "actor-boundaries.js",
            "filesystem-paths.js",
            "filesystem-workflows.js",
            "platform-abstentions.js",
            "syntax-valid.js",
            "syntax-malformed.js",
        ] {
            let source = std::fs::read_to_string(fixture_path().join(file)).expect("fixture");
            assert!(!source.to_ascii_lowercase().contains(prohibited));
        }
    }
}

#[test]
fn actor_authority_and_lower_privilege_paths_are_calibrated_differently()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    let environment = report.findings.iter().find(|finding| {
        finding.calibration.as_ref().is_some_and(|calibration| {
            calibration.reason.as_deref() == Some("actor-authority-equivalence")
        })
    });
    let environment = environment.expect("environment-controlled destination remains visible");
    assert_eq!(environment.confidence, "low");
    assert_eq!(
        environment.calibration.as_ref().map(|value| &value.disposition),
        Some(&EvidenceDisposition::ExplicitAbstention)
    );
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "SE1004"
            && finding.calibration.as_ref().is_some_and(|calibration| {
                calibration.disposition == EvidenceDisposition::SecurityPath
            })
    }));
    Ok(())
}

#[test]
fn filesystem_confinement_retains_lexical_and_canonical_identity_abstentions()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    let identities = report
        .abstentions
        .iter()
        .map(|abstention| abstention.calibration.filesystem_identity.clone())
        .collect::<Vec<_>>();
    assert!(identities.contains(&FilesystemIdentityState::LexicalPath));
    assert!(identities.contains(&FilesystemIdentityState::CanonicalTarget));
    assert!(report.abstentions.iter().all(|abstention| {
        abstention.reason == "filesystem-object-identity-unresolved"
            && abstention.calibration.disposition == EvidenceDisposition::ExplicitAbstention
            && abstention.calibration.security_control.time_binding
                == secure_engine::EvidenceResolution::Unresolved
    }));
    Ok(())
}

#[test]
fn compact_projection_is_schema_valid_deterministic_and_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    let full = scan_fixture()?;
    let mut first = full.clone();
    let mut second = full;
    compact_report(&mut first, 8 * 1024 * 1024)?;
    compact_report(&mut second, 8 * 1024 * 1024)?;
    assert_eq!(first, second);
    assert_eq!(first.projection.facts_scope, "evidence-neighborhood");
    assert!(first.projection.retained_facts < first.projection.total_facts);
    assert_eq!(first.graph.scope, "finding-evidence");
    assert!(first.graph.nodes.len() < first.graph.total_nodes);
    let schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&serde_json::to_value(&first)?));
    assert_eq!(
        serialize_export_bounded(&first, ExportFormat::SecureJson, 128),
        Err(ExportError::OutputBudgetExceeded { maximum_bytes: 128 })
    );
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("bounded.json");
    assert_eq!(
        write_export_bounded(
            &first,
            ExportFormat::SecureJson,
            &output,
            &CancellationToken::new(),
            128,
        ),
        Err(ExportError::OutputBudgetExceeded { maximum_bytes: 128 })
    );
    assert!(!output.exists());
    std::fs::write(&output, b"previous-complete-report")?;
    assert_eq!(
        write_export_bounded(
            &first,
            ExportFormat::SecureJson,
            &output,
            &CancellationToken::new(),
            128,
        ),
        Err(ExportError::OutputBudgetExceeded { maximum_bytes: 128 })
    );
    assert_eq!(std::fs::read(&output)?, b"previous-complete-report");
    Ok(())
}
