//! Neutral parser, filesystem-identity, actor-boundary, and projection regressions.

use std::path::{Path, PathBuf};

use secure_engine::{
    CancellationToken, EvidenceDisposition, EvidenceResolution, ExportError, ExportFormat,
    FilesystemIdentityState, SECURE_JSON_V1_SCHEMA, ScanReport, ScanRequest, compact_report,
    scan_repository, serialize_export_bounded, write_export_bounded,
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
    assert!(
        report
            .parser_diagnostics
            .iter()
            .all(|diagnostic| { diagnostic.location.path != "syntax-valid.js" })
    );
    assert!(report.parser_diagnostics.iter().any(|diagnostic| {
        diagnostic.location.path == "syntax-malformed.js"
            && matches!(diagnostic.code.as_str(), "syntax-error" | "missing-syntax")
    }));
    assert!(report.facts.iter().any(|fact| {
        fact.location.path == "syntax-valid.js"
            && fact.kind == "module-export"
            && fact.name.as_deref() == Some("declarationBoundary")
    }));
    assert!(report.facts.iter().any(|fact| {
        fact.location.path == "syntax-valid.js"
            && fact.kind == "call"
            && fact.name.as_deref() == Some("describe")
            && fact.location.span.start_line == 13
    }));
    Ok(())
}

#[test]
fn neutral_matrix_is_repository_independent() -> Result<(), Box<dyn std::error::Error>> {
    for prohibited in ["npm", "oidc", "patcheddependencies", "pacote", "github"] {
        for file in [
            "actor-boundaries.js",
            "filesystem-paths.js",
            "filesystem-workflows.js",
            "platform-abstentions.js",
            "syntax-valid.js",
            "syntax-malformed.js",
            "causal-identity.js",
            "calibration-prerequisites.js",
            "manifest-authority-lifecycle-policy.js",
        ] {
            let source = std::fs::read_to_string(fixture_path().join(file))?;
            assert!(!source.to_ascii_lowercase().contains(prohibited));
        }
    }
    Ok(())
}

#[test]
fn actor_authority_and_lower_privilege_paths_are_calibrated_differently()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    let environment = report.abstentions.iter().find(|abstention| {
        abstention.calibration.reason.as_deref() == Some("actor-authority-equivalence")
    });
    let environment = environment.ok_or("environment-controlled destination is missing")?;
    assert_eq!(
        environment.calibration.disposition,
        EvidenceDisposition::ExplicitAbstention
    );
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "SE1004"
            && finding.calibration.as_ref().is_some_and(|calibration| {
                calibration.disposition == EvidenceDisposition::BoundedHardening
                    && calibration.actor_identity == EvidenceResolution::Proven
                    && calibration.trust_boundary == EvidenceResolution::Proven
            })
    }));
    Ok(())
}

#[test]
fn calibration_promotes_only_explicit_actor_boundary_and_impact_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    let in_file = |line: u32| {
        report.findings.iter().find(|finding| {
            finding.sink.as_ref().is_some_and(|sink| {
                sink.path == "calibration-prerequisites.js" && sink.span.start_line == line
            })
        })
    };

    for line in [4, 8] {
        let calibration = in_file(line)
            .and_then(|finding| finding.calibration.as_ref())
            .ok_or("expected lower-privilege integrity or availability path")?;
        assert_eq!(calibration.attacker_control, EvidenceResolution::Proven);
        assert_eq!(calibration.actor_identity, EvidenceResolution::Proven);
        assert_eq!(calibration.trust_boundary, EvidenceResolution::Proven);
        assert_eq!(calibration.observable_impact, EvidenceResolution::Proven);
        assert_eq!(calibration.disposition, EvidenceDisposition::SecurityPath);
    }

    let read = in_file(12)
        .and_then(|finding| finding.calibration.as_ref())
        .ok_or("expected filesystem read path")?;
    assert_eq!(read.actor_identity, EvidenceResolution::Proven);
    assert_eq!(read.trust_boundary, EvidenceResolution::Proven);
    assert_eq!(read.observable_impact, EvidenceResolution::Unresolved);
    assert_eq!(read.disposition, EvidenceDisposition::BoundedHardening);

    let environment = report
        .abstentions
        .iter()
        .find(|abstention| {
            abstention.sink.path == "calibration-prerequisites.js"
                && abstention.sink.span.start_line == 16
        })
        .map(|abstention| &abstention.calibration)
        .ok_or("expected environment-owned filesystem path")?;
    assert_eq!(
        environment.actor_identity,
        EvidenceResolution::EquivalentCapability
    );
    assert_eq!(environment.trust_boundary, EvidenceResolution::Unresolved);
    assert_eq!(
        environment.disposition,
        EvidenceDisposition::ExplicitAbstention
    );
    assert!(in_file(20).is_none());
    Ok(())
}

#[test]
fn findings_and_abstentions_have_structurally_disjoint_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    assert!(report.findings.iter().all(|finding| {
        finding.calibration.as_ref().is_none_or(|calibration| {
            calibration.disposition != EvidenceDisposition::ExplicitAbstention
        })
    }));
    assert!(report.abstentions.iter().all(|abstention| {
        abstention.calibration.disposition == EvidenceDisposition::ExplicitAbstention
    }));
    Ok(())
}

#[test]
fn selector_control_does_not_become_direct_value_taint() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    let filesystem_sinks = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1003")
        .filter_map(|finding| finding.sink.as_ref())
        .filter(|sink| sink.path == "causal-identity.js")
        .map(|sink| sink.span.start_line)
        .collect::<Vec<_>>();
    assert!(!filesystem_sinks.contains(&10));
    assert!(filesystem_sinks.contains(&15));
    assert!(filesystem_sinks.contains(&28));
    assert!(!filesystem_sinks.contains(&39));

    let returned_field = report
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "SE1003"
                && finding.sink.as_ref().is_some_and(|sink| {
                    sink.path == "causal-identity.js" && sink.span.start_line == 28
                })
        })
        .ok_or("returned tainted field path is missing")?;
    assert!(returned_field.source.as_ref().is_some_and(|source| {
        source.path == "causal-identity.js" && source.span.start_line == 24
    }));
    Ok(())
}

#[test]
fn policy_composition_gaps_are_bounded_and_controls_remain_clean()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    let policy_lines = report
        .abstentions
        .iter()
        .filter(|abstention| abstention.rule_id == "SE1013")
        .filter(|abstention| abstention.sink.path == "manifest-authority-lifecycle-policy.js")
        .map(|abstention| abstention.sink.span.start_line)
        .collect::<Vec<_>>();
    assert!(policy_lines.contains(&8));
    assert!(policy_lines.contains(&25));
    assert!(policy_lines.contains(&45));
    assert!(!policy_lines.contains(&18));
    assert!(!policy_lines.contains(&35));
    assert!(!policy_lines.contains(&56));
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
    assert!(
        report
            .abstentions
            .iter()
            .filter(|abstention| {
                abstention.rule_id == "SE1003"
                    && abstention.reason == "filesystem-object-identity-unresolved"
            })
            .all(|abstention| {
                abstention.calibration.disposition == EvidenceDisposition::ExplicitAbstention
                    && abstention.calibration.security_control.time_binding
                        == secure_engine::EvidenceResolution::Unresolved
            })
    );
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
