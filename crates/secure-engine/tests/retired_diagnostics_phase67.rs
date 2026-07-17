//! Phase 6.7 regression coverage for the explicitly disclosed retired diagnostics.

use std::fs;
use std::path::{Path, PathBuf};

use secure_engine::{
    CancellationToken, EVIDENCE_CONTRACT_VERSION, EVIDENCE_SEMANTICS_VERSION,
    EvidenceContractRoleV2, ScanRequest, scan_repository,
};
use sha2::{Digest, Sha256};

fn workspace_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn sha256(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn expected_location_matches(
    location: &secure_engine::SourceLocation,
    expected: &serde_json::Value,
) -> bool {
    let direct = expected["path"].as_str().zip(expected["line"].as_u64());
    let alternatives = expected["alternatives"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|alternative| {
            alternative["path"]
                .as_str()
                .zip(alternative["line"].as_u64())
        });
    direct
        .into_iter()
        .chain(alternatives)
        .any(|(path, line)| location.path == path && u64::from(location.span.start_line) == line)
}

#[test]
fn retired_manifest_is_frozen_and_declares_balanced_development_only_input()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest_path =
        workspace_path("fixtures/phase67-retired-diagnostics/regression-manifest-v1.json");
    assert_eq!(
        sha256(&manifest_path)?,
        "68269560554cb9f3c1d837912321e2f34a1cc1bef81602aec9994efa726a7a17"
    );
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(manifest_path)?)?;
    let cases = manifest["cases"].as_array().ok_or("cases missing")?;
    assert_eq!(cases.len(), 56);
    assert_eq!(
        cases
            .iter()
            .filter(|case| case["kind"] == "vulnerable")
            .count(),
        28
    );
    assert_eq!(
        cases
            .iter()
            .filter(|case| case["kind"] == "safe_control")
            .count(),
        28
    );
    assert_eq!(manifest["unbiased_holdout_use_prohibited"], true);
    Ok(())
}

#[test]
fn all_retired_vulnerable_cases_have_exact_contract_evidence_and_controls_are_clean()
-> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_path("fixtures/phase67-retired-diagnostics");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("regression-manifest-v1.json"))?)?;
    let cases = manifest["cases"].as_array().ok_or("cases missing")?;
    let mut vulnerable = 0_usize;
    let mut controls = 0_usize;

    for case in cases {
        let case_id = case["case_id"].as_str().ok_or("case id missing")?;
        let mut request = ScanRequest::new(root.join("fixtures").join(case_id));
        request.configuration.parse_cache_enabled = false;
        let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
        if case["kind"] == "safe_control" {
            controls = controls.saturating_add(1);
            assert!(
                report.findings.is_empty(),
                "safe control {case_id} emitted findings"
            );
            continue;
        }
        vulnerable = vulnerable.saturating_add(1);
        assert_eq!(report.findings.len(), 1, "vulnerable case {case_id}");
        let finding = &report.findings[0];
        let taxonomy = finding.taxonomy.as_ref().ok_or("taxonomy missing")?;
        assert_eq!(
            taxonomy.taxonomy_version,
            case["taxonomy"]["taxonomy_version"]
                .as_str()
                .ok_or("taxonomy version missing")?
        );
        assert_eq!(
            taxonomy.category_id,
            case["taxonomy"]["category_id"]
                .as_str()
                .ok_or("category missing")?
        );
        assert_eq!(
            taxonomy.invariant_id,
            case["taxonomy"]["invariant_id"]
                .as_str()
                .ok_or("invariant missing")?
        );
        assert_eq!(
            finding.primary_cwe.as_ref().ok_or("CWE missing")?.id,
            case["primary_cwe"].as_str().ok_or("expected CWE missing")?
        );
        assert!(
            expected_location_matches(
                finding.source.as_ref().ok_or("source missing")?,
                &case["expected_source"]
            ),
            "unexpected source for {case_id}: {:?}",
            finding.source
        );
        assert!(expected_location_matches(
            finding.sink.as_ref().ok_or("sink missing")?,
            &case["expected_sink"]
        ));

        let contract = finding
            .evidence_contract_v2
            .as_ref()
            .ok_or("contract-v2 projection missing")?;
        assert_eq!(contract.contract_version, EVIDENCE_CONTRACT_VERSION);
        assert_eq!(contract.semantics_version, EVIDENCE_SEMANTICS_VERSION);
        assert_eq!(
            contract.path.first().ok_or("contract source missing")?.role,
            EvidenceContractRoleV2::Source
        );
        assert_eq!(
            contract.path.last().ok_or("contract sink missing")?.role,
            EvidenceContractRoleV2::Sink
        );
        assert!(
            contract
                .path
                .first()
                .is_some_and(|step| step.source_kind.is_some())
        );
        assert!(
            contract
                .path
                .last()
                .is_some_and(|step| step.sink_kind.is_some())
        );
        assert_eq!(
            contract.connected_edges.len().saturating_add(1),
            contract.path.len()
        );
        assert!(contract.connected_edges.iter().all(|connected| *connected));
        assert!(contract.effective_barriers.is_empty());
        assert!(!contract.unresolved_call);
        assert!(!contract.uncertain);
    }
    assert_eq!((vulnerable, controls), (28, 28));
    Ok(())
}

#[test]
fn production_scanner_contains_no_retired_identifiers_or_fixture_vocabulary()
-> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_path("fixtures/phase67-retired-diagnostics");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("regression-manifest-v1.json"))?)?;
    let mut production = String::new();
    for entry in fs::read_dir(workspace_path("crates/secure-engine/src"))? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            production.push_str(&fs::read_to_string(path)?);
        }
    }
    for case in manifest["cases"].as_array().ok_or("cases missing")? {
        let case_id = case["case_id"].as_str().ok_or("case id missing")?;
        assert!(
            !production.contains(case_id),
            "production references {case_id}"
        );
    }
    for diagnostic_fragment in [
        "x-lab-",
        "custodian-",
        "active-",
        "outside-",
        "blocked-",
        "display-",
        "catalog_28",
        "project-0",
        "data-panel=",
    ] {
        assert!(
            !production.contains(diagnostic_fragment),
            "production contains diagnostic-only fragment {diagnostic_fragment}"
        );
    }
    Ok(())
}
