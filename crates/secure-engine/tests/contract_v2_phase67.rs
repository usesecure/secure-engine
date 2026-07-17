//! Phase 6.7 public evidence-contract-v2 conformance and provenance tests.

use std::fs;
use std::path::{Path, PathBuf};

use secure_engine::{
    CancellationToken, EVIDENCE_CONTRACT_VERSION, EVIDENCE_SEMANTICS_VERSION,
    EvidenceContractOutcome, EvidenceContractTestDocument, SECURE_JSON_V1_SCHEMA, ScanRequest,
    evaluate_contract_v2, sarif_report, scan_repository,
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

#[test]
fn permitted_public_contract_inputs_are_byte_identical_and_schema_valid()
-> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_path("fixtures/phase67-contract-v2");
    let contract_path = root.join("evidence-contract-v2.json");
    let tests_path = root.join("contract-tests.json");
    let schema_path = root.join("evidence-contract-v2.schema.json");
    assert_eq!(
        sha256(&contract_path)?,
        "142c7f31c6c584cc808410130fa7db8451427e87504e72e64868c9cbc6564c42"
    );
    assert_eq!(
        sha256(&tests_path)?,
        "9e96c98c0688397a5fb6c070d1d55e4336c9760f02347dbbf7162a6d43dc44d4"
    );
    assert_eq!(
        sha256(&schema_path)?,
        "c0298b4a2ceb3d176e5773ea72a057d1929807711560255e0ea6645713bfc4b6"
    );

    let contract: serde_json::Value = serde_json::from_slice(&fs::read(contract_path)?)?;
    let schema: serde_json::Value = serde_json::from_slice(&fs::read(schema_path)?)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&contract));
    assert_eq!(contract["contract_version"], EVIDENCE_CONTRACT_VERSION);
    Ok(())
}

#[test]
fn every_public_canonical_and_near_miss_vector_has_the_required_outcome()
-> Result<(), Box<dyn std::error::Error>> {
    let document: EvidenceContractTestDocument = serde_json::from_slice(&fs::read(
        workspace_path("fixtures/phase67-contract-v2/contract-tests.json"),
    )?)?;
    assert_eq!(document.contract_version, EVIDENCE_CONTRACT_VERSION);
    assert!(document.synthetic_reports_only);
    assert_eq!(document.tests.len(), 11);

    for test in &document.tests {
        assert_eq!(
            evaluate_contract_v2(&test.expectation, &test.finding),
            test.expected,
            "public contract vector {}",
            test.test_id
        );
    }
    assert_eq!(
        document
            .tests
            .iter()
            .filter(|test| test.expected == EvidenceContractOutcome::Exact)
            .count(),
        3
    );
    assert_eq!(
        document
            .tests
            .iter()
            .filter(|test| test.expected == EvidenceContractOutcome::Partial)
            .count(),
        2
    );
    assert_eq!(
        document
            .tests
            .iter()
            .filter(|test| test.expected == EvidenceContractOutcome::NoMatch)
            .count(),
        6
    );
    Ok(())
}

#[test]
fn non_scoring_tool_rule_and_prose_fields_do_not_change_contract_matching()
-> Result<(), Box<dyn std::error::Error>> {
    let document: EvidenceContractTestDocument = serde_json::from_slice(&fs::read(
        workspace_path("fixtures/phase67-contract-v2/contract-tests.json"),
    )?)?;
    let canonical = document
        .tests
        .iter()
        .find(|test| test.test_id == "canonical")
        .ok_or("canonical vector missing")?;
    let mut finding = canonical.finding.clone();
    finding.rule_id = "an-entirely-different-native-rule".into();
    finding.tool_identity = "independent-static-analyzer".into();
    finding.prose = "Changed explanatory text with no scoring semantics".into();
    assert_eq!(
        evaluate_contract_v2(&canonical.expectation, &finding),
        EvidenceContractOutcome::Exact
    );
    assert_eq!(EVIDENCE_SEMANTICS_VERSION, "secure-evidence-semantics-v2");
    Ok(())
}

#[test]
fn scanner_json_and_official_sarif_export_contract_v2_additively()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    fs::write(
        directory.path().join("route.ts"),
        "export function receive(request) { const value = request.body.expression; return eval(value); }",
    )?;
    let mut request = ScanRequest::new(directory.path());
    request.configuration.parse_cache_enabled = false;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(report.findings.len(), 1);
    let contract = report.findings[0]
        .evidence_contract_v2
        .as_ref()
        .ok_or("contract projection missing")?;
    assert_eq!(contract.contract_version, EVIDENCE_CONTRACT_VERSION);
    assert_eq!(contract.semantics_version, EVIDENCE_SEMANTICS_VERSION);

    let secure_schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&secure_schema)?.is_valid(&serde_json::to_value(&report)?));

    let sarif = sarif_report(&report);
    let sarif_schema: serde_json::Value = serde_json::from_slice(&fs::read(workspace_path(
        "schemas/sarif-schema-2.1.0.json",
    ))?)?;
    assert!(jsonschema::validator_for(&sarif_schema)?.is_valid(&sarif));
    assert_eq!(
        sarif["runs"][0]["properties"]["secureEvidenceContractVersion"],
        EVIDENCE_CONTRACT_VERSION
    );
    assert_eq!(
        sarif["runs"][0]["properties"]["secureEvidenceSemanticsVersion"],
        EVIDENCE_SEMANTICS_VERSION
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["evidenceContractV2"]["fingerprint"],
        contract.fingerprint
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["fingerprints"]["secureContractDuplicateFingerprint/v2"],
        contract.duplicate_fingerprint
    );
    Ok(())
}
