//! Neutral regressions for test-context calibration without test-path exclusion.

use std::{fs, path::Path};

use secure_engine::{
    AnalysisAbstention, CancellationToken, EvidenceDisposition, ScanReport, ScanRequest,
    scan_repository,
};

fn write_fixture(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root.join("src"))?;
    fs::create_dir_all(root.join("tests"))?;
    fs::write(
        root.join("src/carry.js"),
        "export function carry(value) { return value; }",
    )?;
    fs::write(
        root.join("src/environment.js"),
        "export function requestStatus() { return fetch(process.env.RUNTIME_STATUS_URL); }",
    )?;
    fs::write(
        root.join("tests/environment.js"),
        "import { spawn } from 'node:child_process';\nexport function launchFixture() { return spawn(process.env.TEST_INTERPRETER, ['-c', 'printf ok']); }",
    )?;
    fs::write(
        root.join("tests/untrusted.js"),
        "import { exec } from 'node:child_process';\nexport function handle(request) { return exec(request.query.command); }",
    )?;
    fs::write(
        root.join("tests/mixed.js"),
        "import { spawn } from 'node:child_process';\nimport { carry } from '../src/carry.js';\nexport function launchMixedFixture() { return spawn(carry(process.env.MIXED_TEST_INTERPRETER), ['-c', 'printf ok']); }",
    )?;
    Ok(())
}

fn is_test_only(abstention: &AnalysisAbstention) -> bool {
    !abstention.evidence_path.is_empty()
        && abstention
            .evidence_path
            .iter()
            .all(|step| step.location.path.starts_with("tests/"))
}

fn assert_context_order(report: &ScanReport) -> Result<(), Box<dyn std::error::Error>> {
    let first_test_abstention = report
        .abstentions
        .iter()
        .position(is_test_only)
        .ok_or("test-context abstention is missing from ordered output")?;
    assert!(
        report.abstentions[..first_test_abstention]
            .iter()
            .all(|abstention| !is_test_only(abstention))
    );
    assert!(
        report.abstentions[first_test_abstention..]
            .iter()
            .all(is_test_only)
    );
    Ok(())
}

#[test]
fn test_context_refines_only_existing_abstentions_and_orders_them_last()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    write_fixture(directory.path())?;

    let mut request = ScanRequest::new(directory.path());
    request.configuration.parse_cache_enabled = false;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;

    let production_abstention = report
        .abstentions
        .iter()
        .find(|abstention| abstention.sink.path == "src/environment.js")
        .ok_or("production environment abstention is missing")?;
    assert_eq!(production_abstention.reason, "actor-authority-equivalence");

    let test_abstention = report
        .abstentions
        .iter()
        .find(|abstention| abstention.sink.path == "tests/environment.js")
        .ok_or("test environment abstention is missing")?;
    assert_eq!(
        test_abstention.reason,
        "test-context-reachability-unresolved"
    );
    assert_eq!(
        test_abstention.calibration.disposition,
        EvidenceDisposition::ExplicitAbstention
    );
    assert!(test_abstention.limitations.iter().any(|limitation| {
        limitation.contains("production or CI reachability")
            && limitation.contains("Test paths remain analyzed")
    }));

    let mixed_abstention = report
        .abstentions
        .iter()
        .find(|abstention| abstention.sink.path == "tests/mixed.js")
        .ok_or("mixed test/production abstention is missing")?;
    assert_eq!(mixed_abstention.reason, "actor-authority-equivalence");
    assert!(
        mixed_abstention
            .evidence_path
            .iter()
            .any(|step| step.location.path == "src/carry.js")
    );

    assert_context_order(&report)?;

    let test_security_path = report
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "SE1001"
                && finding
                    .sink
                    .as_ref()
                    .is_some_and(|sink| sink.path == "tests/untrusted.js")
        })
        .ok_or("test-source security path was incorrectly excluded")?;
    assert_eq!(
        test_security_path
            .calibration
            .as_ref()
            .map(|calibration| &calibration.disposition),
        Some(&EvidenceDisposition::SecurityPath)
    );
    Ok(())
}
