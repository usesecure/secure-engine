//! Neutral regressions for test-context calibration without test-path exclusion.

use std::fs;

use secure_engine::{CancellationToken, EvidenceDisposition, ScanRequest, scan_repository};

#[test]
fn test_context_refines_only_existing_abstentions_and_orders_them_last()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    fs::create_dir_all(directory.path().join("src"))?;
    fs::create_dir_all(directory.path().join("tests"))?;
    fs::write(
        directory.path().join("src/environment.js"),
        "export function requestStatus() { return fetch(process.env.RUNTIME_STATUS_URL); }",
    )?;
    fs::write(
        directory.path().join("tests/environment.js"),
        "import { spawn } from 'node:child_process';\nexport function launchFixture() { return spawn(process.env.TEST_INTERPRETER, ['-c', 'printf ok']); }",
    )?;
    fs::write(
        directory.path().join("tests/untrusted.js"),
        "import { exec } from 'node:child_process';\nexport function handle(request) { return exec(request.query.command); }",
    )?;

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

    let first_test_abstention = report
        .abstentions
        .iter()
        .position(|abstention| abstention.source.path.starts_with("tests/"))
        .ok_or("test-context abstention is missing from ordered output")?;
    assert!(
        report.abstentions[..first_test_abstention]
            .iter()
            .all(|abstention| !abstention.source.path.starts_with("tests/"))
    );

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
