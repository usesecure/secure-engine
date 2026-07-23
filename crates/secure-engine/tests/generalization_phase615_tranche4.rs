//! Phase 6.15 tranche 4 sensitive-data boundary fixtures.

use std::fs;

use secure_engine::{CancellationToken, ScanReport, ScanRequest, scan_repository};
use tempfile::TempDir;

fn scan(source: &str) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::write(repository.path().join("provider.ts"), source)?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

fn count(report: &ScanReport) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1010")
        .count()
}

#[test]
fn secret_environment_value_to_log_and_model_is_reported() -> Result<(), Box<dyn std::error::Error>>
{
    let report = scan(
        "async function run() { const token = process.env.MODEL_API_TOKEN; \
         console.error('failed', token); return llm.generate({ token }); }",
    )?;
    assert_eq!(count(&report), 2);
    Ok(())
}

#[test]
fn redacted_metadata_and_prompt_are_controls() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "async function run(prompt) { console.error('failed', { redacted: true }); \
         return llm.generate({ prompt }); }",
    )?;
    assert_eq!(count(&report), 0);
    Ok(())
}

#[test]
fn non_secret_environment_configuration_is_not_a_secret_source()
-> Result<(), Box<dyn std::error::Error>> {
    let report =
        scan("function run() { const region = process.env.PUBLIC_REGION; console.info(region); }")?;
    assert_eq!(count(&report), 0);
    Ok(())
}
