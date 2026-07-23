//! Phase 6.15 tranche 3 structural injection fixtures.

use std::fs;

use secure_engine::{CancellationToken, ScanReport, ScanRequest, scan_repository};
use tempfile::TempDir;

fn scan(source: &str) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::write(repository.path().join("service.ts"), source)?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(&request, &CancellationToken::new(), |_| {})?)
}

fn has(report: &ScanReport, rule: &str) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.rule_id == rule)
}

#[test]
fn dynamic_cli_value_before_delimiter_is_reported() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.spawn('tool', ['read', value], { shell: false }); }",
    )?;
    assert!(has(&report, "SE1008"));
    Ok(())
}

#[test]
fn end_of_options_delimiter_is_a_control() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.spawn('tool', ['read', '--', value], { shell: false }); }",
    )?;
    assert!(!has(&report, "SE1008"));
    Ok(())
}

#[test]
fn structured_sql_and_bound_sql_are_distinguished() -> Result<(), Box<dyn std::error::Error>> {
    let vulnerable = scan(
        "'use server'; export async function copy(form, db) { \
         const option = String(form.get('option')); return db.query(`COPY x WITH (${option})`); }",
    )?;
    assert!(has(&vulnerable, "SE1002"));
    let control = scan(
        "'use server'; export async function find(form, db) { \
         const id = String(form.get('id')); \
         return db.query('SELECT * FROM x WHERE id = ?', [id]); }",
    )?;
    assert!(!has(&control, "SE1002"));
    Ok(())
}

#[test]
fn shared_prototype_merge_is_reported_but_null_map_is_not()
-> Result<(), Box<dyn std::error::Error>> {
    let vulnerable = scan(
        "'use server'; export async function merge(form) { const body = form.get('settings'); \
         Object.assign(Object.prototype, body); }",
    )?;
    assert!(has(&vulnerable, "SE1009"));
    let control = scan(
        "'use server'; export async function merge(form) { const body = form.get('settings'); \
         Object.assign(Object.create(null), body); }",
    )?;
    assert!(!has(&control, "SE1009"));
    Ok(())
}
