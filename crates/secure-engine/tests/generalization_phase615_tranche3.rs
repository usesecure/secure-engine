//! Phase 6.15 tranche 3 structural injection fixtures.

use std::fs;

use secure_engine::{CancellationToken, ScanReport, ScanRequest, scan_repository};
use tempfile::TempDir;

fn scan(source: &str) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::write(repository.path().join("service.ts"), source)?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
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
fn fixed_format_argv_separates_exact_data_operands_only() -> Result<(), Box<dyn std::error::Error>>
{
    let controls = [
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('printf', ['%s', value], { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('/usr/bin/printf', ['%s', value], { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('/bin/printf', ['%s', value], { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.spawn('printf', ['%%:%s', value], { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.spawn('/usr/bin/printf', ['label=%s:%s', 'fixed', value], \
         { shell: false }); }",
    ];
    for source in controls {
        assert!(!has(&scan(source)?, "SE1008"), "control: {source}");
    }

    let adversarial = [
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('/usr/local/bin/printf', ['%s', value], \
         { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('/tmp/printf', ['%s', value], { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('/opt/tools/printf', ['%s', value], \
         { shell: false }); }",
        "'use server'; export async function run(form) { \
         const attackerInput = String(form.get('value')); \
         return child_process.execFile(\"/opt/render\", [\"%s\", attackerInput], \
         { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('/usr/bin/printf', [value], { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('/usr/bin/printf', ['%s', value, value], \
         { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         const format = '%s'; \
         return child_process.execFile('/usr/bin/printf', [format, value], { shell: false }); }",
        "'use server'; export async function run(form) { \
         const format = String(form.get('format')); \
         return child_process.execFile('/usr/bin/printf', [format, 'fixed'], \
         { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         const values = [value]; \
         return child_process.execFile('/usr/bin/printf', ['%s', ...values], \
         { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('./printf', ['%s', value], { shell: false }); }",
    ];
    for source in adversarial {
        assert!(has(&scan(source)?, "SE1008"), "adversarial: {source}");
    }

    let conservative_shapes = [
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         const executable = '/usr/bin/printf'; \
         return child_process.execFile(executable, ['%s', value], { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         const argv = ['%s', value]; \
         return child_process.execFile('/usr/bin/printf', argv, { shell: false }); }",
        "'use server'; export async function run(form) { \
         const argv = form.get('argv'); \
         return child_process.execFile('/usr/bin/printf', argv, { shell: false }); }",
        "'use server'; export async function run(form) { \
         const executable = String(form.get('executable')); \
         return child_process.execFile(executable, ['%s', 'fixed'], { shell: false }); }",
        "'use server'; export async function run(form) { const value = String(form.get('value')); \
         return child_process.execFile('/usr/bin/printf', ['%s', value], \
         { shell: true }); }",
    ];
    for source in conservative_shapes {
        assert!(!scan(source)?.findings.is_empty(), "conservative: {source}");
    }
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
fn shared_prototype_merge_is_reported_but_null_map_is_not() -> Result<(), Box<dyn std::error::Error>>
{
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
