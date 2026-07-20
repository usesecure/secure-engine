//! Phase 6.13 tranche 2 authorization-contract boundary fixtures.

use std::fs;

use secure_engine::{CancellationToken, ScanReport, ScanRequest, scan_repository};
use tempfile::TempDir;

fn scan(files: &[(&str, &str)]) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    for (relative, source) in files {
        let path = repository.path().join(relative);
        fs::create_dir_all(path.parent().ok_or("fixture path has no parent")?)?;
        fs::write(path, source)?;
    }
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

fn se1007_count(report: &ScanReport) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1007")
        .count()
}

fn sensitive_mutation_count(report: &ScanReport) -> usize {
    report
        .graph
        .nodes
        .iter()
        .filter(|node| node.kind == "sink" && node.name.as_deref() == Some("sensitive-mutation"))
        .count()
}

fn handler_count(report: &ScanReport) -> usize {
    report
        .graph
        .nodes
        .iter()
        .filter(|node| node.kind == "handler")
        .count()
}

#[test]
fn existing_structural_handler_and_supported_mutation_contract_remains_active()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan(&[(
        "app/actions/revise.ts",
        "'use server'; export async function revise(form: FormData) { const key = String(form.get('key') ?? ''); return ledgerRepository.update(key, { state: 'sealed' }); }",
    )])?;
    assert_eq!(sensitive_mutation_count(&report), 1);
    assert_eq!(se1007_count(&report), 1);
    Ok(())
}

#[test]
fn maps_sets_properties_and_generic_cache_methods_are_not_authorization_sinks()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "'use server'; const table = new Map(); export async function revise(form: FormData) { const key = String(form.get('key') ?? ''); table.set(key, { state: 'sealed' }); return key; }",
        "'use server'; const membership = new Set(); export async function revise(form: FormData) { const key = String(form.get('key') ?? ''); membership.add(key); return key; }",
        "'use server'; const localState = Object.create(null); export async function revise(form: FormData) { const key = String(form.get('key') ?? ''); localState[key] = { state: 'sealed' }; return key; }",
        "'use server'; const memoryCache = { set(key, value) { return value; } }; export async function revise(form: FormData) { const key = String(form.get('key') ?? ''); return memoryCache.set(key, { state: 'sealed' }); }",
        "'use server'; const table = new Map(); const write = table.set.bind(table); export async function revise(form: FormData) { const key = String(form.get('key') ?? ''); return write(key, { state: 'sealed' }); }",
        "'use server'; const table = new Map(); function store(key) { return table.set(key, { state: 'sealed' }); } export async function revise(form: FormData) { const key = String(form.get('key') ?? ''); return store(key); }",
        "'use server'; const table = new Map(); export async function revise(form: FormData) { const key = String(form.get('key') ?? ''); const receiver = form.get('mode') ? table : new Map(); return receiver.set(key, { state: 'sealed' }); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        let report = scan(&[(&format!("app/actions/local-{index}.ts"), source)])?;
        assert_eq!(
            sensitive_mutation_count(&report),
            0,
            "local mutation {index} became a sensitive sink"
        );
        assert_eq!(
            se1007_count(&report),
            0,
            "local mutation {index} produced SE1007"
        );
    }
    Ok(())
}

#[test]
fn framework_handler_evidence_requires_structure_not_an_exported_function_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let unregistered = scan(&[(
        "src/library.ts",
        "export async function dispatch(request, response) { void response; return ledgerRepository.update(request.body.key, { state: 'sealed' }); }",
    )])?;
    assert_eq!(sensitive_mutation_count(&unregistered), 1);
    assert_eq!(handler_count(&unregistered), 0);

    let registered = scan(&[(
        "src/router.ts",
        "async function dispatch(request, response) { void response; return ledgerRepository.update(request.body.key, { state: 'sealed' }); } router.patch('/ledger/:key', dispatch);",
    )])?;
    assert_eq!(sensitive_mutation_count(&registered), 1);
    assert!(handler_count(&registered) > 0);
    assert_eq!(se1007_count(&registered), 1);
    Ok(())
}
