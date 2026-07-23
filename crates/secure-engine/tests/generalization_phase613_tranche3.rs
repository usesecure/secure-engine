//! Phase 6.13 tranche 3 independent false-positive boundary fixtures.

use std::fs;

use secure_engine::{CacheControl, CancellationToken, ScanReport, ScanRequest, scan_repository};
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

fn count(report: &ScanReport, rule: &str) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule)
        .count()
}

fn assert_control(rule: &str, source: &str) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(&[("src/control.ts", source)])?;
    assert_eq!(
        count(&report, rule),
        0,
        "unexpected {rule}; findings={:#?}",
        report.findings
    );
    Ok(())
}

fn assert_detected(rule: &str, source: &str) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(&[("src/vulnerable.ts", source)])?;
    assert!(
        count(&report, rule) > 0,
        "expected {rule}; findings={:#?}",
        report.findings
    );
    Ok(())
}

#[test]
fn exact_guards_clean_only_the_same_derived_value() -> Result<(), Box<dyn std::error::Error>> {
    assert_control(
        "SE1004",
        "const PEERS = Object.freeze(new Set(['relay.saffron.example'])); function approve(raw: string) { const endpoint = new URL(raw); if (endpoint.protocol !== 'https:' || !PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return endpoint.href; } export function transmit(req: any) { return fetch(approve(req.query.address)); }",
    )?;
    assert_control(
        "SE1003",
        "import { readFile } from 'node:fs/promises'; import { resolve, sep } from 'node:path'; const ARCHIVE = resolve('/opt/saffron/archive'); function locate(leaf: string) { const candidate = resolve(ARCHIVE, leaf); if (candidate !== ARCHIVE && !candidate.startsWith(ARCHIVE + sep)) { throw new Error('refused'); } return candidate; } export function retrieve(req: any) { return readFile(locate(req.params.leaf), 'utf8'); }",
    )?;
    assert_control(
        "SE1005",
        "const PORTAL = 'https://saffron.example:9443'; function approve(raw: string) { const destination = new URL(raw, PORTAL); if (destination.origin !== PORTAL) { throw new Error('refused'); } return destination; } export function transfer(req: any) { return Response.redirect(approve(req.body.next), 303); }",
    )?;
    Ok(())
}

#[test]
fn shadowing_reassignment_and_ambiguous_aliases_do_not_borrow_guard_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let outbound = [
        "const HOST = 'relay.saffron.example'; export function transmit(req) { const endpoint = new URL(req.query.address); { const endpoint = new URL('https://relay.saffron.example/status'); if (endpoint.protocol !== 'https:' || endpoint.hostname !== HOST) { throw new Error('refused'); } } return fetch(endpoint.href); }",
        "const HOST = 'relay.saffron.example'; export function transmit(req) { let endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || endpoint.hostname !== HOST) { throw new Error('refused'); } endpoint = new URL(req.body.fallback); return fetch(endpoint.href); }",
        "const HOST = 'relay.saffron.example'; export function transmit(req) { const first = new URL(req.query.address); const second = new URL(req.body.address); const endpoint = req.query.primary ? first : second; if (endpoint.protocol !== 'https:' || endpoint.hostname !== HOST) { throw new Error('refused'); } return fetch(endpoint.href); }",
    ];
    for source in outbound {
        assert_detected("SE1004", source)?;
    }
    Ok(())
}

#[test]
fn mutation_spreads_computed_properties_and_exceptional_control_remain_vulnerable()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            "SE1004",
            "const HOST = 'relay.saffron.example'; export function transmit(req) { const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || endpoint.hostname !== HOST) { throw new Error('refused'); } endpoint.hostname = req.body.host; return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "const PEERS = Object.freeze(new Set(['relay.saffron.example'])); export function transmit(req) { PEERS.add(req.body.host); const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || !PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "const APPROVED_PEERS = new Set(['relay.saffron.example']); export function transmit(req) { APPROVED_PEERS.add(req.body.host); const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || !APPROVED_PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return fetch(endpoint); }",
        ),
        (
            "SE1004",
            "const PEERS = Object.freeze(new Set(['relay.saffron.example'])); export function transmit(req) { const alias = PEERS; alias.add(req.body.host); const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || !PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "const PEERS = Object.freeze(new Set(['relay.saffron.example'])); function alter(collection, value) { collection.add(value); } export function transmit(req) { alter(PEERS, req.body.host); const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || !PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "const Object = { freeze(value) { return value; } }; const PEERS = Object.freeze(new Set(['relay.saffron.example'])); export function transmit(req) { const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || !PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "Object.freeze = function passthrough(value) { return value; }; const PEERS = Object.freeze(new Set(['relay.saffron.example'])); export function transmit(req) { const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || !PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "URL = function replacement(value) { return { href: value, protocol: 'https:', hostname: 'relay.saffron.example' }; }; export function transmit(req) { const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || endpoint.hostname !== 'relay.saffron.example') { throw new Error('refused'); } return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "const freeze = Object.freeze; const PEERS = freeze(new Set(['relay.saffron.example'])); export function transmit(req) { const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || !PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "const PEERS = Object.freeze(Object.freeze(Object.freeze(Object.freeze(Object.freeze(Object.freeze(Object.freeze(Object.freeze(Object.freeze(new Set(['relay.saffron.example'])))))))))); export function transmit(req) { const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || !PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "const HOST = 'relay.saffron.example'; export function transmit(req) { const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' && endpoint.hostname !== HOST) { throw new Error('refused'); } return fetch(endpoint.href); }",
        ),
        (
            "SE1004",
            "const HOST = 'relay.saffron.example'; export function transmit(req) { const state = { endpoint: new URL(req.query.address) }; const packet = { ...state }; if (packet.endpoint.protocol !== 'https:' || packet.endpoint.hostname !== HOST) { throw new Error('refused'); } return fetch(req.query.address); }",
        ),
        (
            "SE1005",
            "const PORTAL = 'https://saffron.example'; export function transfer(req) { const destination = new URL(req.query.next, PORTAL); if (destination.origin !== PORTAL) { throw new Error('refused'); } const field = req.query.field; return Response.redirect(destination[field]); }",
        ),
        (
            "SE1005",
            "const PORTAL = 'https://saffron.example'; export function transfer(req) { const destination = new URL(req.query.next, PORTAL); try { if (destination.origin !== PORTAL) throw new Error('refused'); } catch { audit(destination); } return Response.redirect(destination); }",
        ),
        (
            "SE1003",
            "import { readFile } from 'node:fs/promises'; import { resolve, sep } from 'node:path'; const ROOT = resolve('/opt/saffron/archive'); export function retrieve(req) { const candidate = resolve(ROOT, req.query.leaf); try { if (candidate !== ROOT && !candidate.startsWith(ROOT + sep)) throw new Error('refused'); } finally { audit(candidate); } return readFile(candidate); }",
        ),
    ];
    for (rule, source) in cases {
        assert_detected(rule, source)?;
    }
    Ok(())
}

#[test]
fn outbound_proof_cycles_and_depth_exhaustion_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    assert_detected(
        "SE1004",
        "const HOST = 'relay.saffron.example'; export function transmit(req) { const value0 = new URL(req.query.address); const value1 = value0; const value2 = value1; const value3 = value2; const value4 = value3; const value5 = value4; const value6 = value5; const value7 = value6; const value8 = value7; const value9 = value8; if (value9.protocol !== 'https:' || value9.hostname !== HOST) { throw new Error('refused'); } return fetch(value9.href); }",
    )?;
    assert_detected(
        "SE1004",
        "const HOST = 'relay.saffron.example'; export function transmit(req) { let endpoint = new URL(req.query.address); let alias = endpoint; endpoint = alias; alias = endpoint; if (alias.protocol !== 'https:' || alias.hostname !== HOST) { throw new Error('refused'); } return fetch(alias.href); }",
    )?;
    Ok(())
}

#[test]
fn parser_recovery_is_neither_a_global_suppression_nor_a_safety_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let vulnerable = scan(&[(
        "src/recovered-vulnerable.ts",
        "export function transmit(req) { const endpoint = req.query.address; return fetch(endpoint); } export const unfinished = [;",
    )])?;
    assert!(
        vulnerable.parser_diagnostics.iter().any(|diagnostic| {
            diagnostic.location.path == "src/recovered-vulnerable.ts" && diagnostic.recoverable
        }),
        "expected a recoverable parser diagnostic"
    );
    assert!(count(&vulnerable, "SE1004") > 0);

    let controlled = scan(&[(
        "src/recovered-control.ts",
        "const PEERS = Object.freeze(new Set(['relay.saffron.example'])); export function transmit(req) { const endpoint = new URL(req.query.address); if (endpoint.protocol !== 'https:' || !PEERS.has(endpoint.hostname)) { throw new Error('refused'); } return fetch(endpoint.href); } export const unfinished = [;",
    )])?;
    assert!(
        controlled.parser_diagnostics.iter().any(|diagnostic| {
            diagnostic.location.path == "src/recovered-control.ts" && diagnostic.recoverable
        }),
        "expected a recoverable parser diagnostic"
    );
    assert_eq!(count(&controlled, "SE1004"), 0);
    Ok(())
}

#[test]
fn cache_v16_safely_misses_v15_and_reports_remain_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::create_dir_all(repository.path().join("src"))?;
    let source = "export function transmit(req) { const endpoint = req.query.address; return fetch(endpoint); }";
    fs::write(repository.path().join("src/stable.ts"), source)?;
    let cache = TempDir::new()?;
    let stale = cache.path().join("secure-parse-cache-v15/old/entry.json");
    fs::create_dir_all(stale.parent().ok_or("stale parent missing")?)?;
    fs::write(&stale, b"historical-private-cache")?;

    let mut request = ScanRequest::new(repository.path());
    request.cache = CacheControl {
        directory: Some(cache.path().to_path_buf()),
        clear_before_scan: false,
    };
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let finding = cold
        .findings
        .iter()
        .find(|finding| finding.rule_id == "SE1004")
        .ok_or("SE1004 finding missing")?;
    let source_span = finding.source.as_ref().ok_or("source span missing")?;
    let sink_span = finding.sink.as_ref().ok_or("sink span missing")?;
    assert_eq!(
        &source[usize::try_from(source_span.span.start_byte)?
            ..usize::try_from(source_span.span.end_byte)?],
        "req.query.address"
    );
    assert_eq!(
        &source[usize::try_from(sink_span.span.start_byte)?
            ..usize::try_from(sink_span.span.end_byte)?],
        "fetch(endpoint)"
    );
    assert!(!finding.fingerprint.is_empty());
    assert!(finding.semantic_fingerprint.is_some());
    assert!(finding.evidence_contract_v2.is_some());
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.findings, warm.findings);
    assert_eq!(cold.parsing.cache_hits, 0);
    assert!(cold.parsing.cache_misses > 0);
    assert!(warm.parsing.cache_hits > 0);
    assert!(stale.is_file());
    assert!(cache.path().join("secure-parse-cache-v20").is_dir());
    Ok(())
}
