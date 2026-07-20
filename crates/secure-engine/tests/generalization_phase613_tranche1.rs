//! Phase 6.13 tranche 1 independent bounded propagation fixtures.

use std::{fmt::Write as _, fs};

use secure_engine::{
    CacheControl, CancellationToken, Finding, ScanReport, ScanRequest, scan_repository,
};
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

fn findings<'a>(report: &'a ScanReport, rule: &str) -> Vec<&'a Finding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule)
        .collect()
}

fn assert_detected(rule: &str, files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert!(
        !findings(&report, rule).is_empty(),
        "expected {rule}; files={files:?}; findings={:#?}",
        report.findings
    );
    Ok(())
}

fn assert_control(rule: &str, files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert!(
        findings(&report, rule).is_empty(),
        "unexpected {rule}; files={files:?}; findings={:#?}",
        report.findings
    );
    Ok(())
}

#[test]
fn forward_scalar_aliases_and_proven_joins_reach_supported_sinks()
-> Result<(), Box<dyn std::error::Error>> {
    assert_detected(
        "SE1006",
        &[(
            "src/formula.ts",
            "export async function POST(request: Request) { const document = await request.json(); let fragment = String(document.formula ?? ''); const mirrored = fragment; fragment = mirrored; const source = `Number(${fragment})`; return (0, eval)(source); }",
        )],
    )?;
    assert_detected(
        "SE1004",
        &[(
            "src/relay.jsx",
            "export async function send(request) { const document = await request.json(); let endpoint = String(document.endpoint ?? ''); let selected = endpoint; if (endpoint.length > 0) selected = endpoint; endpoint = selected; return fetch(endpoint); }",
        )],
    )?;
    assert_detected(
        "SE1003",
        &[
            (
                "src/open.ts",
                "import { openText as relay } from './reader'; export async function POST(request: Request) { const document = await request.json(); let leaf = String(document.leaf ?? ''); const stable = leaf; leaf = stable; return relay(leaf); }",
            ),
            (
                "src/reader.ts",
                "import { readFile } from 'node:fs/promises'; import { join } from 'node:path'; export function openText(leaf: string) { const target = join('/srv/quartz-ledger', leaf); return readFile(target, 'utf8'); }",
            ),
        ],
    )?;
    Ok(())
}

#[test]
fn static_object_round_trips_and_value_preserving_property_writes_propagate()
-> Result<(), Box<dyn std::error::Error>> {
    let positives = [
        "export async function calculate(request) { const document = await request.json(); let fragment = String(document.formula ?? ''); const capsule = { script: fragment, note: 'fixed' }; const { script: chosen } = capsule; fragment = chosen; return eval(fragment); }",
        "export async function calculate(request) { const document = await request.json(); let fragment = String(document.formula ?? ''); const capsule = { script: fragment, note: 'fixed' }; fragment = capsule.script; return eval(fragment); }",
        "export async function calculate(request) { const document = await request.json(); let fragment = String(document.formula ?? ''); const capsule = { script: fragment, note: 'fixed' }; capsule.script = String(capsule.script); fragment = capsule.script; return eval(fragment); }",
    ];
    for (index, source) in positives.into_iter().enumerate() {
        assert_detected(
            "SE1006",
            &[(&format!("src/object-positive-{index}.tsx"), source)],
        )?;
    }
    Ok(())
}

#[test]
fn shadowing_reassignment_spreads_computed_properties_and_ambiguous_aliases_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "export async function calculate(request) { const document = await request.json(); let fragment = String(document.formula ?? ''); fragment = '40 + 2'; return eval(fragment); }",
        "export async function calculate(request) { const document = await request.json(); const fragment = String(document.formula ?? ''); { const fragment = '40 + 2'; return eval(fragment); } }",
        "export async function calculate(request) { const document = await request.json(); const base = { script: String(document.formula ?? '') }; const capsule = { ...base }; return eval(capsule.script); }",
        "export async function calculate(request) { const document = await request.json(); const key = String(document.key ?? ''); const capsule = { [key]: String(document.formula ?? '') }; return eval(capsule.script); }",
        "export async function calculate(request) { const document = await request.json(); const capsule = { script: String(document.formula ?? '') }; return eval(capsule[String(document.key ?? '')]); }",
        "function left(value) { return '40 + 2'; } function right(value) { return '21 * 2'; } export async function calculate(request) { const document = await request.json(); const fragment = String(document.formula ?? ''); const alias = document.mode ? left : right; return eval(alias(fragment)); }",
        "export async function calculate(request) { const document = await request.json(); const capsule = { script: String(document.formula ?? '') }; capsule.script = rewrite(capsule.script); return eval(capsule.script); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control(
            "SE1006",
            &[(&format!("src/object-control-{index}.js"), source)],
        )?;
    }
    Ok(())
}

#[test]
fn cycles_do_not_invent_sources_and_local_value_depth_is_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    assert_control(
        "SE1006",
        &[(
            "src/unseeded-cycle.js",
            "export function calculate(req) { let first = second; let second = first; void req.body.formula; return eval(second); }",
        )],
    )?;

    let mut within_bound =
        String::from("export function calculate(req) { const value0 = req.body.formula;");
    for index in 1..=15 {
        write!(
            &mut within_bound,
            " const value{index} = value{};",
            index - 1
        )?;
    }
    within_bound.push_str(" return eval(value15); }");
    assert_detected("SE1006", &[("src/within-depth.js", within_bound.as_str())])?;

    let bounded = within_bound.replace(
        " return eval(value15); }",
        " const value16 = value15; return eval(value16); }",
    );
    assert_control("SE1006", &[("src/exhausted-depth.js", bounded.as_str())])?;
    Ok(())
}

#[test]
fn evidence_contracts_are_deterministic_and_cache_v16_safely_misses_v14()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::create_dir_all(repository.path().join("src"))?;
    let source = "export async function calculate(request) { const document = await request.json(); let fragment = String(document.formula ?? ''); const capsule = { script: fragment }; const { script: chosen } = capsule; fragment = chosen; return eval(fragment); }";
    fs::write(repository.path().join("src/stable.ts"), source)?;
    let cache = TempDir::new()?;
    let stale = cache
        .path()
        .join("secure-parse-cache-v14/legacy/stale.json");
    fs::create_dir_all(stale.parent().ok_or("stale parent missing")?)?;
    fs::write(&stale, b"historical-cache-envelope")?;
    let mut request = ScanRequest::new(repository.path());
    request.cache = CacheControl {
        directory: Some(cache.path().to_path_buf()),
        clear_before_scan: false,
    };
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let matches = findings(&cold, "SE1006");
    let finding = match matches.as_slice() {
        [finding] => *finding,
        _ => return Err(format!("expected one SE1006: {:#?}", cold.findings).into()),
    };
    assert!(finding.evidence_contract_v2.is_some());
    assert!(!finding.fingerprint.is_empty());
    assert!(
        !finding
            .semantic_fingerprint
            .as_deref()
            .unwrap_or_default()
            .is_empty()
    );
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.findings, warm.findings);
    assert_eq!(cold.parsing.cache_hits, 0);
    assert!(cold.parsing.cache_misses > 0);
    assert!(stale.is_file());
    assert!(cache.path().join("secure-parse-cache-v16").is_dir());
    assert!(warm.parsing.cache_hits > 0);
    Ok(())
}
