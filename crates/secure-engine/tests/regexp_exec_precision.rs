//! Call-target calibration derived from reviewed `RegExp` false positives.
//! Fixtures are synthetic; scanned JavaScript is never executed.

use std::fs;

use secure_engine::{CacheControl, CancellationToken, ScanReport, ScanRequest, scan_repository};

fn scan(source: &str, extension: &str) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::create_dir_all(root.path().join("app/api/check"))?;
    fs::write(
        root.path().join(format!("app/api/check/route.{extension}")),
        source,
    )?;
    let mut request = ScanRequest::new(root.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

fn process_facts(report: &ScanReport) -> usize {
    report
        .facts
        .iter()
        .filter(|fact| fact.kind == "process-execution")
        .count()
}

#[test]
fn literal_regexp_receivers_are_not_command_sinks() -> Result<(), Box<dyn std::error::Error>> {
    for extension in ["js", "jsx", "ts", "tsx"] {
        let report = scan(
            "export async function POST(request) { const body = await request.json(); const senderPattern = /name: (.+)/g; let match = senderPattern.exec(body.text); while (match) { match = senderPattern.exec(body.text); } return Response.json({ found: Boolean(match) }); }",
            extension,
        )?;
        assert_eq!(process_facts(&report), 0, "{extension}");
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "SE1001"),
            "{extension}"
        );
        assert!(
            report
                .facts
                .iter()
                .any(|fact| fact.kind == "call"
                    && fact.name.as_deref() == Some("senderPattern.exec"))
        );
    }
    Ok(())
}

#[test]
fn imports_and_unknown_exec_receivers_remain_candidates() -> Result<(), Box<dyn std::error::Error>>
{
    for source in [
        "import { exec } from 'node:child_process'; export async function POST(request) { const body = await request.json(); return exec(body.command); }",
        "import * as pattern from 'node:child_process'; export async function POST(request) { const body = await request.json(); return pattern.exec(body.command); }",
        "import { exec as run } from 'node:child_process'; export async function POST(request) { const body = await request.json(); return run(body.command); }",
        "export async function POST(request) { const body = await request.json(); const pattern = getRunner(); return pattern.exec(body.command); }",
    ] {
        let report = scan(source, "ts")?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "SE1001"),
            "{source}"
        );
    }
    Ok(())
}

#[test]
fn mutation_escape_shadowing_and_dynamic_constructors_keep_process_facts()
-> Result<(), Box<dyn std::error::Error>> {
    for source in [
        "const pattern = /x/; export function handle(req, pattern) { return pattern.exec(req.body.command); }",
        "export function handle(req) { let pattern = /x/; pattern = child_process; return pattern.exec(req.body.command); }",
        "export function handle(req) { const pattern = /x/; pattern.exec = exec; return pattern.exec(req.body.command); }",
        "export function handle(req) { const pattern = /x/; mutate(pattern); return pattern.exec(req.body.command); }",
        "export function handle(req) { const pattern = /x/; mutate({ pattern }); return pattern.exec(req.body.command); }",
        "export function handle(req) { const pattern = /x/; const alias = pattern; alias.exec = exec; return pattern.exec(req.body.command); }",
        "export function handle(req) { const pattern = /x/; Object.defineProperty(pattern, 'exec', { value: exec }); return pattern.exec(req.body.command); }",
        "export function handle(req) { const pattern = /x/; while (req.body.next) { pattern.exec(req.body.command); pattern.exec = exec; } }",
        "export function handle(req) { const pattern = /x/; function nested(pattern) { return pattern.exec(req.body.command); } return nested(child_process); }",
        "export function handle(req) { const pattern = /x/; return function* () { yield pattern.exec(req.body.command); }; }",
        "export function handle(req) { const pattern = /x/; { const pattern = child_process; return pattern.exec(req.body.command); } }",
        "export function handle(req) { const pattern = /x/; try { throw child_process; } catch (pattern) { return pattern.exec(req.body.command); } }",
        "export function handle(req) { const pattern = /x/; eval('pattern.exec = exec'); return pattern.exec(req.body.command); }",
        "RegExp.prototype.exec = exec; export function handle(req) { const pattern = /x/; return pattern.exec(req.body.command); }",
        "Object.getPrototypeOf(/x/).exec = exec; export function handle(req) { const pattern = /x/; return pattern.exec(req.body.command); }",
        "export function handle(req, RegExp) { const pattern = new RegExp('x'); return pattern.exec(req.body.command); }",
    ] {
        let report = scan(source, "ts")?;
        assert!(process_facts(&report) > 0, "{source}");
    }
    Ok(())
}

#[test]
fn traversal_budget_exhaustion_preserves_process_facts() -> Result<(), Box<dyn std::error::Error>> {
    let local = format!(
        "export function handle(req) {{ const pattern = /x/; {} return pattern.exec(req.body.text); }}",
        ";".repeat(5000)
    );
    let module = format!(
        "{} export function handle(req) {{ const pattern = /x/; return pattern.exec(req.body.text); }}",
        ";".repeat(17000)
    );
    for source in [local, module] {
        assert!(process_facts(&scan(&source, "ts")?) > 0);
    }
    Ok(())
}

#[test]
fn cache_v24_ignores_v23_and_preserves_cold_warm_results() -> Result<(), Box<dyn std::error::Error>>
{
    let repository = tempfile::tempdir()?;
    fs::create_dir_all(repository.path().join("app/api/check"))?;
    fs::write(
        repository.path().join("app/api/check/route.ts"),
        "import { exec } from 'node:child_process'; export async function POST(request) { const body = await request.json(); const pattern = /x/; pattern.exec(body.text); return exec(body.command); }",
    )?;
    let cache = tempfile::tempdir()?;
    let stale = cache.path().join("secure-parse-cache-v23/old/entry.json");
    fs::create_dir_all(stale.parent().ok_or("missing stale-cache parent")?)?;
    fs::write(&stale, b"historical-private-cache")?;
    let mut request = ScanRequest::new(repository.path());
    request.cache = CacheControl {
        directory: Some(cache.path().to_path_buf()),
        clear_before_scan: false,
    };
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(process_facts(&cold), 1);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert_eq!(cold.facts, warm.facts);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.findings, warm.findings);
    assert_eq!(cold.parsing.cache_hits, 0);
    assert!(cold.parsing.cache_misses > 0);
    assert!(warm.parsing.cache_hits > 0);
    assert_eq!(fs::read(stale)?, b"historical-private-cache");
    assert!(cache.path().join("secure-parse-cache-v24").is_dir());
    Ok(())
}

#[test]
fn unrelated_regexp_construction_does_not_invalidate_local_literal()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "const other = new RegExp('fixed'); export function handle(req) { const pattern = /x/g; return pattern.exec(req.body.text); }",
        "ts",
    )?;
    assert_eq!(process_facts(&report), 0);
    Ok(())
}

#[test]
fn regex_refinement_does_not_hide_a_real_process_sink_in_the_same_handler()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "import { exec } from 'node:child_process'; export async function POST(request) { const body = await request.json(); const pattern = /x/; pattern.exec(body.text); return exec(body.command); }",
        "ts",
    )?;
    assert_eq!(process_facts(&report), 1);
    let commands = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1001")
        .collect::<Vec<_>>();
    assert_eq!(commands.len(), 1);
    Ok(())
}
