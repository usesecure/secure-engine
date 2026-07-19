//! Phase 6.12 tranche 3 independent shell program-text fixtures.

use std::fs;

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

fn assert_detected(files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert!(
        !findings(&report, "SE1001").is_empty(),
        "expected SE1001; files={files:?}; findings={:#?}",
        report.findings
    );
    Ok(())
}

fn assert_control(files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert!(
        findings(&report, "SE1001").is_empty(),
        "unexpected SE1001; files={files:?}; findings={:#?}",
        report.findings
    );
    Ok(())
}

#[test]
fn known_shells_and_exact_command_options_select_program_text()
-> Result<(), Box<dyn std::error::Error>> {
    let variants = [
        "import { spawn } from 'node:child_process'; export function dispatch(req) { const label = req.query.label; return spawn('sh', ['-c', 'printf ' + label]); }",
        "import { execFile } from 'node:child_process'; export function dispatch(req) { return execFile('/bin/sh', ['-c', `echo ${req.body.note}`], { shell: false }); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { const recipe = 'echo ' + req.params.word; return spawn('bash', ['-l', '-c', recipe]); }",
        "import { spawnSync } from 'node:child_process'; export function dispatch(req) { return spawnSync('/usr/bin/dash', ['-ec', req.query.job]); }",
        "import { execFileSync } from 'node:child_process'; const runtime = '/bin/ash'; export function dispatch(req) { return execFileSync(runtime, ['-xc', req.body.job]); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { return spawn('/usr/bin/ksh', ['-lc', req.query.job]); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { return spawn('/bin/zsh', ['-c', req.body.job]); }",
        "import { spawn } from 'node:child_process'; const mode = '-c'; export function dispatch(req) { const words = [mode, /* exact slot */ req.params.job,]; return spawn('/bin/bash', words); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { return spawn('sh', ['-c', 'printf ready', req.query.outer], { shell: true }); }",
    ];
    for (index, source) in variants.into_iter().enumerate() {
        assert_detected(&[(&format!("src/program-{index}.ts"), source)])?;
    }
    Ok(())
}

#[test]
fn direct_helper_arrow_and_unique_import_flows_reach_only_program_text()
-> Result<(), Box<dyn std::error::Error>> {
    assert_detected(&[(
        "src/helper.ts",
        "import { spawn } from 'node:child_process'; function render(value) { return 'printf ' + value; } export function dispatch(req) { return spawn('sh', ['-c', render(req.body.token)]); }",
    )])?;
    assert_detected(&[(
        "src/arrow.ts",
        "import { execFile } from 'node:child_process'; const render = value => `printf ${value}`; export function dispatch(req) { return execFile('bash', ['-c', render(req.query.token)]); }",
    )])?;
    assert_detected(&[
        (
            "src/dispatch.ts",
            "import { spawn as launch } from 'node:child_process'; import { assemble } from './recipe'; export function dispatch(req) { return launch('/bin/sh', ['-c', assemble(req.params.token)]); }",
        ),
        (
            "src/recipe.ts",
            "export function assemble(value) { return 'printf ' + value; }",
        ),
    ])?;
    Ok(())
}

#[test]
fn partial_rewriting_blocklists_and_quoting_are_not_shell_sanitizers()
-> Result<(), Box<dyn std::error::Error>> {
    let variants = [
        "import { spawn } from 'node:child_process'; export function dispatch(req) { const raw = req.query.word; const recipe = raw.replace(';', ''); return spawn('sh', ['-c', recipe]); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { const raw = req.body.word; if (raw.includes('&&')) throw new Error('blocked'); return spawn('sh', ['-c', raw]); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { const raw = req.params.word; const recipe = '\"' + raw + '\"'; return spawn('sh', ['-c', recipe]); }",
    ];
    for (index, source) in variants.into_iter().enumerate() {
        assert_detected(&[(&format!("src/weak-{index}.js"), source)])?;
    }
    Ok(())
}

#[test]
fn ordinary_argv_constant_programs_and_positional_parameters_remain_clean()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "import { execFile } from 'node:child_process'; export function dispatch(req) { return execFile('/usr/bin/catalog-reader', ['--entry', req.query.entry], { shell: false }); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { return spawn('sh', ['-c', 'printf %s \"$1\"', 'label', req.body.value]); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { void req.query.audit; return spawn('/bin/sh', ['-c', 'printf ready']); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { return spawn('sh', ['-C', req.query.value]); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { return spawn('bash', ['-c', 'printf %s \"$0\"', req.params.value]); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control(&[(&format!("src/argv-control-{index}.ts"), source)])?;
    }
    Ok(())
}

#[test]
fn ambiguous_shadowed_mutated_spread_and_unknown_shapes_invent_no_program_flow()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "import { spawn } from 'node:child_process'; export function dispatch(req) { const runtime = selectRuntime(); void req.query.audit; return spawn(runtime, ['-c', 'printf ready']); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { const option = selectOption(); return spawn('sh', [option, req.body.program]); }",
        "import { spawn as launch } from 'node:child_process'; const safeRunner = () => 0; export function dispatch(req) { const launch = safeRunner; return launch('sh', ['-c', req.query.program]); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { let words = ['-c', req.query.program]; words = ['-C', 'fixed']; return spawn('sh', words); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { const words = ['-c', 'printf ready']; words.push(req.body.positional); return spawn('sh', words); }",
        "import { spawn } from 'node:child_process'; export function dispatch(req) { return spawn('sh', ['-c', 'printf ready', ...req.body.positional]); }",
        "export function dispatch(req) { return invokeRuntime('sh', ['-c', req.query.program]); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control(&[(&format!("src/ambiguous-control-{index}.ts"), source)])?;
    }
    Ok(())
}

#[test]
fn evidence_span_is_the_exact_program_argument_and_cache_v13_misses_v12()
-> Result<(), Box<dyn std::error::Error>> {
    let source = "import { spawn } from 'node:child_process'; export function dispatch(req) { const recipe = `printf ${req.query.message}`; return spawn('/bin/sh', ['-c', recipe, 'label', req.body.positional]); }";
    let report = scan(&[("src/evidence.ts", source)])?;
    let matches = findings(&report, "SE1001");
    let finding = match matches.as_slice() {
        [finding] => *finding,
        _ => return Err(format!("expected one SE1001: {:#?}", report.findings).into()),
    };
    let sink = finding.sink.as_ref().ok_or("sink span missing")?;
    assert_eq!(
        &source[usize::try_from(sink.span.start_byte)?..usize::try_from(sink.span.end_byte)?],
        "recipe"
    );

    let repository = TempDir::new()?;
    fs::create_dir_all(repository.path().join("src"))?;
    fs::write(repository.path().join("src/evidence.ts"), source)?;
    let cache = TempDir::new()?;
    let stale = cache
        .path()
        .join("secure-parse-cache-v12/legacy/stale.json");
    fs::create_dir_all(stale.parent().ok_or("stale parent missing")?)?;
    fs::write(&stale, b"legacy-cache-envelope")?;
    let mut request = ScanRequest::new(repository.path());
    request.cache = CacheControl {
        directory: Some(cache.path().to_path_buf()),
        clear_before_scan: false,
    };
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(cold.parsing.cache_hits, 0);
    assert!(cold.parsing.cache_misses > 0);
    assert!(cold.parsing.cache_writes > 0);
    assert!(stale.is_file());
    assert!(cache.path().join("secure-parse-cache-v13").is_dir());
    assert!(warm.parsing.cache_hits > 0);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert_eq!(cold.facts, warm.facts);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.findings, warm.findings);
    Ok(())
}

#[test]
fn exhausted_interprocedural_depth_does_not_invent_a_shell_program_trace()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::create_dir_all(repository.path().join("src"))?;
    fs::write(
        repository.path().join("src/depth.ts"),
        "import { spawn } from 'node:child_process'; const first = value => second(value); const second = value => third(value); const third = value => value; export function dispatch(req) { return spawn('sh', ['-c', first(req.body.program)]); }",
    )?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    request.configuration.max_interprocedural_depth = 1;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert!(
        findings(&report, "SE1001").is_empty(),
        "{:#?}",
        report.findings
    );
    assert!(report.limitations.iter().any(|limitation| {
        limitation.code == "bounded-interprocedural-analysis"
            && limitation.message.contains("1 traversal levels")
    }));
    Ok(())
}
