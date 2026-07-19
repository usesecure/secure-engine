//! Phase 6.12 tranche 1 independent arrow and `node:path` summary fixtures.

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
fn expression_and_block_arrows_preserve_the_same_value_flow()
-> Result<(), Box<dyn std::error::Error>> {
    let expression = "const carry = value => value;\nexport function evaluate(req) { return eval(carry(req.body.formula)); }\n";
    let block = "const carry = value => { return value; };\nexport function evaluate(req) { return eval(carry(req.body.formula)); }\n";
    for source in [expression, block] {
        let report = scan(&[("src/evaluator.js", source)])?;
        let matches = findings(&report, "SE1006");
        let finding = match matches.as_slice() {
            [finding] => *finding,
            _ => {
                return Err(format!(
                    "expected exactly one SE1006 finding for {source}: {:#?}",
                    report.findings
                )
                .into());
            }
        };
        let source_span = finding.source.as_ref().ok_or("source span missing")?;
        let sink_span = finding.sink.as_ref().ok_or("sink span missing")?;
        assert_eq!(
            &source[usize::try_from(source_span.span.start_byte)?
                ..usize::try_from(source_span.span.end_byte)?],
            "req.body.formula"
        );
        assert_eq!(
            &source[usize::try_from(sink_span.span.start_byte)?
                ..usize::try_from(sink_span.span.end_byte)?],
            "eval(carry(req.body.formula))"
        );
        assert!(!finding.fingerprint.is_empty());
    }
    Ok(())
}

#[test]
fn arrows_propagate_through_bounded_helpers_and_unique_imports()
-> Result<(), Box<dyn std::error::Error>> {
    assert_detected(
        "SE1002",
        &[(
            "src/query.ts",
            "const carry = (value: string) => value; function forward(value: string) { return carry(value); } export function search(req: any, db: any) { return db.query('select ' + forward(req.query.term)); }",
        )],
    )?;
    assert_detected(
        "SE1005",
        &[
            (
                "src/route.ts",
                "import { preserve as relay } from './value'; export function leave(req: any) { return Response.redirect(relay(req.query.destination)); }",
            ),
            (
                "src/value.ts",
                "export const preserve = (candidate: string) => candidate;",
            ),
        ],
    )?;
    Ok(())
}

#[test]
fn named_namespace_and_aliased_node_path_imports_preserve_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        "import { readFile } from 'node:fs'; import { join } from 'node:path'; const ROOT = '/srv/archive'; export function open(req) { return readFile(join(ROOT, req.params.name), () => undefined); }",
        "import { readFile } from 'node:fs'; import { resolve as compose } from 'node:path'; const ROOT = '/srv/archive'; export function open(req) { return readFile(compose(ROOT, req.body.name), () => undefined); }",
        "import { readFile } from 'node:fs'; import * as pathname from 'node:path'; const ROOT = '/srv/archive'; export function open(req) { return readFile(pathname.resolve(ROOT, req.query.name), () => undefined); }",
        "import { readFile } from 'node:fs'; import pathname from 'node:path'; const ROOT = '/srv/archive'; export function open(req) { return readFile(pathname.join(ROOT, req.params.name), () => undefined); }",
    ];
    for (index, source) in cases.into_iter().enumerate() {
        assert_detected("SE1003", &[(&format!("src/path-{index}.tsx"), source)])?;
    }
    Ok(())
}

#[test]
fn arrow_and_node_path_summaries_compose_within_the_existing_bound()
-> Result<(), Box<dyn std::error::Error>> {
    assert_detected(
        "SE1003",
        &[(
            "src/combined.ts",
            "import { readFile } from 'node:fs'; import { resolve } from 'node:path'; const ROOT = '/srv/archive'; const carry = (piece: string) => piece; export function open(req: any) { return readFile(resolve(ROOT, carry(req.params.name)), () => undefined); }",
        )],
    )?;
    Ok(())
}

#[test]
fn path_summary_fails_closed_for_shadowing_mutation_computed_and_dynamic_shapes()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "import { readFile } from 'node:fs'; import { join } from 'node:path'; const ROOT = '/srv/archive'; export function open(req) { const join = (base, name) => ROOT + '/fixed'; return readFile(join(ROOT, req.params.name), () => undefined); }",
        "import { readFile } from 'node:fs'; import { join as compose } from 'node:path'; const ROOT = '/srv/archive'; compose = (base, name) => ROOT + '/fixed'; export function open(req) { return readFile(compose(ROOT, req.body.name), () => undefined); }",
        "import { readFile } from 'node:fs'; import * as pathname from 'node:path'; const ROOT = '/srv/archive'; pathname.resolve = (base, name) => ROOT + '/fixed'; export function open(req) { return readFile(pathname.resolve(ROOT, req.query.name), () => undefined); }",
        "import { readFile } from 'node:fs'; import * as pathname from 'node:path'; const ROOT = '/srv/archive'; export function open(req) { return readFile(pathname['join'](ROOT, req.params.name), () => undefined); }",
        "import { readFile } from 'node:fs'; import * as pathname from 'node:path'; const ROOT = '/srv/archive'; export function open(req) { const member = req.query.member; return readFile(pathname[member](ROOT, req.params.name), () => undefined); }",
        "import { readFile } from 'node:fs'; import { join } from 'node:path'; const ROOT = '/srv/archive'; export function open(req) { const pieces = [ROOT, req.body.name]; return readFile(join(...pieces), () => undefined); }",
        "import { readFile } from 'node:fs'; import { resolve } from 'node:path'; const ROOT = '/srv/archive'; export function open(req) { return readFile(resolve(ROOT + req.query.folder, req.params.name), () => undefined); }",
        "import { readFile } from 'node:fs'; import { join } from 'node:path'; export function open(req) { void req.body.audit; return readFile(join('/srv/archive', 'fixed.txt'), () => undefined); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control(
            "SE1003",
            &[(&format!("src/path-control-{index}.tsx"), source)],
        )?;
    }
    Ok(())
}

#[test]
fn arrow_summary_fails_closed_for_reassignment_duplicates_and_depth()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "let carry = value => value; carry = value => 'fixed'; export function evaluate(req) { return eval(carry(req.body.formula)); }",
        "function carry(value) { return value; } function carry(value) { return 'fixed'; } export function evaluate(req) { return eval(carry(req.body.formula)); }",
        "const carry = value => 'fixed'; export function evaluate(req) { void req.body.formula; return eval(carry('fixed')); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control(
            "SE1006",
            &[(&format!("src/arrow-control-{index}.js"), source)],
        )?;
    }
    assert_control(
        "SE1006",
        &[
            (
                "src/changed-import.ts",
                "import { preserve as relay } from './preserver'; relay = value => 'fixed'; export function evaluate(req: any) { return eval(relay(req.body.formula)); }",
            ),
            (
                "src/preserver.ts",
                "export const preserve = (value: string) => value;",
            ),
        ],
    )?;

    let repository = TempDir::new()?;
    fs::create_dir_all(repository.path().join("src"))?;
    fs::write(
        repository.path().join("src/depth.ts"),
        "const first = (v: string) => second(v); const second = (v: string) => third(v); const third = (v: string) => v; export function evaluate(req: any) { return eval(first(req.body.formula)); }",
    )?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    request.configuration.max_interprocedural_depth = 2;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert!(
        findings(&report, "SE1006").is_empty(),
        "{:#?}",
        report.findings
    );
    assert!(report.limitations.iter().any(|limitation| {
        limitation.code == "bounded-interprocedural-analysis"
            && limitation.message.contains("2 traversal levels")
    }));
    Ok(())
}

#[test]
fn path_composition_neither_sanitizes_nor_removes_a_valid_same_value_guard()
-> Result<(), Box<dyn std::error::Error>> {
    assert_detected(
        "SE1003",
        &[(
            "src/advisory.ts",
            "import { readFile } from 'node:fs'; import { resolve } from 'node:path'; const ROOT = '/srv/archive'; export function open(req: any) { const candidate = resolve(ROOT, req.params.name); if (!candidate.startsWith(ROOT + '/')) console.warn('outside'); return readFile(candidate, () => undefined); }",
        )],
    )?;
    assert_control(
        "SE1003",
        &[(
            "src/confined.ts",
            "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; const ROOT = '/srv/archive'; export function open(req: any) { const candidate = resolve(ROOT, req.params.name); if (!candidate.startsWith(ROOT + sep)) throw new Error('outside'); return readFile(candidate, () => undefined); }",
        )],
    )?;
    Ok(())
}

#[test]
fn cold_and_warm_summaries_keep_report_fingerprints_and_evidence_stable()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::create_dir_all(repository.path().join("src"))?;
    fs::write(
        repository.path().join("src/stable.ts"),
        "import { readFile } from 'node:fs'; import { join } from 'node:path'; const ROOT = '/srv/archive'; const carry = (piece: string) => piece; export function open(req: any) { return readFile(join(ROOT, carry(req.body.name)), () => undefined); }",
    )?;
    fs::write(
        repository.path().join("src/dynamic.js"),
        "export function execute(req) { return (0, eval)(req.body.formula); }",
    )?;
    let cache = TempDir::new()?;
    let mut request = ScanRequest::new(repository.path());
    request.cache = CacheControl {
        directory: Some(cache.path().to_path_buf()),
        clear_before_scan: false,
    };
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(findings(&cold, "SE1003").len(), 1);
    assert_eq!(findings(&cold, "SE1006").len(), 1);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert_eq!(cold.findings, warm.findings);
    assert_eq!(cold.graph, warm.graph);
    assert!(cold.parsing.cache_writes > 0);
    assert!(warm.parsing.cache_hits > 0);
    Ok(())
}
