//! Phase 6.12 tranche 4 independent object-literal destructuring fixtures.

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
fn static_object_properties_reach_only_matching_destructured_bindings()
-> Result<(), Box<dyn std::error::Error>> {
    let variants = [
        (
            "SE1002",
            "export function search(request) { const { clause: fragment } = { clause: request.body.filter, sibling: 'fixed' }; return db.raw(fragment); }",
        ),
        (
            "SE1006",
            "export function evaluate(req) { const formula = req.body.formula; const { formula: program } = { formula, note: 'fixed' }; return eval(program); }",
        ),
        (
            "SE1006",
            "export function evaluate(req) { const packet = { formula: req.params.formula, note: 'fixed' }; const { formula } = packet; return eval(formula); }",
        ),
        (
            "SE1002",
            "export function search(request) { const phrase = request.body.filter; const parcel = { phrase }; const { phrase: selected } = parcel; return db.raw(selected); }",
        ),
        (
            "SE1006",
            "export function evaluate(req) { let capsule = { expression: req.body.expression }; let { expression: selected } = capsule; return eval(selected); }",
        ),
        (
            "SE1006",
            "export function evaluate(req) { var capsule = { expression: req.body.expression }; var { expression: selected } = capsule; return eval(selected); }",
        ),
    ];
    for (index, (rule, source)) in variants.into_iter().enumerate() {
        assert_detected(rule, &[(&format!("src/property-flow-{index}.ts"), source)])?;
    }
    Ok(())
}

#[test]
fn helpers_arrows_and_unique_imports_preserve_extracted_property_identity()
-> Result<(), Box<dyn std::error::Error>> {
    assert_detected(
        "SE1006",
        &[(
            "src/helper.ts",
            "function relayValue(value) { return eval(value); } export function evaluate(req) { const capsule = { expression: req.body.expression }; const { expression: chosen } = capsule; return relayValue(chosen); }",
        )],
    )?;
    assert_detected(
        "SE1006",
        &[(
            "src/arrow.ts",
            "const carry = value => value; export function evaluate(req) { const capsule = { expression: req.query.expression }; const { expression: chosen } = capsule; return eval(carry(chosen)); }",
        )],
    )?;
    assert_detected(
        "SE1006",
        &[
            (
                "src/entry.ts",
                "import { calculate as relay } from './worker'; export function evaluate(req) { const capsule = { expression: req.params.expression }; const { expression: chosen } = capsule; return relay(chosen); }",
            ),
            (
                "src/worker.ts",
                "export function calculate(value) { return eval(value); }",
            ),
        ],
    )?;
    Ok(())
}

#[test]
fn sensitive_resource_and_multi_property_flows_retain_exact_field_identity()
-> Result<(), Box<dyn std::error::Error>> {
    assert_detected(
        "SE1007",
        &[(
            "app/actions/archive.ts",
            "'use server'; export async function archive(payload) { const capsule = { resource: payload.body.resource, decoration: 'fixed' }; const { resource: selected } = capsule; return archiveStore.delete(selected); }",
        )],
    )?;
    assert_detected(
        "SE1006",
        &[(
            "src/selected.ts",
            "export function evaluate(req) { const capsule = { expression: req.body.expression, audit: req.body.audit }; const { expression: selected } = capsule; return eval(selected); }",
        )],
    )?;
    assert_control(
        "SE1006",
        &[(
            "src/sibling.ts",
            "export function evaluate(req) { const capsule = { expression: req.body.expression, safe: '2 + 2' }; const { safe: selected } = capsule; return eval(selected); }",
        )],
    )?;
    Ok(())
}

#[test]
fn unsupported_object_and_pattern_shapes_never_invent_property_flow()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; const { other: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const key = req.query.key; const capsule = { [key]: req.body.expression }; const { expression: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const base = { expression: req.body.expression }; const capsule = { ...base }; const { expression: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; const { ...remaining } = capsule; return eval(remaining.expression); }",
        "export function evaluate(req) { const capsule = { expression: 'fixed', expression: req.body.expression }; const { expression: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; const { expression: selected = 'fixed' } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = { get expression() { return req.body.expression; } }; const { expression: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = { set expression(value) { void value; }, safe: req.body.expression }; const { safe: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = { expression() { return req.body.expression; } }; const { expression: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = { nested: [req.body.expression] }; const { nested: [selected] } = capsule; return eval(selected); }",
        "export function evaluate(req) { const key = req.query.key; const capsule = { expression: req.body.expression }; const { [key]: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = fabricate(req.body.expression); const { expression: selected } = capsule; return eval(selected); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control(
            "SE1006",
            &[(&format!("src/shape-control-{index}.ts"), source)],
        )?;
    }
    assert_control(
        "SE1006",
        &[
            (
                "src/ambiguous.ts",
                "import { fabricate } from './maker'; export function evaluate(req) { const capsule = fabricate(req.body.expression); const { expression: selected } = capsule; return eval(selected); }",
            ),
            (
                "src/maker.js",
                "export function fabricate(value) { return { expression: value }; }",
            ),
            (
                "src/maker.ts",
                "export function fabricate(value) { return { expression: value }; }",
            ),
        ],
    )?;
    Ok(())
}

#[test]
fn mutation_reassignment_and_shadowing_obey_extraction_time()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "export function evaluate(req) { let capsule = { expression: req.body.expression }; capsule = { expression: 'fixed' }; const { expression: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; capsule.expression = 'fixed'; const { expression: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; let { expression: selected } = capsule; selected = 'fixed'; return eval(selected); }",
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; { const capsule = { expression: 'fixed' }; const { expression: selected } = capsule; return eval(selected); } }",
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; const alias = capsule; const { expression: selected } = capsule; void alias; return eval(selected); }",
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; inspect(capsule); const { expression: selected } = capsule; return eval(selected); }",
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; capsule.refresh(); const { expression: selected } = capsule; return eval(selected); }",
        "export function evaluate(req, flag) { const capsule = { expression: req.body.expression }; if (flag) capsule[req.query.key] = 'fixed'; const { expression: selected } = capsule; return eval(selected); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control(
            "SE1006",
            &[(&format!("src/time-control-{index}.js"), source)],
        )?;
    }
    assert_detected(
        "SE1006",
        &[(
            "src/post-extraction.js",
            "export function evaluate(req) { const capsule = { expression: req.body.expression }; const { expression: selected } = capsule; capsule.expression = 'fixed'; return eval(selected); }",
        )],
    )?;
    Ok(())
}

#[test]
fn evidence_spans_fingerprints_and_metamorphic_renames_are_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let source = "export function evaluate(req) { const capsule = { expression: req.body.expression, safe: 'fixed' }; const { expression: selected } = capsule; return eval(selected); }";
    let repository = TempDir::new()?;
    fs::create_dir_all(repository.path().join("src"))?;
    fs::write(repository.path().join("src/evidence.ts"), source)?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    let first = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let second = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let matches = findings(&first, "SE1006");
    let finding = match matches.as_slice() {
        [finding] => *finding,
        _ => return Err(format!("expected one SE1006: {:#?}", first.findings).into()),
    };
    assert_eq!(first.report_fingerprint, second.report_fingerprint);
    assert_eq!(first.graph, second.graph);
    assert_eq!(first.findings, second.findings);
    let transformations = finding
        .transformations
        .iter()
        .map(|location| {
            &source[usize::try_from(location.span.start_byte).unwrap_or(0)
                ..usize::try_from(location.span.end_byte).unwrap_or(0)]
        })
        .collect::<Vec<_>>();
    assert!(
        transformations
            .iter()
            .any(|fragment| fragment.contains("expression: req.body.expression")),
        "missing property evidence: {transformations:?}"
    );
    assert!(
        transformations
            .iter()
            .any(|fragment| fragment.contains("expression: selected")),
        "missing destructuring evidence: {transformations:?}"
    );

    let renamed = scan(&[(
        "src/evidence.ts",
        "export function evaluate(req) { const envelope = { formula: req.body.expression, note: 'fixed' }; const { formula: chosen } = envelope; return eval(chosen); }",
    )])?;
    let renamed_finding = findings(&renamed, "SE1006")
        .into_iter()
        .next()
        .ok_or("renamed finding missing")?;
    assert_eq!(renamed_finding.rule_id, finding.rule_id);
    Ok(())
}

#[test]
fn current_cache_misses_v13_and_interprocedural_depth_remains_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::create_dir_all(repository.path().join("src"))?;
    fs::write(
        repository.path().join("src/cache.ts"),
        "export function evaluate(req) { const capsule = { expression: req.body.expression }; const { expression: selected } = capsule; return eval(selected); }",
    )?;
    let cache = TempDir::new()?;
    let stale = cache
        .path()
        .join("secure-parse-cache-v13/legacy/stale.json");
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
    assert!(cache.path().join("secure-parse-cache-v20").is_dir());
    assert!(warm.parsing.cache_hits > 0);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert_eq!(cold.facts, warm.facts);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.findings, warm.findings);

    fs::write(
        repository.path().join("src/cache.ts"),
        "const first = value => second(value); const second = value => third(value); const third = value => value; export function evaluate(req) { const capsule = { expression: req.body.expression }; const { expression: selected } = capsule; return eval(first(selected)); }",
    )?;
    request.configuration.parse_cache_enabled = false;
    request.configuration.max_interprocedural_depth = 1;
    let bounded = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert!(
        findings(&bounded, "SE1006").is_empty(),
        "{:#?}",
        bounded.findings
    );
    assert!(bounded.limitations.iter().any(|limitation| {
        limitation.code == "bounded-interprocedural-analysis"
            && limitation.message.contains("1 traversal levels")
    }));
    Ok(())
}
