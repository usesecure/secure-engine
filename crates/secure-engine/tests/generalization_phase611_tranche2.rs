//! Phase 6.11 tranche 2 independent dynamic-callee and filesystem fixtures.

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

fn count(report: &ScanReport, rule: &str) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule)
        .count()
}

fn assert_detected(rule: &str, files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert!(
        count(&report, rule) > 0,
        "expected {rule}; files={files:?}; findings={:#?}",
        report.findings
    );
    Ok(())
}

fn assert_control(rule: &str, files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert_eq!(
        count(&report, rule),
        0,
        "unexpected {rule}; findings={:#?}",
        report.findings
    );
    Ok(())
}

#[test]
fn final_sequence_callee_reaches_only_unshadowed_dynamic_code_sinks()
-> Result<(), Box<dyn std::error::Error>> {
    let vulnerable = [
        (
            "src/ledger.js",
            "export function ingest(req) { return (0, eval)(req.body.program); }",
        ),
        (
            "src/panel.jsx",
            "export function receive(req) { const text = req.query.expression; return ((void 0, (eval)))(text); }",
        ),
        (
            "src/runner.ts",
            "const interpreter = eval; export function execute(req: any) { const payload = String(req.body.payload ?? ''); return (false, interpreter)(payload); }",
        ),
        (
            "app/actions/compile.tsx",
            "'use server'; function relay(fragment: string) { const marker = 17; void marker; return (null, eval)(fragment); } export async function compile(form: FormData) { const fragment = String(form.get('fragment') ?? ''); return relay(fragment); }",
        ),
    ];
    for (path, source) in vulnerable {
        assert_detected("SE1006", &[(path, source)])?;
    }
    let normalized = scan(&[(
        "src/normalized.js",
        "export function handle(req) { return (0, eval)(req.body.program); }",
    )])?;
    assert!(
        normalized
            .facts
            .iter()
            .any(|fact| fact.kind == "dynamic-code-execution")
    );

    assert_detected(
        "SE1006",
        &[
            (
                "app/api/interpret/route.ts",
                "import { interpret as invoke } from './worker'; export async function POST(request: Request) { const packet = await request.json(); const fragment = String(packet.fragment ?? ''); return invoke(fragment); }",
            ),
            (
                "app/api/interpret/worker.ts",
                "export function interpret(fragment: string) { return (undefined, eval)(fragment); }",
            ),
        ],
    )?;
    Ok(())
}

#[test]
fn shadowing_nonfinal_members_and_reassignment_are_not_dynamic_sinks()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "function eval(value) { return value; } export function ingest(req) { return (0, eval)(req.body.program); }",
        "export function ingest(req, eval) { return (0, eval)(req.body.program); }",
        "export function ingest(req) { return (eval, parseExpression)(req.body.program); }",
        "export function ingest(req) { return (0, utilities.eval)(req.body.program); }",
        "export function ingest(req) { return (0, utilities[req.query.member])(req.body.program); }",
        "export function ingest(req) { let interpreter = eval; interpreter = parseExpression; return (0, interpreter)(req.body.program); }",
        "function eval(value) { return value; } const interpreter = eval; export function ingest(req) { return (0, interpreter)(req.body.program); }",
        "export function ingest(req) { return (0, eval)(req.body.program); } function eval(value) { return value; }",
        "export function ingest(req) { const text = 'eval'; /* eval(req.body.program) */ return parseExpression(text); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        let report = scan(&[(&format!("src/control-{index}.tsx"), source)])?;
        assert_eq!(count(&report, "SE1006"), 0, "{:#?}", report.findings);
        assert!(
            report
                .facts
                .iter()
                .all(|fact| fact.kind != "dynamic-code-execution"),
            "shadowed or ambiguous evaluator leaked into normalized facts"
        );
    }
    Ok(())
}

#[test]
fn dynamic_sequence_keeps_argument_position_sanitizer_and_metamorphic_behavior()
-> Result<(), Box<dyn std::error::Error>> {
    assert_control(
        "SE1006",
        &[(
            "src/constant.js",
            "export function ingest(req) { void req.body.audit; return (0, eval)('6 * 7'); }",
        )],
    )?;
    assert_control(
        "SE1006",
        &[(
            "src/position.ts",
            "export function ingest(req: any) { return (0, eval)('6 * 7', req.body.decoy); }",
        )],
    )?;
    assert_control(
        "SE1006",
        &[(
            "src/filtered.tsx",
            "export function ingest(req: any) { const fragment = sanitizeCode(req.body.fragment); return (0, eval)(fragment); }",
        )],
    )?;
    for source in [
        "export function ingest(req) { const fragment = req.body.fragment; return (0, eval)(fragment); }",
        "export function ingest(message) { const note = 9; void note; const expression = message.body.fragment; return (true, eval)(expression); }",
    ] {
        assert_detected("SE1006", &[("src/metamorphic.jsx", source)])?;
    }
    Ok(())
}

#[test]
fn composed_paths_reach_filesystem_sinks_across_supported_topologies()
-> Result<(), Box<dyn std::error::Error>> {
    assert_detected(
        "SE1003",
        &[(
            "src/archive.js",
            "import { readFile } from 'node:fs'; import { join } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function fetchRecord(req) { const leaf = req.params.leaf; const candidate = join(CABINET, leaf); return readFile(candidate, () => undefined); }",
        )],
    )?;
    assert_detected(
        "SE1003",
        &[(
            "src/archive.jsx",
            "import { readFile } from 'node:fs'; import path from 'node:path'; const CABINET = '/var/lib/cabinet'; function compose(piece) { const forwarded = piece; return path.resolve(CABINET, forwarded); } function fetchRecord(req) { const selected = req.body.leaf; const candidate = compose(selected); return readFile(candidate, () => undefined); } router.post('/records/open', fetchRecord);",
        )],
    )?;
    assert_detected(
        "SE1003",
        &[
            (
                "app/api/records/route.ts",
                "import { openRecord } from './reader'; export async function POST(request: Request) { const packet = await request.json(); const leaf = String(packet.leaf ?? ''); const alias = leaf; return openRecord(alias); }",
            ),
            (
                "app/api/records/reader.ts",
                "import { readFile } from 'node:fs/promises'; import { resolve } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function openRecord(piece: string) { const candidate = resolve(CABINET, piece); return readFile(candidate, 'utf8'); }",
            ),
        ],
    )?;
    assert_detected(
        "SE1003",
        &[(
            "app/actions/open.tsx",
            "'use server'; import { readFile } from 'node:fs/promises'; import { normalize, join } from 'node:path'; const CABINET = '/var/lib/cabinet'; export async function open(form: FormData) { const leaf = String(form.get('leaf') ?? ''); const preview = leaf.slice(0, 2); if (preview.length > leaf.length) throw new Error('unreachable'); const candidate = normalize(join(CABINET, leaf)); return readFile(candidate, 'utf8'); }",
        )],
    )?;
    Ok(())
}

#[test]
fn exact_composed_path_confinement_requires_trusted_root_boundary_and_same_value()
-> Result<(), Box<dyn std::error::Error>> {
    let exact = "import { readFile, realpath } from 'node:fs/promises'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export async function open(req) { const base = await realpath(CABINET); const candidate = await realpath(resolve(base, req.params.leaf)); if (candidate !== base && !candidate.startsWith(base + sep)) throw new Error('outside'); return readFile(candidate, 'utf8'); }";
    assert_control("SE1003", &[("src/exact.ts", exact)])?;

    let alias = "import { readFile, realpath } from 'node:fs/promises'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export async function open(req) { const base = await realpath(CABINET); const candidate = await realpath(resolve(base, req.params.leaf)); if (!candidate.startsWith(base + sep)) return null; const approved = candidate; return readFile(approved, 'utf8'); }";
    assert_control("SE1003", &[("src/alias.jsx", alias)])?;

    let near_misses = [
        "import { readFile } from 'node:fs'; import { resolve } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function open(req) { const candidate = resolve(CABINET, req.params.leaf); if (!candidate.startsWith(CABINET)) throw new Error('outside'); return readFile(candidate, () => undefined); }",
        "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; export function open(req) { const base = resolve(req.body.root); const candidate = resolve(base, req.body.leaf); if (!candidate.startsWith(base + sep)) throw new Error('outside'); return readFile(candidate, () => undefined); }",
        "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function open(req) { const candidate = resolve(CABINET, req.params.leaf); const other = resolve(CABINET, req.params.other); if (!candidate.startsWith(CABINET + sep)) throw new Error('outside'); return readFile(other, () => undefined); }",
        "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function open(req) { const candidate = resolve(CABINET, req.params.leaf); const result = readFile(candidate, () => undefined); if (!candidate.startsWith(CABINET + sep)) throw new Error('late'); return result; }",
        "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function open(req) { const candidate = resolve(CABINET, req.params.leaf); try { if (!candidate.startsWith(CABINET + sep)) throw new Error('outside'); } catch { console.warn('continuing'); } return readFile(candidate, () => undefined); }",
        "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function open(req) { let candidate = resolve(CABINET, req.params.leaf); if (!candidate.startsWith(CABINET + sep)) throw new Error('outside'); candidate = resolve('/tmp', req.params.leaf); return readFile(candidate, () => undefined); }",
        "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; export function open(req) { const base = resolve('/var/lib/cabinet', req.body.root); const candidate = resolve(base, req.body.leaf); if (!candidate.startsWith(base + sep)) throw new Error('outside'); return readFile(candidate, () => undefined); }",
        "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function open(req) { const candidate = choosePath(req.params.leaf, resolve(CABINET, 'fixed')); if (!candidate.startsWith(CABINET + sep)) throw new Error('outside'); return readFile(candidate, () => undefined); }",
        "import { readFile } from 'node:fs'; import { sep } from 'node:path'; const path = { resolve: (base, leaf) => base + sep + leaf }; const CABINET = '/var/lib/cabinet'; export function open(req) { const candidate = path.resolve(CABINET, req.params.leaf); if (!candidate.startsWith(CABINET + sep)) throw new Error('outside'); return readFile(candidate, () => undefined); }",
        "import { readFile } from 'node:fs'; import path, { sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function open(req) { const candidate = utilities.path.resolve(CABINET, req.params.leaf); if (!candidate.startsWith(CABINET + sep)) throw new Error('outside'); return readFile(candidate, () => undefined); }",
        "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function open(req) { const candidate = resolve(CABINET, req.params.leaf); if (!candidate.includes('..') && !candidate.endsWith('.key')) return readFile(candidate, () => undefined); return readFile(resolve('/tmp', req.params.leaf), () => undefined); }",
    ];
    for (index, source) in near_misses.into_iter().enumerate() {
        assert_detected("SE1003", &[(&format!("src/near-miss-{index}.tsx"), source)])?;
    }
    Ok(())
}

#[test]
fn helper_confinement_is_value_bound_and_runtime_limits_remain_explicit()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan(&[
        (
            "src/entry.tsx",
            "import { readFile } from 'node:fs/promises'; import { confine } from './boundary'; export async function open(req: any) { const leaf = String(req.body.leaf ?? ''); const candidate = await confine(leaf); return readFile(candidate, 'utf8'); }",
        ),
        (
            "src/boundary.ts",
            "import { realpath } from 'node:fs/promises'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export async function confine(piece: string) { const base = await realpath(CABINET); const candidate = await realpath(resolve(base, piece)); if (candidate !== base && !candidate.startsWith(base + sep)) throw new Error('outside'); return candidate; }",
        ),
    ])?;
    assert_eq!(count(&report, "SE1003"), 0, "{:#?}", report.findings);
    assert!(report.limitations.iter().any(|limitation| {
        limitation.code == "filesystem-symlink-safety-not-proven"
            && limitation.message.contains("race")
            && limitation.message.contains("mount")
    }));

    assert_detected(
        "SE1003",
        &[(
            "src/deceptive.js",
            "import { readFile } from 'node:fs'; import { resolve, sep } from 'node:path'; const CABINET = '/var/lib/cabinet'; export function open(req) { const harmlessName = resolve(CABINET, req.params.leaf); if (!harmlessName.startsWith(CABINET + sep)) console.warn('outside'); return readFile(harmlessName, () => undefined); }",
        )],
    )?;
    Ok(())
}
