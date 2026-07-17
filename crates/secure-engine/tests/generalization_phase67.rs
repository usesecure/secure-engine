//! Phase 6.7 Engine-owned generalization, mutation, and adversarial near-miss coverage.

use std::fs;
use std::path::Path;

use secure_engine::{
    CancellationToken, EVIDENCE_CONTRACT_VERSION, EvidenceContractRoleV2, ScanReport, ScanRequest,
    scan_repository,
};
use tempfile::TempDir;

const FAMILIES: [&str; 7] = [
    "SE1001", "SE1002", "SE1003", "SE1004", "SE1005", "SE1006", "SE1007",
];

fn operation(rule: &str, vulnerable: bool) -> &'static str {
    match (rule, vulnerable) {
        ("SE1001", true) => "return exec('status-tool --item ' + value);",
        ("SE1001", false) => {
            "return execFile('/usr/bin/status-tool', ['--item', value], { shell: false });"
        }
        ("SE1002", true) => {
            "return database.query(\"SELECT title FROM inventory WHERE code = '\" + value + \"'\");"
        }
        ("SE1002", false) => {
            "return database.query('SELECT title FROM inventory WHERE code = $1', [value]);"
        }
        ("SE1003", true) => "return fs.readFile('/srv/library/' + value, () => undefined);",
        ("SE1003", false) => "return fs.readFile(normalizeSafePath(value), () => undefined);",
        ("SE1004", true) => "return fetch(value);",
        ("SE1004", false) => "return fetch(safeUrl(value));",
        ("SE1005", true) => "return redirect(value);",
        ("SE1005", false) => "return redirect(safeRedirect(value));",
        ("SE1006", true) => "return eval(value);",
        ("SE1006", false) => "return eval(sanitizeCode(value));",
        ("SE1007", true) => "return accountStore.update(value);",
        ("SE1007", false) => {
            "requireRolePermission(actor, value); return accountStore.update(value);"
        }
        _ => "",
    }
}

fn prelude(rule: &str) -> &'static str {
    match rule {
        "SE1001" => "import { exec, execFile } from 'node:child_process';\n",
        "SE1003" => "import fs from 'node:fs';\n",
        "SE1007" => "'use server';\n",
        _ => "",
    }
}

fn body(rule: &str, vulnerable: bool) -> String {
    let operation = operation(rule, vulnerable);
    if rule == "SE1007" {
        operation.replace("actor", "context.actor")
    } else {
        operation.into()
    }
}

fn scenario_files(rule: &str, vulnerable: bool, variant: usize) -> Vec<(String, String)> {
    let operation = body(rule, vulnerable);
    let prefix = prelude(rule);
    match variant {
        0 => vec![(
            "src/endpoint.js".into(),
            format!(
                "{prefix}export function receive(request) {{ const context = request; const value = request.query.item; {operation} }}\n"
            ),
        )],
        1 => vec![(
            "src/router.ts".into(),
            format!(
                "{prefix}function consume(value, context) {{ {operation} }}\nexport function receive(request, response) {{ return consume(request.body.item, request); }}\n"
            ),
        )],
        2 => vec![(
            "src/controller.js".into(),
            format!(
                "{prefix}const consume = (value, context) => {{ {operation} }};\nexport function receive(req, res) {{ const inserted = 17; return consume(req.params.item, req); }}\n"
            ),
        )],
        3 => vec![(
            "app/api/items/route.ts".into(),
            format!(
                "{prefix}export async function POST(request: Request) {{ const context = request; const value = new URL(request.url).searchParams.get('item') ?? ''; {operation} }}\n"
            ),
        )],
        4 => vec![(
            "app/actions/submit.js".into(),
            format!(
                "'use server';\n{prefix}export async function submit(form) {{ const context = form; const value = String(form.get('item') ?? ''); {operation} }}\n"
            ),
        )],
        5 => vec![(
            "src/renamed.ts".into(),
            format!(
                "{prefix}export function receive(inbound) {{ const context = inbound; const selected = inbound.headers['x-item']; const value = selected; {operation} }}\n"
            ),
        )],
        6 => vec![(
            "src/wrapped.js".into(),
            format!(
                "{prefix}function consume(value, context) {{ {operation} }}\nfunction bridge(value, context) {{ return consume(value, context); }}\nexport function receive(req) {{ return bridge(req.query.item, req); }}\n"
            ),
        )],
        7 => vec![
            (
                "app/api/catalog/route.ts".into(),
                "import { consume } from './worker';\nexport async function GET(request: Request) { const value = new URL(request.url).searchParams.get('item') ?? ''; return consume(value, request); }\n".into(),
            ),
            (
                "app/api/catalog/worker.ts".into(),
                format!("{prefix}export function consume(value, context) {{ {operation} }}\n"),
            ),
        ],
        8 => vec![(
            "src/metamorphic.js".into(),
            format!(
                "{prefix}export function receive(request) {{ const harmless = 'inserted statement'; const context = request; let renamed = request.body.item; renamed = renamed; const value = renamed; {operation} }}\n"
            ),
        )],
        9 => vec![(
                "app/actions/controlled.ts".into(),
                format!(
                "'use server';\n{prefix}function consume(value, context) {{ if (!value) return; {operation} }}\nexport async function submit(form: FormData) {{ const selected = String(form.get('item') ?? ''); return consume(selected, form); }}\n"
            ),
        )],
        _ => Vec::new(),
    }
}

fn write_scenario(
    directory: &Path,
    files: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    for (relative, content) in files {
        let path = directory.join(relative);
        fs::create_dir_all(path.parent().ok_or("scenario parent missing")?)?;
        fs::write(path, content)?;
    }
    Ok(())
}

fn scan(files: &[(String, String)]) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    write_scenario(directory.path(), files)?;
    let mut request = ScanRequest::new(directory.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

#[test]
fn independent_matrix_has_ten_vulnerable_and_ten_safe_scenarios_per_family()
-> Result<(), Box<dyn std::error::Error>> {
    let mut vulnerable_count = 0_usize;
    let mut safe_count = 0_usize;
    let mut javascript = 0_usize;
    let mut typescript = 0_usize;
    for rule in FAMILIES {
        for variant in 0..10 {
            for vulnerable in [true, false] {
                let files = scenario_files(rule, vulnerable, variant);
                if files.iter().any(|(path, _)| {
                    Path::new(path)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("js"))
                }) {
                    javascript = javascript.saturating_add(1);
                } else {
                    typescript = typescript.saturating_add(1);
                }
                let report = scan(&files)?;
                let matching = report
                    .findings
                    .iter()
                    .filter(|finding| finding.rule_id == rule)
                    .collect::<Vec<_>>();
                if vulnerable {
                    vulnerable_count = vulnerable_count.saturating_add(1);
                    assert_eq!(
                        matching.len(),
                        1,
                        "independent vulnerable {rule} variant {variant}: {:?}",
                        report
                            .findings
                            .iter()
                            .map(|finding| finding.rule_id.as_str())
                            .collect::<Vec<_>>()
                    );
                    let contract = matching[0]
                        .evidence_contract_v2
                        .as_ref()
                        .ok_or("contract projection missing")?;
                    assert_eq!(contract.contract_version, EVIDENCE_CONTRACT_VERSION);
                    assert_eq!(
                        contract.path.first().ok_or("source missing")?.role,
                        EvidenceContractRoleV2::Source
                    );
                    assert_eq!(
                        contract.path.last().ok_or("sink missing")?.role,
                        EvidenceContractRoleV2::Sink
                    );
                } else {
                    safe_count = safe_count.saturating_add(1);
                    assert!(
                        matching.is_empty(),
                        "independent safe {rule} variant {variant} emitted {rule}"
                    );
                }
                assert!(!report.analysis.truncated);
                assert!(report.analysis.nodes < 512);
                assert!(report.analysis.edges < 1024);
            }
        }
    }
    assert_eq!((vulnerable_count, safe_count), (70, 70));
    assert_eq!(javascript, typescript);
    Ok(())
}

#[test]
fn adversarial_near_misses_do_not_become_false_barriers() -> Result<(), Box<dyn std::error::Error>>
{
    let cases = [
        (
            "SE1003",
            "export function receive(request) { const candidate = path.resolve('/srv/data', request.query.item); if (!candidate.startsWith('/srv/data')) throw new Error('reject'); return fs.readFile(candidate, () => undefined); }",
        ),
        (
            "SE1004",
            "export function receive(request) { const target = new URL(request.query.item); if (target.hostname.endsWith('.example.test')) return fetch(target); throw new Error('reject'); }",
        ),
        (
            "SE1004",
            "export function receive(request) { const target = new URL(request.query.item); if (target.protocol !== request.query.protocol || target.hostname !== request.query.host) throw new Error('reject'); return fetch(target); }",
        ),
        (
            "SE1005",
            "const BLOCKED = new Set(['https://evil.invalid']); export function receive(request) { const value = request.query.item; if (BLOCKED.has(value)) throw new Error('reject'); return redirect(value); }",
        ),
        (
            "SE1007",
            "'use server'; export async function change(payload) { if (!payload.actor || payload.actor.scope !== 'admin') throw new Error('reject'); return accountStore.update(payload.change); }",
        ),
    ];
    for (rule, source) in cases {
        let report = scan(&[("scenario.ts".into(), source.into())])?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule),
            "adversarial near miss suppressed {rule}"
        );
    }
    Ok(())
}

#[test]
fn disconnected_and_fixed_sinks_remain_clean_while_guard_removal_flips_results()
-> Result<(), Box<dyn std::error::Error>> {
    let disconnected = scan(&[(
        "scenario.ts".into(),
        "export function receive(request) { const observed = request.query.item; return fetch('https://api.example.test/status'); }".into(),
    )])?;
    assert!(disconnected.findings.is_empty());

    for rule in FAMILIES {
        let safe = scan(&scenario_files(rule, false, 6))?;
        let vulnerable = scan(&scenario_files(rule, true, 6))?;
        assert!(!safe.findings.iter().any(|finding| finding.rule_id == rule));
        assert!(
            vulnerable
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule)
        );
    }
    Ok(())
}

#[test]
fn recursion_cycles_ambiguous_aliases_and_malformed_syntax_remain_bounded_and_private()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let absolute_root = directory.path().to_string_lossy().into_owned();
    write_scenario(
        directory.path(),
        &[
            (
                "src/cycle.ts".into(),
                "function first(value) { return second(value); } function second(value) { return first(value); } export function receive(request) { return first(request.query.item); }".into(),
            ),
            (
                "src/ambiguous.ts".into(),
                "export function receive(request) { const operation = request.query.mode ? eval : fetch; return operation(request.query.item); }".into(),
            ),
            (
                "src/malformed.ts".into(),
                "export function broken( { return fetch(request.query.item".into(),
            ),
        ],
    )?;
    let mut request = ScanRequest::new(directory.path());
    request.configuration.parse_cache_enabled = false;
    request.configuration.max_interprocedural_depth = 3;
    request.configuration.max_graph_nodes = 256;
    request.configuration.max_graph_edges = 512;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert!(report.graph.nodes.len() <= 256);
    assert!(report.graph.edges.len() <= 512);
    assert!(report.limitations.iter().any(|limitation| {
        limitation.code == "dynamic-resolution-limited"
            && limitation.message.contains("recursion")
            && limitation.message.contains("unresolved calls")
    }));
    let serialized = serde_json::to_string(&report)?;
    assert!(!serialized.contains(&absolute_root));
    assert!(!serialized.contains("/tmp/"));

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(scan_repository(&request, &cancelled, |_| {}).is_err());
    Ok(())
}
