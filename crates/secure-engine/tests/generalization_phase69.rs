//! Phase 6.9 Engine-owned vulnerable/control pairs for every disclosed cause class.

use std::fs;

use secure_engine::{CancellationToken, Finding, ScanReport, ScanRequest, scan_repository};
use tempfile::TempDir;

#[derive(Clone)]
struct Pair {
    cause: &'static str,
    language: &'static str,
    framework: &'static str,
    topology: &'static str,
    rule: &'static str,
    vulnerable: Vec<(&'static str, &'static str)>,
    control: Vec<(&'static str, &'static str)>,
    source_path: &'static str,
    source_fragment: &'static str,
    sink_path: &'static str,
    sink_prefix: &'static str,
}

fn scan(files: &[(&str, &str)]) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    for (relative, content) in files {
        let path = directory.path().join(relative);
        fs::create_dir_all(path.parent().ok_or("missing parent")?)?;
        fs::write(path, content)?;
    }
    let mut request = ScanRequest::new(directory.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

#[allow(clippy::too_many_lines)]
fn pairs() -> Vec<Pair> {
    vec![
        Pair {
            cause: "source-identity",
            language: "javascript",
            framework: "node",
            topology: "direct",
            rule: "SE1006",
            vulnerable: vec![(
                "src/evaluate.js",
                "export function handle(request) { const program = request.query.program; return eval(program); }",
            )],
            control: vec![(
                "src/evaluate.js",
                "export function handle(request) { const program = request.query.program; return JSON.parse(program); }",
            )],
            source_path: "src/evaluate.js",
            source_fragment: "request.query.program",
            sink_path: "src/evaluate.js",
            sink_prefix: "eval(",
        },
        Pair {
            cause: "source-span",
            language: "jsx",
            framework: "express",
            topology: "helper-mediated",
            rule: "SE1004",
            vulnerable: vec![(
                "src/proxy.jsx",
                "function relay(destination) { return fetch(destination); } function endpoint(req, res) { const destination = req.body.destination; return relay(destination); } router.post('/proxy', endpoint);",
            )],
            control: vec![(
                "src/proxy.jsx",
                "function relay(destination) { return fetch(safeUrl(destination)); } function endpoint(req, res) { const destination = req.body.destination; return relay(destination); } router.post('/proxy', endpoint);",
            )],
            source_path: "src/proxy.jsx",
            source_fragment: "req.body.destination",
            sink_path: "src/proxy.jsx",
            sink_prefix: "fetch(",
        },
        Pair {
            cause: "value-connectivity",
            language: "typescript",
            framework: "next-app-router",
            topology: "inter-file-aliased",
            rule: "SE1004",
            vulnerable: vec![
                (
                    "app/api/proxy/route.ts",
                    "import { relay as send } from './relay'; export async function POST(request: Request) { const payload = await request.json(); return send(payload.destination, 'audit'); }",
                ),
                (
                    "app/api/proxy/relay.ts",
                    "export function relay(destination: string, audit: string) { return fetch(destination); }",
                ),
            ],
            control: vec![
                (
                    "app/api/proxy/route.ts",
                    "import { relay as send } from './relay'; export async function POST(request: Request) { const payload = await request.json(); return send('https://api.example.test', payload.audit); }",
                ),
                (
                    "app/api/proxy/relay.ts",
                    "export function relay(destination: string, audit: string) { return fetch(destination); }",
                ),
            ],
            source_path: "app/api/proxy/route.ts",
            source_fragment: "request.json()",
            sink_path: "app/api/proxy/relay.ts",
            sink_prefix: "fetch(",
        },
        Pair {
            cause: "guard-recognition",
            language: "tsx",
            framework: "server-actions",
            topology: "control-flow-sensitive",
            rule: "SE1005",
            vulnerable: vec![(
                "app/actions/navigate.tsx",
                "'use server'; export async function navigate(form: FormData) { const destination = String(form.get('destination') ?? ''); if (destination.endsWith('/account')) console.info('familiar'); return redirect(destination); }",
            )],
            control: vec![(
                "app/actions/navigate.tsx",
                "'use server'; const ALLOWED = new Set(['/account']); export async function navigate(form: FormData) { const destination = String(form.get('destination') ?? ''); if (!ALLOWED.has(destination)) throw new Error('reject'); return redirect(destination); }",
            )],
            source_path: "app/actions/navigate.tsx",
            source_fragment: "form.get('destination')",
            sink_path: "app/actions/navigate.tsx",
            sink_prefix: "redirect(",
        },
        Pair {
            cause: "sanitizer-recognition",
            language: "javascript",
            framework: "node",
            topology: "helper-mediated",
            rule: "SE1004",
            vulnerable: vec![(
                "src/destination.js",
                "export function handle(request) { const target = request.body.target; const validated = safeUrl(target); return fetch(target); }",
            )],
            control: vec![(
                "src/destination.js",
                "export function handle(request) { const target = request.body.target; const validated = safeUrl(target); return fetch(validated); }",
            )],
            source_path: "src/destination.js",
            source_fragment: "request.body.target",
            sink_path: "src/destination.js",
            sink_prefix: "fetch(",
        },
        Pair {
            cause: "dominance-value-association",
            language: "jsx",
            framework: "express",
            topology: "control-flow-sensitive",
            rule: "SE1004",
            vulnerable: vec![(
                "src/dominance.jsx",
                "const ALLOWED = new Set(['https://api.example.test']); function endpoint(req, res) { const target = req.query.target; const response = fetch(target); if (!ALLOWED.has(target)) throw new Error('reject'); return response; } router.get('/proxy', endpoint);",
            )],
            control: vec![(
                "src/dominance.jsx",
                "const ALLOWED = new Set(['https://api.example.test']); function endpoint(req, res) { const target = req.query.target; if (!ALLOWED.has(target)) throw new Error('reject'); return fetch(target); } router.get('/proxy', endpoint);",
            )],
            source_path: "src/dominance.jsx",
            source_fragment: "req.query.target",
            sink_path: "src/dominance.jsx",
            sink_prefix: "fetch(",
        },
        Pair {
            cause: "overbroad-false-positive",
            language: "typescript",
            framework: "next-app-router",
            topology: "direct",
            rule: "SE1004",
            vulnerable: vec![(
                "app/api/forward/route.ts",
                "export async function POST(request: Request) { const payload = await request.json(); return fetch(payload.destination, { method: 'POST' }); }",
            )],
            control: vec![(
                "app/api/forward/route.ts",
                "export async function POST(request: Request) { const payload = await request.json(); return fetch('https://api.example.test', { method: 'POST', body: payload.audit }); }",
            )],
            source_path: "app/api/forward/route.ts",
            source_fragment: "request.json()",
            sink_path: "app/api/forward/route.ts",
            sink_prefix: "fetch(",
        },
    ]
}

fn one_finding<'a>(
    report: &'a ScanReport,
    pair: &Pair,
) -> Result<&'a Finding, Box<dyn std::error::Error>> {
    if report.findings.len() != 1 || report.findings[0].rule_id != pair.rule {
        return Err(format!(
            "{} expected exactly one {}, got {:?}",
            pair.cause,
            pair.rule,
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>()
        )
        .into());
    }
    Ok(&report.findings[0])
}

#[test]
fn independent_cause_pairs_are_exact_connected_and_balanced()
-> Result<(), Box<dyn std::error::Error>> {
    let pairs = pairs();
    let mut vulnerable = 0_usize;
    let mut controls = 0_usize;
    for pair in &pairs {
        let report = scan(&pair.vulnerable)?;
        let finding = one_finding(&report, pair)?;
        let source = finding.source.as_ref().ok_or("source missing")?;
        let sink = finding.sink.as_ref().ok_or("sink missing")?;
        assert_eq!(source.path, pair.source_path, "{} source path", pair.cause);
        assert_eq!(sink.path, pair.sink_path, "{} sink path", pair.cause);
        let source_text = pair
            .vulnerable
            .iter()
            .find_map(|(path, text)| (*path == pair.source_path).then_some(*text))
            .ok_or("source file missing")?;
        let expected_start = source_text
            .find(pair.source_fragment)
            .ok_or("source fragment missing")?;
        assert_eq!(
            source.span.start_byte,
            u64::try_from(expected_start)?,
            "{} source start",
            pair.cause
        );
        assert_eq!(
            source.span.end_byte,
            u64::try_from(expected_start + pair.source_fragment.len())?,
            "{} source end",
            pair.cause
        );
        let sink_text = pair
            .vulnerable
            .iter()
            .find_map(|(path, text)| (*path == pair.sink_path).then_some(*text))
            .ok_or("sink file missing")?;
        let sink_start = usize::try_from(sink.span.start_byte)?;
        assert!(
            sink_text[sink_start..].starts_with(pair.sink_prefix),
            "{} sink span",
            pair.cause
        );
        let contract = finding
            .evidence_contract_v2
            .as_ref()
            .ok_or("evidence contract missing")?;
        assert!(!contract.path.is_empty(), "{} empty path", pair.cause);
        assert_eq!(
            contract.connected_edges,
            vec![true; contract.path.len().saturating_sub(1)],
            "{} disconnected path",
            pair.cause
        );
        vulnerable += 1;

        let control = scan(&pair.control)?;
        assert!(
            control.findings.is_empty(),
            "{} control findings: {:?}",
            pair.cause,
            control
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>()
        );
        controls += 1;
    }
    assert_eq!((vulnerable, controls), (7, 7));
    Ok(())
}

#[test]
fn independent_matrix_covers_required_surfaces_and_topologies() {
    let pairs = pairs();
    for required in ["javascript", "jsx", "typescript", "tsx"] {
        assert!(pairs.iter().any(|pair| pair.language == required));
    }
    for required in ["node", "express", "next-app-router", "server-actions"] {
        assert!(pairs.iter().any(|pair| pair.framework == required));
    }
    for required in [
        "direct",
        "helper-mediated",
        "inter-file-aliased",
        "control-flow-sensitive",
    ] {
        assert!(pairs.iter().any(|pair| pair.topology == required));
    }
}
