//! Phase 6.9 independent value-identity, span, barrier, and near-miss regressions.

use std::fs;
use std::path::Path;

use secure_engine::{
    CacheControl, CancellationToken, EvidenceSourceKindV2, Finding, ScanReport, ScanRequest,
    scan_repository,
};
use tempfile::TempDir;

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

fn finding<'a>(report: &'a ScanReport, rule: &str) -> Result<&'a Finding, String> {
    let matches = report
        .findings
        .iter()
        .filter(|candidate| candidate.rule_id == rule)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [finding] => Ok(finding),
        _ => Err(format!(
            "expected one {rule} finding, got {}",
            matches.len()
        )),
    }
}

fn exact_fragment_span(
    finding: &Finding,
    path: &str,
    source: &str,
    fragment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let location = finding.source.as_ref().ok_or("source missing")?;
    let start = source.find(fragment).ok_or("fragment missing")?;
    let end = start.saturating_add(fragment.len());
    let line = u32::try_from(
        source[..start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1,
    )?;
    let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
    let column = u32::try_from(source[line_start..start].chars().count() + 1)?;
    assert_eq!(location.path, path);
    assert_eq!(location.span.start_byte, u64::try_from(start)?);
    assert_eq!(location.span.end_byte, u64::try_from(end)?);
    assert_eq!(location.span.start_line, line);
    assert_eq!(location.span.start_column, column);
    Ok(())
}

#[test]
fn sources_retain_exact_identity_and_expression_spans_through_supported_topologies()
-> Result<(), Box<dyn std::error::Error>> {
    let express = "import { exec } from 'node:child_process';\nfunction consume(note, command) { return exec('lookup ' + command); }\nfunction endpoint(req, res) { const { note, command: selected } = req.body; return consume(note, selected); }\nrouter.post('/jobs', endpoint);\n";
    let report = scan(&[("src/router.jsx", express)])?;
    let express_finding = finding(&report, "SE1001")?;
    exact_fragment_span(
        express_finding,
        "src/router.jsx",
        express,
        "command: selected",
    )?;
    assert_eq!(
        express_finding
            .evidence_contract_v2
            .as_ref()
            .and_then(|contract| contract.path.first())
            .and_then(|step| step.source_kind.clone()),
        Some(EvidenceSourceKindV2::HttpBodyField)
    );

    let next = "export async function POST(request: Request) {\n  const payload = await request.json();\n  const target = payload.target;\n  return fetch(target);\n}\n";
    let report = scan(&[("app/api/proxy/route.ts", next)])?;
    let next_finding = finding(&report, "SE1004")?;
    exact_fragment_span(
        next_finding,
        "app/api/proxy/route.ts",
        next,
        "request.json()",
    )?;
    assert_eq!(
        next_finding
            .evidence_contract_v2
            .as_ref()
            .and_then(|contract| contract.path.first())
            .and_then(|step| step.source_kind.clone()),
        Some(EvidenceSourceKindV2::HttpBodyField)
    );

    let action = "'use server';\nexport async function submit(form: FormData) {\n  const destination = String(form.get('destination') ?? '');\n  return redirect(destination);\n}\n";
    let report = scan(&[("app/actions/submit.tsx", action)])?;
    let action_finding = finding(&report, "SE1005")?;
    exact_fragment_span(
        action_finding,
        "app/actions/submit.tsx",
        action,
        "form.get('destination')",
    )?;
    assert_eq!(
        action_finding
            .evidence_contract_v2
            .as_ref()
            .and_then(|contract| contract.path.first())
            .and_then(|step| step.source_kind.clone()),
        Some(EvidenceSourceKindV2::FormDataValue)
    );
    Ok(())
}

#[test]
fn sink_argument_positions_and_helper_parameters_do_not_cross_connect_values()
-> Result<(), Box<dyn std::error::Error>> {
    let safe_cases = [
        "export function handle(req) { return fetch('https://api.example.test', { body: req.body.payload }); }",
        "export function handle(req) { return redirect('/account', req.query.next); }",
        "export function handle(req) { return fs.readFile('/srv/fixed.txt', { signal: req.body.signal }, () => undefined); }",
        "export function handle(req) { return eval('2 + 2', req.body.code); }",
        "function consume(clean, risky) { return eval(clean); } export function handle(req) { return consume('2 + 2', req.body.code); }",
    ];
    for source in safe_cases {
        assert!(
            scan(&[("src/safe.ts", source)])?.findings.is_empty(),
            "{source}"
        );
    }

    let vulnerable = "function consume(risky, clean) { return eval(risky); } export function handle(req) { return consume(req.body.code, '2 + 2'); }";
    let report = scan(&[("src/unsafe.ts", vulnerable)])?;
    finding(&report, "SE1006")?;

    let function_constructor =
        "export function handle(req) { return new Function('input', req.body.code); }";
    finding(
        &scan(&[("src/function-constructor.ts", function_constructor)])?,
        "SE1006",
    )?;

    let second_path = "export function handle(req) { return fs.rename('/srv/fixed.txt', req.body.target, () => undefined); }";
    finding(&scan(&[("src/second-path.ts", second_path)])?, "SE1003")?;

    let nonsensitive_content = "export function handle(req) { return fs.writeFile('/srv/fixed.txt', req.body.content, () => undefined); }";
    assert!(
        scan(&[("src/nonsensitive-content.ts", nonsensitive_content)])?
            .findings
            .is_empty()
    );

    let destructured_safe = "function consume({ code, audit }) { return eval(code); } export function handle(req) { return consume({ code: '2 + 2', audit: req.body.audit }); }";
    assert!(
        scan(&[("src/destructured-safe.tsx", destructured_safe)])?
            .findings
            .is_empty()
    );

    let destructured_vulnerable = "function consume({ code: program, audit }) { return eval(program); } export function handle(req) { return consume({ code: req.body.code, audit: 'fixed' }); }";
    finding(
        &scan(&[("src/destructured-vulnerable.tsx", destructured_vulnerable)])?,
        "SE1006",
    )?;

    let worker = "export function consume({ code, audit }: { code: string; audit: string }) { return eval(code); }";
    let inter_file_safe = "import { consume as relay } from './worker'; export async function POST(request: Request) { const payload = await request.json(); return relay({ code: '2 + 2', audit: payload.audit }); }";
    assert!(
        scan(&[
            ("app/api/evaluate/route.ts", inter_file_safe),
            ("app/api/evaluate/worker.ts", worker),
        ])?
        .findings
        .is_empty()
    );
    let inter_file_vulnerable = "import { consume as relay } from './worker'; export async function POST(request: Request) { const payload = await request.json(); return relay({ code: payload.code, audit: 'fixed' }); }";
    let inter_file_report = scan(&[
        ("app/api/evaluate/route.ts", inter_file_vulnerable),
        ("app/api/evaluate/worker.ts", worker),
    ])?;
    finding(&inter_file_report, "SE1006")?;
    Ok(())
}

#[test]
fn barriers_must_dominate_and_protect_the_same_current_value()
-> Result<(), Box<dyn std::error::Error>> {
    let safe = "const ALLOWED = new Set(['https://api.example.test']); export function handle(req) { const target = req.body.target; if (!ALLOWED.has(target)) throw new Error('reject'); return fetch(target); }";
    assert!(scan(&[("src/safe.js", safe)])?.findings.is_empty());

    let wrong_value = "const ALLOWED = new Set(['https://api.example.test']); export function handle(req) { const target = req.body.target; const decoy = req.body.decoy; if (!ALLOWED.has(decoy)) throw new Error('reject'); return fetch(target); }";
    finding(&scan(&[("src/wrong-value.js", wrong_value)])?, "SE1004")?;

    let after_sink = "const ALLOWED = new Set(['https://api.example.test']); export function handle(req) { const target = req.body.target; const result = fetch(target); if (!ALLOWED.has(target)) throw new Error('reject'); return result; }";
    finding(&scan(&[("src/after.js", after_sink)])?, "SE1004")?;

    let transformed_safe = "export function handle(req) { const target = req.body.target; const safe = safeUrl(target); return fetch(safe); }";
    assert!(
        scan(&[("src/transformed-safe.js", transformed_safe)])?
            .findings
            .is_empty()
    );

    let original_unsafe = "export function handle(req) { const target = req.body.target; const safe = safeUrl(target); return fetch(target); }";
    finding(
        &scan(&[("src/original-unsafe.js", original_unsafe)])?,
        "SE1004",
    )?;

    let authorization_safe = "'use server'; export async function change(request) { const target = request.body.target; enforceOwnership(currentUser(), target); return recordStore.update(target); }";
    assert!(
        scan(&[("app/actions/authorization-safe.ts", authorization_safe)])?
            .findings
            .is_empty()
    );

    let authorization_wrong_value = "'use server'; export async function change(request) { const target = request.body.target; const decoy = request.body.decoy; enforceOwnership(currentUser(), decoy); return recordStore.update(target); }";
    finding(
        &scan(&[(
            "app/actions/authorization-wrong-value.ts",
            authorization_wrong_value,
        )])?,
        "SE1007",
    )?;

    let relay = "export function relay(destination: string) { return fetch(destination); }";
    let guarded_caller = "import { relay } from './relay'; const ALLOWED = new Set(['https://api.example.test']); export async function POST(request: Request) { const payload = await request.json(); const destination = payload.destination; if (!ALLOWED.has(destination)) throw new Error('reject'); return relay(destination); }";
    assert!(
        scan(&[
            ("app/api/guarded/route.ts", guarded_caller),
            ("app/api/guarded/relay.ts", relay),
        ])?
        .findings
        .is_empty()
    );
    let wrong_guarded_caller = "import { relay } from './relay'; const ALLOWED = new Set(['https://api.example.test']); export async function POST(request: Request) { const payload = await request.json(); const destination = payload.destination; const decoy = payload.decoy; if (!ALLOWED.has(decoy)) throw new Error('reject'); return relay(destination); }";
    finding(
        &scan(&[
            ("app/api/guarded/route.ts", wrong_guarded_caller),
            ("app/api/guarded/relay.ts", relay),
        ])?,
        "SE1004",
    )?;

    let mutation = "export function mutate(target: string) { return recordStore.update(target); }";
    let authorized_caller = "'use server'; import { mutate as relay } from './mutation'; export async function change(request) { const target = request.body.target; enforceOwnership(currentUser(), target); return relay(target); }";
    assert!(
        scan(&[
            ("app/actions/authorized.ts", authorized_caller),
            ("app/actions/mutation.ts", mutation),
        ])?
        .findings
        .is_empty()
    );
    let wrong_authorized_caller = "'use server'; import { mutate as relay } from './mutation'; export async function change(request) { const target = request.body.target; const decoy = request.body.decoy; enforceOwnership(currentUser(), decoy); return relay(target); }";
    finding(
        &scan(&[
            ("app/actions/authorized.ts", wrong_authorized_caller),
            ("app/actions/mutation.ts", mutation),
        ])?,
        "SE1007",
    )?;
    Ok(())
}

#[test]
fn aliases_are_function_scoped_and_reassignment_does_not_inherit_stale_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let scoped = "function unsafeHandler(req) { const payload = req.body; return eval(payload.code); } function safeHandler(req) { const payload = config.defaults; return JSON.parse(payload.code); } router.post('/unsafe', unsafeHandler); router.post('/safe', safeHandler);";
    finding(&scan(&[("src/scoped.jsx", scoped)])?, "SE1006")?;

    let reassigned = "export function handle(req) { let payload = req.body; payload = config.defaults; return eval(payload.code); }";
    assert!(
        scan(&[("src/reassigned.jsx", reassigned)])?
            .findings
            .is_empty()
    );

    let conditional_reassignment = "export function handle(req) { let payload = req.body; if (req.query.useDefaults) payload = config.defaults; return eval(payload.code); }";
    finding(
        &scan(&[("src/conditional-reassignment.jsx", conditional_reassignment)])?,
        "SE1006",
    )?;
    Ok(())
}

#[test]
fn multiple_valid_sources_use_the_earliest_exact_expression_as_stable_tie_breaker()
-> Result<(), Box<dyn std::error::Error>> {
    let source = "export function handle(req) { const first = req.query.first; const second = req.body.second; return eval(first + second); }";
    let result = scan(&[("src/tie.ts", source)])?;
    let selected = finding(&result, "SE1006")?;
    exact_fragment_span(selected, "src/tie.ts", source, "req.query.first")?;
    assert_eq!(
        selected
            .evidence_contract_v2
            .as_ref()
            .and_then(|contract| contract.path.first())
            .and_then(|step| step.source_kind.clone()),
        Some(EvidenceSourceKindV2::HttpQueryValue)
    );
    Ok(())
}

#[test]
fn harmless_renames_and_insertions_preserve_semantics_but_barrier_mutations_flip_outcomes()
-> Result<(), Box<dyn std::error::Error>> {
    let base =
        "export function handle(req) { const target = req.query.target; return fetch(target); }";
    let renamed = "export function handle(incoming) { const harmless = 17; const destination = incoming.query.target; return fetch(destination); }";
    let left = finding(&scan(&[("src/base.ts", base)])?, "SE1004")?.clone();
    let right = finding(&scan(&[("src/renamed.ts", renamed)])?, "SE1004")?.clone();
    assert_eq!(left.semantic_fingerprint, right.semantic_fingerprint);
    assert_eq!(
        left.evidence_contract_v2
            .as_ref()
            .map(|contract| &contract.fingerprint),
        right
            .evidence_contract_v2
            .as_ref()
            .map(|contract| &contract.fingerprint)
    );

    let reordered = "export function handle(req) { const second = 2; const first = 1; const target = req.query.target; return fetch(target); }";
    let reordered_finding = finding(&scan(&[("src/reordered.ts", reordered)])?, "SE1004")?.clone();
    assert_eq!(
        left.semantic_fingerprint,
        reordered_finding.semantic_fingerprint
    );

    let extracted = "function relay(destination) { return fetch(destination); } export function handle(req) { const target = req.query.target; return relay(target); }";
    let extracted_finding = finding(&scan(&[("src/extracted.ts", extracted)])?, "SE1004")?.clone();
    assert_eq!(
        left.semantic_fingerprint,
        extracted_finding.semantic_fingerprint
    );

    let effective = "const ALLOWED = new Set(['https://api.example.test']); export function handle(req) { const target = req.query.target; if (!ALLOWED.has(target)) throw new Error('reject'); return fetch(target); }";
    assert!(
        scan(&[("src/effective.ts", effective)])?
            .findings
            .is_empty()
    );

    let unguarded =
        "export function handle(req) { const target = req.query.target; return fetch(target); }";
    finding(&scan(&[("src/unguarded.ts", unguarded)])?, "SE1004")?;

    let early_return = "const ALLOWED = new Set(['https://api.example.test']); export function handle(req) { const target = req.query.target; if (!ALLOWED.has(target)) return new Response('reject', { status: 400 }); return fetch(target); }";
    assert!(
        scan(&[("src/early-return.ts", early_return)])?
            .findings
            .is_empty()
    );

    let weakened = "export function handle(req) { const target = req.query.target; if (!target.endsWith('.example.test')) console.warn('unexpected'); return fetch(target); }";
    finding(&scan(&[("src/weakened.ts", weakened)])?, "SE1004")?;
    Ok(())
}

#[test]
fn ambiguous_dynamic_boundaries_remain_conservative_and_private()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan(&[
        (
            "src/bounded.ts",
            "function first(value) { return second(value); } function second(value) { return first(value); } export function handle(req) { const operation = req.query.mode ? eval : fetch; return operation(first(req.body.value)); }",
        ),
        (
            "src/callback.ts",
            "export function callbackHandler(req) { return req.body.items.map((item) => eval(item)); }",
        ),
        (
            "src/dynamic-import.ts",
            "export async function dynamicHandler(req) { const module = await import(req.query.module); return module[req.query.action](req.body.value); }",
        ),
        (
            "src/unresolved.ts",
            "import { relay } from './not-present'; export function unresolvedHandler(req) { return relay(req.body.value); }",
        ),
    ])?;
    assert!(report.findings.is_empty());
    assert!(report.limitations.iter().any(|limitation| {
        limitation.code == "dynamic-resolution-limited"
            && limitation.message.contains("callbacks")
            && limitation.message.contains("recursion")
    }));
    let serialized = serde_json::to_string(&report)?;
    assert!(!serialized.contains("/tmp/"));
    assert!(!serialized.contains(Path::new("/tmp").to_string_lossy().as_ref()));
    Ok(())
}

#[test]
fn cache_v7_ignores_v6_and_reuses_only_current_evidence() -> Result<(), Box<dyn std::error::Error>>
{
    let repository = TempDir::new()?;
    fs::create_dir_all(repository.path().join("src"))?;
    fs::write(
        repository.path().join("src/handler.ts"),
        "export function handle(req) { return fetch(req.query.target); }",
    )?;
    let cache = TempDir::new()?;
    let stale = cache.path().join("secure-parse-cache-v6/legacy/stale.json");
    fs::create_dir_all(stale.parent().ok_or("stale parent missing")?)?;
    fs::write(&stale, b"legacy-cache-envelope")?;

    let mut request = ScanRequest::new(repository.path());
    request.cache = CacheControl {
        directory: Some(cache.path().to_path_buf()),
        clear_before_scan: false,
    };
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(cold.parsing.cache_hits, 0);
    assert!(cold.parsing.cache_misses > 0);
    assert!(cold.parsing.cache_writes > 0);
    assert!(stale.is_file());
    assert!(cache.path().join("secure-parse-cache-v7").is_dir());

    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(warm.parsing.cache_misses, 0);
    assert!(warm.parsing.cache_hits > 0);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert_eq!(cold.facts, warm.facts);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.findings, warm.findings);
    Ok(())
}
