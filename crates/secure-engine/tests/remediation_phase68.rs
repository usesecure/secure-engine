//! Phase 6.8 independent precision, identity, and evidence-path regression corpus.

use std::fs;
use std::path::{Path, PathBuf};

use secure_engine::{
    CancellationToken, EvidenceContractRoleV2, EvidenceSinkKindV2, EvidenceSourceKindV2, Finding,
    ScanReport, ScanRequest, scan_repository,
};
use tempfile::TempDir;

const FAMILIES: [&str; 7] = [
    "SE1001", "SE1002", "SE1003", "SE1004", "SE1005", "SE1006", "SE1007",
];

fn operation(rule: &str, vulnerable: bool) -> &'static str {
    match (rule, vulnerable) {
        ("SE1001", true) => "return exec('lookup --value ' + value);",
        ("SE1001", false) => "return execFile('/usr/bin/lookup', ['--value', value]);",
        ("SE1002", true) => {
            "return database.query(\"SELECT id FROM records WHERE value = '\" + value + \"'\");"
        }
        ("SE1002", false) => {
            "return database.query('SELECT id FROM records WHERE value = $1', [value]);"
        }
        ("SE1003", true) => "return fs.readFile('/srv/records/' + value, () => undefined);",
        ("SE1003", false) => "return fs.readFile(normalizeSafePath(value), () => undefined);",
        ("SE1004", true) => "return fetch(value);",
        ("SE1004", false) => "return fetch(safeUrl(value));",
        ("SE1005", true) => "return redirect(value);",
        ("SE1005", false) => "return redirect(safeRedirect(value));",
        ("SE1006", true) => "return eval(value);",
        ("SE1006", false) => "return JSON.parse(value);",
        ("SE1007", true) => "return recordStore.update(value);",
        ("SE1007", false) => {
            "enforceOwnership(currentUser(), value); return recordStore.update(value);"
        }
        _ => "",
    }
}

fn prelude(rule: &str) -> &'static str {
    match rule {
        "SE1001" => "import { exec, execFile } from 'node:child_process';\n",
        "SE1003" => "import fs from 'node:fs';\n",
        _ => "",
    }
}

#[derive(Clone)]
struct Scenario {
    files: Vec<(String, String)>,
    source_path: String,
    source_fragment: &'static str,
    sink_path: String,
    sink_fragment: &'static str,
}

fn scenario(rule: &str, vulnerable: bool, variant: usize) -> Scenario {
    let operation = operation(rule, vulnerable);
    let prelude = prelude(rule);
    let sink_fragment = match rule {
        "SE1001" => {
            if vulnerable {
                "exec("
            } else {
                "execFile("
            }
        }
        "SE1002" => "database.query(",
        "SE1003" => "fs.readFile(",
        "SE1004" => "fetch(",
        "SE1005" => "redirect(",
        "SE1006" => {
            if vulnerable {
                "eval("
            } else {
                "JSON.parse("
            }
        }
        "SE1007" => "recordStore.update(",
        _ => "",
    };
    match variant {
        0 => {
            let path = "src/handler.js".to_owned();
            Scenario {
                files: vec![(
                    path.clone(),
                    format!(
                        "{prelude}export function handle(request) {{\n  const value = request.query.value;\n  {operation}\n}}\n"
                    ),
                )],
                source_path: path.clone(),
                source_fragment: "request.query.value",
                sink_path: path,
                sink_fragment,
            }
        }
        1 => {
            let path = "src/router.jsx".to_owned();
            Scenario {
                files: vec![(
                    path.clone(),
                    format!(
                        "{prelude}function consume(value) {{\n  {operation}\n}}\nfunction handler(req, res) {{\n  const value = req.body.value;\n  return consume(value);\n}}\nrouter.post('/records', handler);\n"
                    ),
                )],
                source_path: path.clone(),
                source_fragment: "req.body.value",
                sink_path: path,
                sink_fragment,
            }
        }
        2 => Scenario {
            files: vec![
                (
                    "app/api/records/route.ts".into(),
                    "import { consume as relay } from './worker';\nexport async function POST(request: Request) {\n  const value = new URL(request.url).searchParams.get('value') ?? '';\n  return relay(value);\n}\n".into(),
                ),
                (
                    "app/api/records/worker.ts".into(),
                    format!("{prelude}export function consume(value: string) {{\n  {operation}\n}}\n"),
                ),
            ],
            source_path: "app/api/records/route.ts".into(),
            source_fragment: "searchParams.get",
            sink_path: "app/api/records/worker.ts".into(),
            sink_fragment,
        },
        3 => {
            let path = "app/actions/submit.tsx".to_owned();
            Scenario {
                files: vec![(
                    path.clone(),
                    format!(
                        "'use server';\n{prelude}function consume(value: string) {{\n  {operation}\n}}\nexport async function submit(form: FormData) {{\n  const value = String(form.get('value') ?? '');\n  if (!value) return null;\n  return consume(value);\n}}\n"
                    ),
                )],
                source_path: path.clone(),
                source_fragment: "form.get",
                sink_path: path,
                sink_fragment,
            }
        }
        _ => unreachable!(),
    }
}

fn write_scenario(root: &Path, scenario: &Scenario) -> Result<(), Box<dyn std::error::Error>> {
    for (relative, content) in &scenario.files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().ok_or("scenario parent missing")?)?;
        fs::write(path, content)?;
    }
    Ok(())
}

fn scan(scenario: &Scenario) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    write_scenario(directory.path(), scenario)?;
    let mut request = ScanRequest::new(directory.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

fn line_of(scenario: &Scenario, path: &str, fragment: &str) -> Result<u32, String> {
    let content = scenario
        .files
        .iter()
        .find_map(|(candidate, content)| (candidate == path).then_some(content))
        .ok_or_else(|| format!("missing scenario path {path}"))?;
    content
        .lines()
        .position(|line| line.contains(fragment))
        .and_then(|index| u32::try_from(index.saturating_add(1)).ok())
        .ok_or_else(|| format!("missing fragment {fragment} in {path}"))
}

fn byte_of(scenario: &Scenario, path: &str, fragment: &str) -> Result<u64, String> {
    let content = scenario
        .files
        .iter()
        .find_map(|(candidate, content)| (candidate == path).then_some(content))
        .ok_or_else(|| format!("missing scenario path {path}"))?;
    content
        .find(fragment)
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or_else(|| format!("missing fragment {fragment} in {path}"))
}

fn expected_source(rule: &str, variant: usize) -> EvidenceSourceKindV2 {
    if rule == "SE1007" {
        EvidenceSourceKindV2::ProtectedResourceId
    } else {
        match variant {
            0 | 2 => EvidenceSourceKindV2::HttpQueryValue,
            1 => EvidenceSourceKindV2::HttpBodyField,
            3 => EvidenceSourceKindV2::FormDataValue,
            _ => unreachable!(),
        }
    }
}

fn expected_sink(rule: &str) -> EvidenceSinkKindV2 {
    match rule {
        "SE1001" => EvidenceSinkKindV2::OsCommandExecution,
        "SE1002" => EvidenceSinkKindV2::SqlQueryExecution,
        "SE1003" => EvidenceSinkKindV2::FilesystemRead,
        "SE1004" => EvidenceSinkKindV2::OutboundRequest,
        "SE1005" => EvidenceSinkKindV2::RedirectResponse,
        "SE1006" => EvidenceSinkKindV2::DynamicCodeEvaluation,
        "SE1007" => EvidenceSinkKindV2::ProtectedRecordMutation,
        _ => unreachable!(),
    }
}

fn expected_taxonomy(rule: &str) -> (&'static str, &'static str, &'static str) {
    match rule {
        "SE1001" => (
            "command-execution",
            "command-control-data-separation",
            "CWE-78",
        ),
        "SE1002" => ("sql-construction", "sql-control-data-separation", "CWE-89"),
        "SE1003" => (
            "filesystem-boundary",
            "filesystem-path-confinement",
            "CWE-22",
        ),
        "SE1004" => (
            "outbound-request-boundary",
            "outbound-destination-policy",
            "CWE-918",
        ),
        "SE1005" => (
            "redirect-boundary",
            "redirect-destination-policy",
            "CWE-601",
        ),
        "SE1006" => (
            "dynamic-code-execution",
            "dynamic-code-control-data-separation",
            "CWE-95",
        ),
        "SE1007" => (
            "authorization-dominance",
            "authorization-before-sensitive-operation",
            "CWE-862",
        ),
        _ => unreachable!(),
    }
}

fn assert_taxonomy_and_endpoints(
    rule: &str,
    case: &Scenario,
    finding: &Finding,
) -> Result<(), Box<dyn std::error::Error>> {
    let taxonomy = finding.taxonomy.as_ref().ok_or("taxonomy missing")?;
    let (category, invariant, cwe) = expected_taxonomy(rule);
    assert!(taxonomy.category_id.ends_with(category));
    assert!(taxonomy.invariant_id.ends_with(invariant));
    assert_eq!(finding.primary_cwe.as_ref().ok_or("CWE missing")?.id, cwe);
    let source = finding.source.as_ref().ok_or("source missing")?;
    let sink = finding.sink.as_ref().ok_or("sink missing")?;
    assert_eq!(source.path, case.source_path);
    assert_eq!(sink.path, case.sink_path);
    assert_eq!(
        source.span.start_line,
        line_of(case, &case.source_path, case.source_fragment)?
    );
    assert_eq!(
        sink.span.start_line,
        line_of(case, &case.sink_path, case.sink_fragment)?
    );
    let source_byte = byte_of(case, &case.source_path, case.source_fragment)?;
    let sink_byte = byte_of(case, &case.sink_path, case.sink_fragment)?;
    assert!(source.span.start_byte <= source_byte);
    assert!(
        source.span.end_byte
            >= source_byte
                .saturating_add(u64::try_from(case.source_fragment.len()).unwrap_or(u64::MAX),)
    );
    assert!(sink.span.start_byte <= sink_byte);
    assert!(
        sink.span.end_byte
            >= sink_byte
                .saturating_add(u64::try_from(case.sink_fragment.len()).unwrap_or(u64::MAX))
    );
    Ok(())
}

fn assert_contract_and_fingerprints(
    rule: &str,
    variant: usize,
    case: &Scenario,
    finding: &Finding,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = finding.source.as_ref().ok_or("source missing")?;
    let sink = finding.sink.as_ref().ok_or("sink missing")?;
    let contract = finding
        .evidence_contract_v2
        .as_ref()
        .ok_or("contract missing")?;
    let contract_source = contract.path.first().ok_or("source step missing")?;
    let contract_sink = contract.path.last().ok_or("sink step missing")?;
    assert_eq!(contract_source.role, EvidenceContractRoleV2::Source);
    assert_eq!(contract_sink.role, EvidenceContractRoleV2::Sink);
    assert_eq!(
        contract_source.source_kind,
        Some(expected_source(rule, variant))
    );
    assert_eq!(contract_sink.sink_kind, Some(expected_sink(rule)));
    assert_eq!(
        contract.connected_edges.len().saturating_add(1),
        contract.path.len()
    );
    assert!(contract.connected_edges.iter().all(|connected| *connected));
    assert!(contract.effective_barriers.is_empty());
    assert!(!contract.uncertain);
    assert!(!contract.unresolved_call);
    assert_eq!(contract_source.span.path, source.path);
    assert_eq!(contract_source.span.span, source.span);
    assert_eq!(contract_sink.span.path, sink.path);
    assert_eq!(contract_sink.span.span, sink.span);
    let semantic = finding
        .semantic_fingerprint
        .as_deref()
        .ok_or("semantic fingerprint missing")?;
    assert_eq!(semantic.len(), 64);
    assert_eq!(contract.fingerprint.len(), 64);
    let repeated = scan(case)?;
    let repeated_finding = repeated
        .findings
        .iter()
        .find(|candidate| candidate.rule_id == rule)
        .ok_or("repeated finding missing")?;
    assert_eq!(
        repeated_finding.semantic_fingerprint.as_deref(),
        Some(semantic)
    );
    assert_eq!(
        repeated_finding
            .evidence_contract_v2
            .as_ref()
            .map(|value| &value.fingerprint),
        Some(&contract.fingerprint)
    );
    Ok(())
}

#[test]
fn independent_matrix_has_exact_taxonomy_endpoints_and_connected_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let mut vulnerable = 0_usize;
    let mut controls = 0_usize;
    for rule in FAMILIES {
        for variant in 0..4 {
            let unsafe_case = scenario(rule, true, variant);
            let report = scan(&unsafe_case)?;
            let findings = report
                .findings
                .iter()
                .filter(|finding| finding.rule_id == rule)
                .collect::<Vec<_>>();
            assert_eq!(findings.len(), 1, "{rule} vulnerable variant {variant}");
            vulnerable = vulnerable.saturating_add(1);
            let finding = findings[0];
            assert_taxonomy_and_endpoints(rule, &unsafe_case, finding)?;
            assert_contract_and_fingerprints(rule, variant, &unsafe_case, finding)?;

            let safe_case = scenario(rule, false, variant);
            let safe_report = scan(&safe_case)?;
            assert!(
                safe_report.findings.is_empty(),
                "{rule} control variant {variant}"
            );
            controls = controls.saturating_add(1);
        }
    }
    assert_eq!((vulnerable, controls), (28, 28));
    Ok(())
}

fn single_source(source: &str) -> Scenario {
    Scenario {
        files: vec![("src/case.ts".into(), source.into())],
        source_path: "src/case.ts".into(),
        source_fragment: "request.query.value",
        sink_path: "src/case.ts".into(),
        sink_fragment: "exec(",
    }
}

#[test]
fn structural_barriers_are_precise_and_authentication_is_not_authorization()
-> Result<(), Box<dyn std::error::Error>> {
    let safe_cases = [
        "import { execFile } from 'node:child_process'; export function handle(request) { return execFile('/usr/bin/lookup', ['--value', request.query.value]); }",
        "import { execFile } from 'node:child_process'; export function handle(request) { return execFile('/usr/bin/lookup', ['--value', request.query.value], { cwd: '/var/empty', shell: false }); }",
        "const DESTINATIONS = new Set(['api.example.test']); function choose(value) { const parsed = new URL(value); if (parsed.protocol !== 'https:' || !DESTINATIONS.has(parsed.hostname)) throw new Error('reject'); return parsed; } export function handle(request) { return fetch(choose(request.query.value)); }",
        "const DESTINATIONS = new Set(['/account']); export function handle(request) { const value = request.query.value; return redirect(DESTINATIONS.has(value) ? value : '/account'); }",
        "'use server'; function currentUser() { return identity.current(); } export async function change(request) { const principal = currentUser(); const resourceOwnerId = request.body.change; if (principal.subject !== resourceOwnerId) throw new Error('reject'); return recordStore.update(resourceOwnerId); }",
    ];
    for source in safe_cases {
        let report = scan(&single_source(source))?;
        assert!(
            report.findings.is_empty(),
            "safe barrier regressed: {source}\nfindings={:#?}",
            report.findings,
        );
    }

    let unsafe_cases = [
        (
            "SE1001",
            "import { execFile } from 'node:child_process'; export function handle(request) { return execFile('/usr/bin/lookup', ['--value', request.query.value], { shell: true }); }",
        ),
        (
            "SE1001",
            "import { execFile } from 'node:child_process'; export function handle(request) { return execFile('/usr/bin/lookup', ['--value', request.query.value], { ...request.body }); }",
        ),
        (
            "SE1004",
            "function choose(value) { const parsed = new URL(value); if (parsed.hostname.endsWith('.example.test')) return parsed; return parsed; } export function handle(request) { return fetch(choose(request.query.value)); }",
        ),
        (
            "SE1005",
            "const BLOCKED = new Set(['/outside']); export function handle(request) { const value = request.query.value; if (BLOCKED.has(value)) throw new Error('reject'); return redirect(value); }",
        ),
        (
            "SE1005",
            "const ALLOWED = new Set(['/account']); export function handle(request) { const value = request.query.value; ALLOWED.add(value); if (!ALLOWED.has(value)) throw new Error('reject'); return redirect(value); }",
        ),
        (
            "SE1007",
            "'use server'; export async function change(request) { requireAuthentication(request.actor); return recordStore.update(request.body.change); }",
        ),
    ];
    for (rule, source) in unsafe_cases {
        assert!(
            scan(&single_source(source))?
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule),
            "unsafe near miss suppressed {rule}: {source}"
        );
    }
    Ok(())
}

#[test]
fn destructuring_metamorphism_cycles_and_ambiguous_aliases_remain_honest()
-> Result<(), Box<dyn std::error::Error>> {
    let base = scan(&single_source(
        "import { exec } from 'node:child_process'; export function handle(request) { const value = request.query.value; return exec('lookup ' + value); }",
    ))?;
    let renamed = scan(&single_source(
        "import { exec } from 'node:child_process'; export function handle(inbound) { const harmless = 17; const renamed = inbound.query.value; return exec('lookup ' + renamed); }",
    ))?;
    let left = base
        .findings
        .iter()
        .find(|finding| finding.rule_id == "SE1001")
        .ok_or("base finding missing")?;
    let right = renamed
        .findings
        .iter()
        .find(|finding| finding.rule_id == "SE1001")
        .ok_or("renamed finding missing")?;
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

    let destructured = scan(&single_source(
        "import { exec } from 'node:child_process'; export function handle(request) { const { value: renamed } = request.query; return exec('lookup ' + renamed); }",
    ))?;
    assert_eq!(
        destructured
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "SE1001")
            .count(),
        1
    );

    let uncertain = scan(&single_source(
        "function first(value) { return second(value); } function second(value) { return first(value); } export function handle(request) { const operation = request.query.mode ? eval : fetch; return operation(first(request.query.value)); }",
    ))?;
    assert!(uncertain.findings.is_empty());
    assert!(
        uncertain
            .limitations
            .iter()
            .any(|limitation| limitation.code == "dynamic-resolution-limited")
    );

    let escaped_import = Scenario {
        files: vec![
            (
                "src/handler.ts".into(),
                "import { consume } from '../../worker'; export function handle(request) { return consume(request.query.value); }".into(),
            ),
            (
                "worker.ts".into(),
                "import { exec } from 'node:child_process'; export function consume(value) { return exec('lookup ' + value); }".into(),
            ),
        ],
        source_path: "src/handler.ts".into(),
        source_fragment: "request.query.value",
        sink_path: "worker.ts".into(),
        sink_fragment: "exec(",
    };
    assert!(scan(&escaped_import)?.findings.is_empty());

    let wrong_namespace = Scenario {
        files: vec![
            (
                "src/handler.ts".into(),
                "import * as helpers from './worker'; export function handle(request) { return unrelated.consume(request.query.value); }".into(),
            ),
            (
                "src/worker.ts".into(),
                "import { exec } from 'node:child_process'; export function consume(value) { return exec('lookup ' + value); }".into(),
            ),
        ],
        source_path: "src/handler.ts".into(),
        source_fragment: "request.query.value",
        sink_path: "src/worker.ts".into(),
        sink_fragment: "exec(",
    };
    assert!(scan(&wrong_namespace)?.findings.is_empty());
    Ok(())
}

#[test]
fn corpus_uses_all_required_languages_frameworks_and_topologies() {
    let mut extensions = Vec::<String>::new();
    for rule in FAMILIES {
        for variant in 0..4 {
            for (path, _) in scenario(rule, true, variant).files {
                if let Some(extension) = PathBuf::from(path).extension() {
                    extensions.push(extension.to_string_lossy().into_owned());
                }
            }
        }
    }
    for required in ["js", "jsx", "ts", "tsx"] {
        assert!(extensions.iter().any(|extension| extension == required));
    }
    assert_eq!(FAMILIES.len(), 7);
}
