//! Phase 6.6 independent semantic, precision, metamorphic, and resource regressions.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use secure_engine::{
    CancellationToken, SECURE_JSON_V1_SCHEMA, ScanConfiguration, ScanRequest, create_baseline,
    sarif_report, scan_repository, validate_baseline,
};
use tempfile::tempdir;

const FAMILIES: [&str; 7] = [
    "SE1001", "SE1002", "SE1003", "SE1004", "SE1005", "SE1006", "SE1007",
];

#[derive(Clone, Copy, Debug)]
struct Scenario {
    rule: &'static str,
    vulnerable: bool,
    variant: usize,
}

fn family_scenarios() -> Vec<Scenario> {
    FAMILIES
        .into_iter()
        .flat_map(|rule| {
            (0..6)
                .map(move |variant| Scenario {
                    rule,
                    vulnerable: true,
                    variant,
                })
                .chain((0..6).map(move |variant| Scenario {
                    rule,
                    vulnerable: false,
                    variant,
                }))
        })
        .collect()
}

fn scan_sources(
    files: &[(&str, String)],
) -> Result<secure_engine::ScanReport, Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    for (path, source) in files {
        let destination = temporary.path().join(path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(destination, source)?;
    }
    let mut request = ScanRequest::new(temporary.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

fn extension(variant: usize) -> &'static str {
    ["ts", "js", "tsx", "jsx", "ts", "js"][variant]
}

fn scenario_path(variant: usize) -> &'static str {
    match extension(variant) {
        "ts" => "scenario.ts",
        "tsx" => "scenario.tsx",
        "jsx" => "scenario.jsx",
        _ => "scenario.js",
    }
}

fn vulnerable_source(rule: &str, variant: usize) -> Vec<(&'static str, String)> {
    let source = match rule {
        "SE1001" => vulnerable_flow(variant, "exec", "request.query.command"),
        "SE1002" => vulnerable_flow(variant, "db.raw", "request.body.filter"),
        "SE1003" => vulnerable_flow(variant, "fs.readFile", "request.params.path"),
        "SE1004" => vulnerable_flow(variant, "fetch", "request.query.endpoint"),
        "SE1005" => vulnerable_flow(variant, "redirect", "request.query.destination"),
        "SE1006" => vulnerable_flow(variant, "eval", "request.body.expression"),
        "SE1007" => vulnerable_authorization(variant),
        _ => unreachable!(),
    };
    if variant == 4 && rule != "SE1007" {
        let (callee, input) = match rule {
            "SE1001" => ("exec", "request.query.command"),
            "SE1002" => ("db.raw", "request.body.filter"),
            "SE1003" => ("fs.readFile", "request.params.path"),
            "SE1004" => ("fetch", "request.query.endpoint"),
            "SE1005" => ("redirect", "request.query.destination"),
            "SE1006" => ("eval", "request.body.expression"),
            _ => unreachable!(),
        };
        return vec![
            (
                "handler.ts",
                format!(
                    "import {{ applyValue }} from './operation';\nexport function receive(request) {{ return applyValue({input}); }}\n"
                ),
            ),
            (
                "operation.ts",
                format!("export function applyValue(value) {{ return {callee}(value); }}\n"),
            ),
        ];
    }
    vec![(scenario_path(variant), source)]
}

fn vulnerable_flow(variant: usize, callee: &str, input: &str) -> String {
    match variant {
        0 => format!("export function receive(request) {{ return {callee}({input}); }}\n"),
        1 => format!(
            "export function renamed(request) {{ const auditLabel = 'harmless'; const influenced = {input}; const forwarded = influenced; return {callee}(forwarded); }}\n"
        ),
        2 => format!(
            "function wrapper(value) {{ return {callee}(value); }}\nexport function receive(request) {{ return wrapper({input}); }}\n"
        ),
        3 => {
            let leaf = callee.rsplit('.').next().unwrap_or(callee);
            format!(
                "const operation = {leaf};\nexport function receive(request) {{ return operation({input}); }}\n"
            )
        }
        4 => String::new(),
        5 => format!(
            "export function receive(request) {{ if (!approved(request.query.unrelated)) {{ throw new Error('reject'); }} const value = {input}; return {callee}(value); }}\n"
        ),
        _ => unreachable!(),
    }
}

fn vulnerable_authorization(variant: usize) -> String {
    match variant {
        0 => "\"use server\";\nexport async function change(payload) { await accountStore.update(payload.change); }\n".into(),
        1 => "\"use server\";\nexport async function renamed(payload) { const auditLabel = 'harmless'; const change = payload.change; await accountStore.update(change); }\n".into(),
        2 => "\"use server\";\nasync function apply(change) { await accountStore.update(change); }\nexport async function change(payload) { await apply(payload.change); }\n".into(),
        3 => "\"use server\";\nconst mutate = accountStore.update;\nexport async function change(payload) { await mutate(payload.change); }\n".into(),
        4 => "\"use server\";\nasync function apply(change) { await accountStore.update(change); }\nexport const change = async (payload) => apply(payload.change);\n".into(),
        5 => "\"use server\";\nexport async function change(payload) { requireAuthentication(payload.actor); await accountStore.update(payload.change); }\n".into(),
        _ => unreachable!(),
    }
}

// Keeping the complete safe matrix adjacent makes the 42 independently reviewed controls auditable.
#[allow(clippy::too_many_lines)]
fn safe_source(rule: &str, variant: usize) -> String {
    let source = match (rule, variant) {
        ("SE1001", 0) => {
            "export function receive(request) { return spawn('/usr/bin/status-tool', ['--record', request.query.command], { shell: false }); }"
        }
        ("SE1001", 1) => {
            "export function receive(request) { const command = sanitizeCommand(request.query.command); return exec(command); }"
        }
        ("SE1001", 2) => {
            "function sanitizeApprovedCommand(value) { return sanitizeCommand(value); }\nexport function receive(request) { return exec(sanitizeApprovedCommand(request.query.command)); }"
        }
        ("SE1001", 3) => {
            "export function receive(request) { const observed = request.query.command; return exec('status-tool --version'); }"
        }
        ("SE1001", 4) => {
            "const runner = spawn;\nexport function receive(request) { return runner('/usr/bin/status-tool', ['--record', request.query.command], { shell: false }); }"
        }
        ("SE1001", 5) => {
            "export function receive(request) { return execFile('/usr/bin/status-tool', ['--record', request.query.command], { shell: false }); }"
        }
        ("SE1002", 0) => {
            "export function receive(request) { return db.query('SELECT * FROM records WHERE id = $1', [request.body.filter]); }"
        }
        ("SE1002", 1) => {
            "export function receive(request) { return db.execute('SELECT * FROM records WHERE id = ?', [request.body.filter]); }"
        }
        ("SE1002", 2) => {
            "export function receive(request) { const query = parameterizeSql(request.body.filter); return db.raw(query); }"
        }
        ("SE1002", 3) => {
            "export function receive(request) { const observed = request.body.filter; return db.raw('SELECT count(*) FROM records'); }"
        }
        ("SE1002", 4) => {
            "function lookup(value) { return db.query('SELECT * FROM records WHERE id = $1', [value]); }\nexport function receive(request) { return lookup(request.body.filter); }"
        }
        ("SE1002", 5) => {
            "const lookup = (value) => db.execute('SELECT * FROM records WHERE id = ?', [value]);\nexport function receive(request) { return lookup(request.body.filter); }"
        }
        ("SE1003", 0) => {
            "export function receive(request) { const safe = normalizeSafePath(request.params.path); return fs.readFile(safe, () => undefined); }"
        }
        ("SE1003", 1) => {
            "const ROOT = '/srv/data';\nfunction confine(value) { const candidate = path.resolve(ROOT, value); if (!candidate.startsWith(ROOT + path.sep)) { throw new Error('outside root'); } return candidate; }\nexport function receive(request) { return fs.readFile(confine(request.params.path), () => undefined); }"
        }
        ("SE1003", 2) => {
            "export function receive(request) { const observed = request.params.path; return fs.readFile('/srv/data/index.txt', () => undefined); }"
        }
        ("SE1003", 3) => {
            "function sanitizeApprovedPath(value) { return sanitizePath(value); }\nexport function receive(request) { return fs.readFile(sanitizeApprovedPath(request.params.path), () => undefined); }"
        }
        ("SE1003", 4) => {
            "const confine = normalizeSafePath;\nexport function receive(request) { return fs.readFile(confine(request.params.path), () => undefined); }"
        }
        ("SE1003", 5) => {
            "const ROOT = '/srv/data';\nexport function receive(request) { const candidate = path.resolve(ROOT, request.params.path); if (!candidate.startsWith(ROOT + path.sep)) { throw new Error('outside root'); } return fs.readFile(candidate, () => undefined); }"
        }
        ("SE1004", 0) => {
            "export function receive(request) { return fetch(safeUrl(request.query.endpoint)); }"
        }
        ("SE1004", 1) => {
            "const APPROVED_HOSTS = new Set(['api.example.test']);\nfunction select(value) { const parsed = new URL(value); if (parsed.protocol !== 'https:' || !APPROVED_HOSTS.has(parsed.hostname)) { throw new Error('rejected'); } return parsed; }\nexport function receive(request) { return fetch(select(request.query.endpoint)); }"
        }
        ("SE1004", 2) => {
            "export function receive(request) { const observed = request.query.endpoint; return fetch('https://api.example.test/status'); }"
        }
        ("SE1004", 3) => {
            "const APPROVED_ORIGINS = new Set(['https://api.example.test']);\nfunction select(value) { const parsed = new URL(value); if (!APPROVED_ORIGINS.has(parsed.origin)) { throw new Error('rejected'); } return parsed; }\nexport function receive(request) { return fetch(select(request.query.endpoint)); }"
        }
        ("SE1004", 4) => {
            "const select = safeUrl;\nexport function receive(request) { return fetch(select(request.query.endpoint)); }"
        }
        ("SE1004", 5) => {
            "const APPROVED_URLS = new Set(['https://api.example.test/status']);\nexport function receive(request) { const target = request.query.endpoint; return fetch(APPROVED_URLS.has(target) ? target : 'https://api.example.test/status'); }"
        }
        ("SE1005", 0) => {
            "export function receive(request) { return redirect(safeRedirect(request.query.destination)); }"
        }
        ("SE1005", 1) => {
            "const APPROVED_REDIRECTS = new Set(['/account']);\nfunction select(value) { if (!APPROVED_REDIRECTS.has(value)) { return '/account'; } return value; }\nexport function receive(request) { return redirect(select(request.query.destination)); }"
        }
        ("SE1005", 2) => {
            "const APPROVED_REDIRECTS = new Set(['/account']);\nexport function receive(request) { const target = request.query.destination; return redirect(APPROVED_REDIRECTS.has(target) ? target : '/account'); }"
        }
        ("SE1005", 3) => {
            "export function receive(request) { const observed = request.query.destination; return redirect('/account'); }"
        }
        ("SE1005", 4) => {
            "const select = sanitizeRedirect;\nexport function receive(request) { return redirect(select(request.query.destination)); }"
        }
        ("SE1005", 5) => {
            "const APPROVED_REDIRECTS = new Set(['/account']);\nfunction select(value) { if (!APPROVED_REDIRECTS.has(value)) { throw new Error('rejected'); } return value; }\nexport function receive(request) { return redirect(select(request.query.destination)); }"
        }
        ("SE1006", 0) => {
            "export function receive(request) { return JSON.parse(request.body.expression); }"
        }
        ("SE1006", 1) => {
            "export function receive(request) { const observed = request.body.expression; return eval('2 + 2'); }"
        }
        ("SE1006", 2) => {
            "export function receive(request) { const safe = sanitizeCode(request.body.expression); return eval(safe); }"
        }
        ("SE1006", 3) => {
            "const OPERATIONS = { status: () => 'ok' };\nexport function receive(request) { return OPERATIONS[request.body.expression]?.(); }"
        }
        ("SE1006", 4) => {
            "export function receive(request) { return parseExpression(request.body.expression); }"
        }
        ("SE1006", 5) => {
            "function sanitizeApprovedCode(value) { return sanitizeCode(value); }\nexport function receive(request) { return eval(sanitizeApprovedCode(request.body.expression)); }"
        }
        ("SE1007", 0) => {
            "\"use server\";\nexport async function change(payload) { requireRolePermission(payload.actor); await accountStore.update(payload.change); }"
        }
        ("SE1007", 1) => {
            "\"use server\";\nexport async function change(payload) { enforceOwnership(payload.actor, payload.change); await accountStore.update(payload.change); }"
        }
        ("SE1007", 2) => {
            "\"use server\";\nexport async function change(payload) { requireTenantBoundary(payload.actor, payload.change); await accountStore.update(payload.change); }"
        }
        ("SE1007", 3) => {
            "\"use server\";\nexport async function change(payload) { authorizeOperation(payload.actor, payload.change); await accountStore.update(payload.change); }"
        }
        ("SE1007", 4) => {
            "\"use server\";\nfunction enforceMembership(actor) { requireRolePermission(actor); }\nexport async function change(payload) { enforceMembership(payload.actor); await accountStore.update(payload.change); }"
        }
        ("SE1007", 5) => {
            "\"use server\";\nexport async function change(payload) { canAccess(payload.actor, payload.change); await accountStore.update(payload.change); }"
        }
        _ => unreachable!(),
    };
    format!("{source}\n")
}

#[test]
fn independent_matrix_has_six_vulnerable_and_six_safe_scenarios_per_family()
-> Result<(), Box<dyn std::error::Error>> {
    let scenarios = family_scenarios();
    assert_eq!(scenarios.len(), 84);
    for rule in FAMILIES {
        assert_eq!(
            scenarios
                .iter()
                .filter(|scenario| scenario.rule == rule && scenario.vulnerable)
                .count(),
            6
        );
        assert_eq!(
            scenarios
                .iter()
                .filter(|scenario| scenario.rule == rule && !scenario.vulnerable)
                .count(),
            6
        );
    }

    for scenario in scenarios {
        let files = if scenario.vulnerable {
            vulnerable_source(scenario.rule, scenario.variant)
        } else {
            vec![(
                scenario_path(scenario.variant),
                safe_source(scenario.rule, scenario.variant),
            )]
        };
        let report = scan_sources(&files)?;
        let emitted = report
            .findings
            .iter()
            .any(|finding| finding.rule_id == scenario.rule);
        assert_eq!(
            emitted,
            scenario.vulnerable,
            "unexpected outcome for {} vulnerable={} variant={} findings={:?}",
            scenario.rule,
            scenario.vulnerable,
            scenario.variant,
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
fn semantic_fingerprints_survive_cosmetic_and_structural_transformations()
-> Result<(), Box<dyn std::error::Error>> {
    for rule in FAMILIES {
        let mut fingerprints = Vec::new();
        for variant in 0..5 {
            let report = scan_sources(&vulnerable_source(rule, variant))?;
            let finding = report
                .findings
                .iter()
                .find(|finding| finding.rule_id == rule)
                .ok_or("metamorphic vulnerable finding missing")?;
            let semantic = finding
                .semantic_fingerprint
                .clone()
                .ok_or("semantic fingerprint missing")?;
            assert_eq!(semantic.len(), 64);
            assert!(finding.evidence_path.iter().any(|step| {
                step.semantic.as_ref().is_some_and(|semantic| {
                    semantic.role == secure_engine::EvidenceSemanticRole::UntrustedSource
                })
            }));
            assert!(
                finding
                    .evidence_path
                    .last()
                    .and_then(|step| step.semantic.as_ref())
                    .is_some()
            );
            fingerprints.push(semantic);
        }
        assert!(
            fingerprints.windows(2).all(|pair| pair[0] == pair[1]),
            "semantic identity changed for {rule}"
        );
    }
    Ok(())
}

#[test]
fn mutations_flip_only_when_the_security_invariant_changes()
-> Result<(), Box<dyn std::error::Error>> {
    for rule in FAMILIES {
        let vulnerable = scan_sources(&vulnerable_source(rule, 0))?;
        let safe = scan_sources(&[("scenario.ts", safe_source(rule, 0))])?;
        assert!(
            vulnerable
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule)
        );
        assert!(!safe.findings.iter().any(|finding| finding.rule_id == rule));
    }
    Ok(())
}

#[test]
fn equivalent_safe_guards_and_guard_removal_are_path_sensitive()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            "SE1003",
            "const ROOT = '/srv/data';\nfunction confine(value) { const candidate = path.resolve(ROOT, value); if (!candidate.startsWith(ROOT + path.sep)) { throw new Error('outside root'); } return candidate; }\nexport function receive(request) { return fs.readFile(confine(request.params.path), () => undefined); }",
            "const ROOT = '/srv/data';\nfunction confine(value) { const candidate = path.normalize(path.join(ROOT, value)); if (!candidate.startsWith(ROOT + path.sep)) { throw new Error('outside root'); } return candidate; }\nexport function receive(request) { return fs.readFile(confine(request.params.path), () => undefined); }",
            "const ROOT = '/srv/data';\nfunction compose(value) { return path.resolve(ROOT, value); }\nexport function receive(request) { return fs.readFile(compose(request.params.path), () => undefined); }",
        ),
        (
            "SE1004",
            "const APPROVED_HOSTS = new Set(['api.example.test']);\nfunction select(value) { const parsed = new URL(value); if (parsed.protocol !== 'https:' || !APPROVED_HOSTS.has(parsed.hostname)) { throw new Error('destination rejected'); } return parsed; }\nexport function receive(request) { return fetch(select(request.query.endpoint)); }",
            "const APPROVED_ORIGINS = new Set(['https://api.example.test']);\nfunction select(value) { const parsed = new URL(value); if (!APPROVED_ORIGINS.has(parsed.origin)) { throw new Error('origin rejected'); } return parsed; }\nexport function receive(request) { return fetch(select(request.query.endpoint)); }",
            "function select(value) { return new URL(value); }\nexport function receive(request) { return fetch(select(request.query.endpoint)); }",
        ),
        (
            "SE1005",
            "const APPROVED_REDIRECTS = new Set(['/account']);\nfunction select(value) { if (!APPROVED_REDIRECTS.has(value)) { return '/account'; } return value; }\nexport function receive(request) { return redirect(select(request.query.destination)); }",
            "const APPROVED_REDIRECTS = new Set(['/account']);\nexport function receive(request) { const value = request.query.destination; return redirect(APPROVED_REDIRECTS.has(value) ? value : '/account'); }",
            "export function receive(request) { return redirect(request.query.destination); }",
        ),
        (
            "SE1007",
            "\"use server\";\nexport async function change(payload) { requireRolePermission(payload.actor); await accountStore.update(payload.change); }",
            "\"use server\";\nexport async function change(payload) { enforceOwnership(payload.actor, payload.change); await accountStore.update(payload.change); }",
            "\"use server\";\nexport async function change(payload) { await accountStore.update(payload.change); }",
        ),
    ];
    for (rule, first_safe, equivalent_safe, guard_removed) in cases {
        for safe in [first_safe, equivalent_safe] {
            let report = scan_sources(&[("scenario.ts", safe.into())])?;
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == rule),
                "equivalent safe guard emitted {rule}"
            );
        }
        let report = scan_sources(&[("scenario.ts", guard_removed.into())])?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule),
            "removing the guard did not emit {rule}"
        );
    }
    Ok(())
}

#[test]
fn path_transformations_keep_specific_semantic_identities() -> Result<(), Box<dyn std::error::Error>>
{
    for (operation, identity) in [
        (
            "path.join(ROOT, request.params.path)",
            "transformation.path-base-join",
        ),
        (
            "decodeURIComponent(request.params.path)",
            "transformation.decoding",
        ),
        (
            "path.relative(ROOT, request.params.path)",
            "transformation.path-relative",
        ),
    ] {
        let source = format!(
            "const ROOT = '/srv/data';\nexport function receive(request) {{ const candidate = {operation}; return fs.readFile(candidate, () => undefined); }}"
        );
        let report = scan_sources(&[("scenario.ts", source)])?;
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "SE1003")
            .ok_or("path finding missing")?;
        assert!(
            finding.evidence_path.iter().any(|step| {
                step.semantic
                    .as_ref()
                    .is_some_and(|semantic| semantic.identity == identity)
            }),
            "missing semantic identity {identity}"
        );
    }
    Ok(())
}

#[test]
fn imports_destructuring_aliases_and_inter_file_wrappers_preserve_provenance()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        vec![(
            "scenario.ts",
            "import { exec as launch } from 'child_process';\nexport function receive(request) { return launch(request.query.command); }".into(),
        )],
        vec![(
            "scenario.ts",
            "const { exec: launch } = childProcess;\nexport function receive(request) { return launch(request.query.command); }".into(),
        )],
        vec![
            (
                "entry.ts",
                "import { run as wrapped } from './operation';\nexport function receive(request) { return wrapped(request.query.command); }".into(),
            ),
            (
                "operation.ts",
                "export function run(value) { return exec(value); }".into(),
            ),
        ],
    ];
    for (index, files) in cases.iter().enumerate() {
        let report = scan_sources(files)?;
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "SE1001")
            .ok_or("aliased command flow missing")?;
        let expected_source = if index == 2 {
            "entry.ts"
        } else {
            "scenario.ts"
        };
        let expected_sink = if index == 2 {
            "operation.ts"
        } else {
            "scenario.ts"
        };
        assert_eq!(
            finding.source.as_ref().map(|source| source.path.as_str()),
            Some(expected_source)
        );
        assert_eq!(
            finding.sink.as_ref().map(|sink| sink.path.as_str()),
            Some(expected_sink)
        );
        assert!(finding.evidence_path.iter().all(|step| {
            step.location.path == expected_source || step.location.path == expected_sink
        }));
    }
    Ok(())
}

#[test]
fn outbound_policies_accept_exact_components_and_reject_permissive_checks()
-> Result<(), Box<dyn std::error::Error>> {
    let exact = "const APPROVED_HOSTS = new Set(['api.example.test']);\nfunction select(value) { const parsed = new URL(value); if (parsed.protocol !== 'https:' || parsed.port !== '443' || !APPROVED_HOSTS.has(parsed.hostname)) { throw new Error('destination rejected'); } return parsed; }\nexport function receive(request) { return fetch(select(request.query.endpoint)); }";
    let report = scan_sources(&[("scenario.ts", exact.into())])?;
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SE1004")
    );

    for permissive in [
        "function select(value) { const parsed = new URL(value); if (parsed.protocol !== 'https:' || !parsed.hostname.endsWith('.example.test')) { throw new Error('destination rejected'); } return parsed; }\nexport function receive(request) { return fetch(select(request.query.endpoint)); }",
        "const APPROVED_FRAGMENT = 'example.test';\nfunction select(value) { const parsed = new URL(value); if (parsed.protocol !== 'https:' || !parsed.hostname.includes(APPROVED_FRAGMENT)) { throw new Error('destination rejected'); } return parsed; }\nexport function receive(request) { return fetch(select(request.query.endpoint)); }",
        "function select(value) { const parsed = new URL(value); if (parsed.username || parsed.password) { throw new Error('userinfo rejected'); } return parsed; }\nexport function receive(request) { return fetch(select(request.query.endpoint)); }",
    ] {
        let report = scan_sources(&[("scenario.ts", permissive.into())])?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "SE1004")
        );
    }
    Ok(())
}

#[test]
fn semantic_metadata_is_additive_in_json_sarif_and_baselines()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_sources(&vulnerable_source("SE1003", 2))?;
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "SE1003")
        .ok_or("filesystem finding missing")?;
    assert!(finding.semantic_fingerprint.is_some());
    assert!(
        finding
            .evidence_path
            .iter()
            .all(|step| step.semantic.is_some())
    );
    assert!(
        report
            .limitations
            .iter()
            .any(|limitation| { limitation.code == "filesystem-symlink-safety-not-proven" })
    );

    let schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&serde_json::to_value(&report)?));

    let sarif = sarif_report(&report);
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(
        result["fingerprints"]["secureSemanticFingerprint/v1"].as_str(),
        finding.semantic_fingerprint.as_deref()
    );
    assert!(
        result["codeFlows"][0]["threadFlows"][0]["locations"]
            .as_array()
            .is_some_and(|locations| locations.iter().all(|location| {
                location["properties"]["secureEvidenceSemantic"]["identity"]
                    .as_str()
                    .is_some()
            }))
    );

    let baseline = create_baseline(&report)?;
    assert_eq!(
        baseline.findings[0].semantic_fingerprint,
        finding.semantic_fingerprint
    );
    validate_baseline(&baseline)?;
    Ok(())
}

#[test]
fn rust_python_and_go_variants_preserve_supported_command_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let language_pairs = [
        (
            "scenario.rs",
            "use axum::{Router, routing::get};\nfn routes() -> Router { Router::new().route(\"/run\", get(receive)) }\nasync fn receive(input: String) { std::process::Command::new(\"sh\").arg(\"-c\").arg(input).output(); }",
            "use axum::{Router, routing::get};\nfn routes() -> Router { Router::new().route(\"/run\", get(receive)) }\nasync fn receive(input: String) { let safe = allowlist(input); std::process::Command::new(\"tool\").arg(safe).output(); }",
        ),
        (
            "scenario.py",
            "from flask import Flask, request\napp = Flask(__name__)\n@app.get('/run')\ndef receive():\n    subprocess.run(request.args.get('command'), shell=True)\n",
            "from flask import Flask, request\napp = Flask(__name__)\n@app.get('/run')\ndef receive():\n    requested = request.args.get('command')\n    safe = allowlist(requested)\n    subprocess.run(['tool', safe], check=True)\n",
        ),
        (
            "scenario.go",
            "package scenarios\nfunc routes(router *gin.Engine) { router.GET(\"/run\", receive) }\nfunc receive(context *gin.Context) { input := context.Query(\"command\"); exec.Command(\"sh\", \"-c\", input).Run() }\n",
            "package scenarios\nfunc routes(router *gin.Engine) { router.GET(\"/run\", receive) }\nfunc receive(context *gin.Context) { input := context.Query(\"command\"); safe := allowlist(input); exec.Command(\"tool\", safe).Run() }\n",
        ),
    ];
    let mut scenarios = 0;
    for (path, vulnerable, safe) in language_pairs {
        for cosmetic in ["", "\n// rename-independent\n", "\n// harmless insertion\n"] {
            let report = scan_sources(&[(path, format!("{vulnerable}{cosmetic}"))])?;
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == "SE1001")
            );
            let report = scan_sources(&[(path, format!("{safe}{cosmetic}"))])?;
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == "SE1001"),
                "safe {path} variant emitted SE1001"
            );
            scenarios += 2;
        }
    }
    assert_eq!(scenarios, 18);
    Ok(())
}

#[test]
fn candidate_paths_are_bounded_and_report_uncertainty() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let mut source = String::new();
    for index in 0..128 {
        let _ignored = writeln!(
            source,
            "export function flow{index}(request) {{ return exec(request.query.value); }}"
        );
    }
    fs::write(temporary.path().join("many.ts"), source)?;
    let mut request = ScanRequest::new(temporary.path());
    request.configuration = ScanConfiguration {
        max_findings: 1,
        max_graph_edges: 10_000,
        max_interprocedural_depth: 1,
        parse_cache_enabled: false,
        ..ScanConfiguration::default()
    };
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert!(report.analysis.truncated);
    assert!(report.analysis.candidate_paths <= 2);
    assert!(
        report
            .limitations
            .iter()
            .any(|limitation| limitation.code == "candidate-path-limit-reached")
    );
    Ok(())
}

#[test]
fn fixture_paths_are_repository_independent() {
    for scenario in family_scenarios() {
        let files = if scenario.vulnerable {
            vulnerable_source(scenario.rule, scenario.variant)
        } else {
            vec![(
                scenario_path(scenario.variant),
                safe_source(scenario.rule, scenario.variant),
            )]
        };
        assert!(files.iter().all(|(path, _)| Path::new(path).is_relative()));
    }
}
