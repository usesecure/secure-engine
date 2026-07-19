//! Phase 6.11 independent body-field connectivity and resource-authorization fixtures.

use std::fs;

use secure_engine::{CancellationToken, ScanReport, ScanRequest, scan_repository};
use tempfile::TempDir;

fn scan(files: &[(&str, &str)]) -> Result<ScanReport, Box<dyn std::error::Error>> {
    scan_with_depth(files, 4)
}

fn scan_with_depth(
    files: &[(&str, &str)],
    max_interprocedural_depth: usize,
) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    for (relative, content) in files {
        let path = directory.path().join(relative);
        fs::create_dir_all(path.parent().ok_or("missing parent")?)?;
        fs::write(path, content)?;
    }
    let mut request = ScanRequest::new(directory.path());
    request.configuration.parse_cache_enabled = false;
    request.configuration.max_interprocedural_depth = max_interprocedural_depth;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

fn rule_count(report: &ScanReport, rule: &str) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule)
        .count()
}

fn assert_vulnerable(rule: &str, files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert!(
        rule_count(&report, rule) > 0,
        "expected {rule}, got {:#?}",
        report.findings
    );
    Ok(())
}

fn assert_control(rule: &str, files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert_eq!(
        rule_count(&report, rule),
        0,
        "unexpected {rule}; guards={:#?}; findings={:#?}",
        report
            .graph
            .nodes
            .iter()
            .filter(|node| node.kind == "guard")
            .collect::<Vec<_>>(),
        report.findings,
    );
    Ok(())
}

#[test]
fn body_field_identity_survives_coercion_aliases_and_unique_helpers()
-> Result<(), Box<dyn std::error::Error>> {
    let bounded_chain = [(
        "app/api/queue/route.js",
        "import { exec } from 'node:child_process'; export async function POST(request) { const envelope = await request.json(); const instruction = String(envelope['instruction'] ?? ''); const options = { detached: false, priority: 0 }; const preview = instruction.substring(0, 3); if (preview.length > instruction.length) throw new Error('impossible'); const response = await perform(instruction, options); return Response.json({ accepted: Boolean(response) }); } async function perform(instruction, options) { const stamp = instruction.length + 41; void stamp; void options; const forwarded = instruction; const finalValue = forwarded; const response = exec(finalValue); return response; }",
    )];
    let default_count = rule_count(&scan(&bounded_chain)?, "SE1001");
    let extended_count = rule_count(&scan_with_depth(&bounded_chain, 8)?, "SE1001");
    assert!(
        default_count > 0 && extended_count > 0,
        "bounded-chain outcomes: default={default_count}, extended={extended_count}"
    );

    assert_vulnerable(
        "SE1004",
        &[(
            "app/api/dispatch/route.ts",
            "function carry(endpoint: string) { return fetch(endpoint); } export async function POST(request: Request) { const packet = await request.json(); const waypoint = String(packet['endpoint'] ?? ''); const renamed = waypoint; return carry(renamed); }",
        )],
    )?;

    assert_vulnerable(
        "SE1001",
        &[
            (
                "app/api/tasks/route.tsx",
                "import { launch as invoke } from './worker'; export async function POST(request: Request) { const parcel = await request.json(); const instruction = String(parcel.command ?? ''); const forwarded = instruction; return invoke(forwarded); }",
            ),
            (
                "app/api/tasks/worker.ts",
                "import { exec } from 'node:child_process'; export function launch(instruction: string) { return exec(instruction); }",
            ),
        ],
    )?;

    assert_vulnerable(
        "SE1002",
        &[(
            "src/query.jsx",
            "function submit(statement) { return database.query(statement); } async function endpoint(req, res) { const envelope = req.body; const fragment = String(envelope.filter ?? ''); const statement = 'select * from ledger where label = ' + fragment; return submit(statement); } router.post('/ledger/search', endpoint);",
        )],
    )?;

    assert_control(
        "SE1004",
        &[(
            "app/api/dispatch/route.js",
            "function carry(endpoint) { return fetch(endpoint); } export async function POST(request) { const packet = await request.json(); const audit = String(packet.audit ?? ''); void audit; return carry('https://service.invalid/fixed'); }",
        )],
    )?;
    assert_control(
        "SE1001",
        &[(
            "app/api/queue/route.ts",
            "import { exec } from 'node:child_process'; function perform(value: string) { void value; return exec('printf fixed'); } export async function POST(request: Request) { const body = await request.json(); const audit = String(body.task ?? ''); return perform(audit); }",
        )],
    )?;
    assert_control(
        "SE1002",
        &[(
            "src/query.tsx",
            "function submit(value: string) { return database.query('select * from ledger where label = $1', [value]); } export async function handler(request: Request) { const body = await request.json(); const label = String(body.label ?? ''); return submit(label); }",
        )],
    )?;

    assert_vulnerable(
        "SE1004",
        &[(
            "app/api/deceptive/route.tsx",
            "function verifiedChannel(value: string) { return fetch(value); } export async function POST(request: Request) { const body = await request.json(); const guaranteedSafeByComment = String(body.endpoint ?? ''); return verifiedChannel(guaranteedSafeByComment); }",
        )],
    )?;

    Ok(())
}

#[test]
fn body_helper_connectivity_is_independent_of_async_result_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let variants = [
        (
            "sync-return",
            "import { exec } from 'node:child_process'; function perform(value) { return exec(value); } export async function POST(request) { const body = await request.json(); const value = String(body.task ?? ''); return perform(value); }",
        ),
        (
            "async-return-await",
            "import { exec } from 'node:child_process'; async function perform(value) { return exec(value); } export async function POST(request) { const body = await request.json(); const value = String(body.task ?? ''); return await perform(value); }",
        ),
        (
            "async-bound-result",
            "import { exec } from 'node:child_process'; async function perform(value) { return exec(value); } export async function POST(request) { const body = await request.json(); const value = String(body.task ?? ''); const answer = await perform(value); return Response.json({ ok: Boolean(answer) }); }",
        ),
        (
            "async-two-arguments",
            "import { exec } from 'node:child_process'; async function perform(value, options) { void options; return exec(value); } export async function POST(request) { const body = await request.json(); const value = String(body.task ?? ''); const answer = await perform(value, { quiet: true }); return Response.json({ ok: Boolean(answer) }); }",
        ),
        (
            "async-two-arguments-and-derived-noise",
            "import { exec } from 'node:child_process'; async function perform(value, options) { void options; const alias = value; return exec(alias); } export async function POST(request) { const body = await request.json(); const value = String(body.task ?? ''); const preview = value.substring(0, 2); if (preview.length > value.length) throw new Error('impossible'); const answer = await perform(value, { quiet: true }); return Response.json({ ok: Boolean(answer) }); }",
        ),
    ];
    let outcomes = variants
        .iter()
        .map(|(name, source)| {
            scan(&[("app/api/queue/route.js", *source)])
                .map(|report| (*name, rule_count(&report, "SE1001")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        outcomes.iter().all(|(_, count)| *count > 0),
        "connectivity outcomes: {outcomes:?}"
    );
    Ok(())
}

#[test]
fn interprocedural_depth_remains_an_explicit_hard_bound() -> Result<(), Box<dyn std::error::Error>>
{
    let files = [(
        "app/api/bounded/route.js",
        "import { exec } from 'node:child_process'; function second(value) { return exec(value); } function first(value) { return second(value); } export async function POST(request) { const body = await request.json(); const task = String(body.task ?? ''); return first(task); }",
    )];
    assert_eq!(
        rule_count(&scan_with_depth(&files, 1)?, "SE1001"),
        0,
        "analysis crossed the configured interprocedural bound"
    );
    assert!(
        rule_count(&scan_with_depth(&files, 2)?, "SE1001") > 0,
        "the bounded two-hop flow was not resolved"
    );
    Ok(())
}

#[test]
fn extended_rounds_preserve_value_bound_redirect_and_path_barriers()
-> Result<(), Box<dyn std::error::Error>> {
    assert_control(
        "SE1005",
        &[(
            "src/navigation.tsx",
            "const SITE = 'https://portal.invalid'; async function cross(value: string, options: object) { void options; const alias = value; const destination = new URL(alias, SITE); if (destination.origin !== SITE) throw new Error('outside'); return Response.redirect(destination, 303); } export async function handler(request: Request) { const body = await request.json(); const requested = String(body.destination ?? ''); const selected = requested; const result = await cross(selected, { audit: true }); return { ok: Boolean(result) }; }",
        )],
    )?;
    assert_vulnerable(
        "SE1005",
        &[(
            "src/navigation.tsx",
            "export function handle(request) { return redirect(request.query.destination); }",
        )],
    )?;

    assert_control(
        "SE1003",
        &[(
            "src/document.jsx",
            "import { readFile, realpath } from 'node:fs/promises'; import { resolve, sep } from 'node:path'; const ZONE = '/opt/archive'; async function openDocument(piece, options) { void options; const alias = piece; const base = await realpath(ZONE); const selected = await realpath(resolve(base, alias)); if (selected !== base && !selected.startsWith(base + sep)) throw new Error('outside'); return readFile(selected, 'utf8'); } export async function handler(request) { const body = await request.json(); const name = String(body.name ?? ''); const forwarded = name; const result = await openDocument(forwarded, { audit: true }); return { ok: Boolean(result) }; }",
        )],
    )?;
    assert_vulnerable(
        "SE1003",
        &[(
            "src/document.jsx",
            "import { readFile } from 'node:fs'; export function handle(request) { return readFile(request.query.name, 'utf8', () => undefined); }",
        )],
    )?;
    Ok(())
}

#[test]
fn resource_authorization_requires_dominance_and_same_value_binding()
-> Result<(), Box<dyn std::error::Error>> {
    assert_control(
        "SE1007",
        &[(
            "app/actions/revise.tsx",
            "'use server'; export async function revise(form: FormData) { const subject = String(form.get('subject') ?? ''); const item = String(form.get('item') ?? ''); if (!(await capabilityPolicy.permits(subject, 'revise', item))) throw new Error('rejected'); return archiveStore.update(item, { state: 'ready' }); }",
        )],
    )?;

    assert_control(
        "SE1007",
        &[(
            "src/change.jsx",
            "async function endpoint(req, res) { const subject = String(req.body.subject ?? ''); const key = String(req.body.key ?? ''); const selected = key; if (!(await membershipPolicy.allows(subject, 'revise', selected))) return res.status(403).end(); const marker = 1; void marker; return vaultRepository.update(key, req.body.patch); } router.patch('/entries/:key', endpoint);",
        )],
    )?;

    assert_control(
        "SE1007",
        &[
            (
                "app/api/entries/route.ts",
                "import { approve as permissionGate } from './decision'; export async function PATCH(request: Request) { const packet = await request.json(); const subject = String(packet.subject ?? ''); const item = String(packet.item ?? ''); if (!(await permissionGate(subject, 'revise', item))) return new Response('denied', { status: 403 }); return resourceRepository.save(item, packet.patch); }",
            ),
            (
                "app/api/entries/decision.ts",
                "export async function approve(subject: string, operation: string, item: string) { return permissionRegistry.includes(subject + ':' + operation + ':' + item); }",
            ),
        ],
    )?;

    let vulnerable = [
        "'use server'; export async function revise(form: FormData) { const subject = String(form.get('subject') ?? ''); const item = String(form.get('item') ?? ''); return archiveStore.update(item, { state: 'ready' }); }",
        "'use server'; export async function revise(form: FormData) { const subject = String(form.get('subject') ?? ''); const item = String(form.get('item') ?? ''); const decoy = String(form.get('decoy') ?? ''); if (!(await capabilityPolicy.permits(subject, 'revise', decoy))) throw new Error('rejected'); return archiveStore.update(item, { state: 'ready' }); }",
        "'use server'; export async function revise(form: FormData) { const subject = String(form.get('subject') ?? ''); const item = String(form.get('item') ?? ''); if (!(await capabilityPolicy.permits(subject, 'revise', item)) && subject === 'guest') throw new Error('maybe'); return archiveStore.update(item, { state: 'ready' }); }",
        "'use server'; export async function revise(form: FormData) { const subject = String(form.get('subject') ?? ''); const item = String(form.get('item') ?? ''); try { if (!(await capabilityPolicy.permits(subject, 'revise', item))) throw new Error('rejected'); } catch { console.info('continuing'); } return archiveStore.update(item, { state: 'ready' }); }",
        "'use server'; export async function revise(form: FormData) { const subject = String(form.get('subject') ?? ''); const item = String(form.get('item') ?? ''); const result = archiveStore.update(item, { state: 'ready' }); if (!(await capabilityPolicy.permits(subject, 'revise', item))) throw new Error('late'); return result; }",
        "'use server'; export async function revise(form: FormData) { const item = String(form.get('item') ?? ''); if (!authorizationLooksSafe(item)) throw new Error('named-safe'); return archiveStore.update(item, { state: 'ready' }); }",
    ];
    for (index, source) in vulnerable.into_iter().enumerate() {
        let report = scan(&[("app/actions/revise.tsx", source)])?;
        assert!(
            rule_count(&report, "SE1007") > 0,
            "authorization near-miss {index} was not reported"
        );
    }

    Ok(())
}

#[test]
fn harmless_renames_and_statements_preserve_phase611_outcomes()
-> Result<(), Box<dyn std::error::Error>> {
    let variants = [
        "function cross(value: string) { return fetch(value); } export async function POST(request: Request) { const boxValue = await request.json(); const input = String(boxValue.endpoint ?? ''); return cross(input); }",
        "function cross(destination: string) { const marker = 1; void marker; return fetch(destination); } export async function POST(request: Request) { const parcel = await request.json(); const target = String(parcel.endpoint ?? ''); const alias = target; return cross(alias); }",
    ];
    for source in variants {
        assert_vulnerable("SE1004", &[("app/api/metamorphic/route.ts", source)])?;
    }
    Ok(())
}
