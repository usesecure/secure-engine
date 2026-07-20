//! Phase 6.12 tranche 2 independent derived-identity and resource-identity fixtures.

use std::fs;

use secure_engine::{CacheControl, CancellationToken, ScanReport, ScanRequest, scan_repository};
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

fn assert_vulnerable(rule: &str, files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert!(
        count(&report, rule) > 0,
        "expected {rule}; files={files:?}; findings={:#?}",
        report.findings
    );
    Ok(())
}

#[test]
fn exact_url_object_guards_protect_only_typed_relative_projections()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "const BASE = 'https://orchard.example:9443'; export function forward(req) { const parsed = new URL(req.query.route, BASE); if (parsed.origin !== BASE) throw new Error('outside'); const relative = parsed.pathname + parsed.search + parsed.hash; return Response.redirect(relative); }",
        "const BASE = 'https://orchard.example:9443'; function choose(raw) { const address = URL.parse(raw, BASE); if (address.origin !== BASE) return null; return address.pathname + address.search + address.hash; } export function forward(req) { return Response.redirect(choose(req.body.route)); }",
        "import { redirect as transfer } from 'next/navigation'; const BASE = 'https://orchard.example:9443'; export function forward(req) { const parsed = new URL(req.params.route, BASE); if (parsed.origin !== BASE) throw new Error('outside'); return transfer(parsed.pathname + parsed.search + parsed.hash); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control(
            "SE1005",
            &[(&format!("src/route-control-{index}.ts"), source)],
        )?;
    }
    Ok(())
}

#[test]
fn redirect_wrong_value_mutation_and_control_flow_remain_vulnerable()
-> Result<(), Box<dyn std::error::Error>> {
    let variants = [
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); if (!parsed.hostname.endsWith('orchard.example')) throw new Error('outside'); return Response.redirect(parsed.pathname); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); if (!parsed.origin.includes(BASE)) throw new Error('outside'); return Response.redirect(parsed.pathname); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const checked = new URL(req.query.route, BASE); if (checked.origin !== BASE) throw new Error('outside'); const other = new URL(req.query.route, BASE); return Response.redirect(other.pathname); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); if (parsed.origin !== BASE) throw new Error('outside'); parsed.pathname = req.body.path; return Response.redirect(parsed.pathname); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { let raw = req.query.route; const parsed = new URL(raw, BASE); if (parsed.origin !== BASE) throw new Error('outside'); raw = raw.trim(); return Response.redirect(parsed.pathname); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); let relative = parsed.pathname; if (parsed.origin !== BASE) throw new Error('outside'); relative = req.body.other; return Response.redirect(relative); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); let relative = parsed.pathname; if (parsed.origin !== BASE) throw new Error('outside'); relative = parsed.pathname; return Response.redirect(relative); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); try { if (parsed.origin !== BASE) throw new Error('outside'); } catch { console.info('continue'); } return Response.redirect(parsed.pathname); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); try { if (parsed.origin !== BASE) throw new Error('outside'); } finally { audit(parsed); } return Response.redirect(parsed.pathname); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); if (req.query.enforce && parsed.origin !== BASE) throw new Error('outside'); return Response.redirect(parsed.pathname); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); if (parsed.origin !== BASE) throw new Error('outside'); const absolute = BASE + parsed.pathname; return Response.redirect(absolute); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); if (parsed.origin !== BASE) throw new Error('outside'); const key = req.query.part; return Response.redirect(parsed[key]); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const first = new URL(req.query.route, BASE); const second = new URL(req.body.route, BASE); const parsed = req.query.mode ? first : second; if (parsed.origin !== BASE) throw new Error('outside'); return Response.redirect(parsed.pathname); }",
        "const BASE = 'https://orchard.example'; export function forward(req) { const parsed = new URL(req.query.route, BASE); if (parsed.origin !== BASE) throw new Error('outside'); const relative = deriveRelative(parsed); return Response.redirect(relative); }",
    ];
    for (index, source) in variants.into_iter().enumerate() {
        assert_vulnerable(
            "SE1005",
            &[(&format!("src/route-adversary-{index}.js"), source)],
        )?;
    }
    Ok(())
}

const DIRECT_RESOURCE_CONTROL: &str = "export async function revise(req) { const requested = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: requested } }); if (!parcel) return new Response('missing', { status: 404 }); if (parcel.tenantId !== session.principal.tenantId) return new Response('denied', { status: 403 }); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); const canonical = parcel.id; return warehouseRepository.update(canonical, { state: 'packed' }); }";

#[test]
fn complete_resource_identity_proof_uses_loaded_record_and_trusted_principal()
-> Result<(), Box<dyn std::error::Error>> {
    assert_control(
        "SE1007",
        &[("src/inventory/direct.ts", DIRECT_RESOURCE_CONTROL)],
    )?;
    assert_control(
        "SE1007",
        &[(
            "src/inventory/helper.ts",
            "async function authenticated(headers) { const context = await identity.current({ headers }); return context; } export async function revise(req) { const requested = req.body.key; const actor = await authenticated(req.headers); const shipment = await depotRepository.getById(requested); if (shipment.workspaceId !== actor.principal.workspaceId) throw new Error('denied'); if (shipment.memberId !== actor.principal.id) return null; return depotRepository.save(shipment.id, { state: 'sealed' }); }",
        )],
    )?;
    assert_control(
        "SE1007",
        &[(
            "app/actions/metamorphic.tsx",
            "'use server'; export async function alter(form: FormData) { const token = String(form.get('key') ?? ''); const envelope = await auth.session.current(); const unit = await crateRepository.findOne({ resourceId: token }); if (unit.organizationId !== envelope.principal.organizationId) return null; if (unit.accountId !== envelope.principal.id) return null; return crateRepository.archive(unit.id); }",
        )],
    )?;
    assert_control(
        "SE1007",
        &[(
            "src/inventory/destructured.js",
            "export async function revise(req) { const requested = req.query.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: requested } }); const { id: canonical, tenantId: parcelTenant, ownerId: parcelOwner } = parcel; const { tenantId: actorTenant, id: actorId } = session.principal; if (parcelTenant !== actorTenant) throw new Error('denied'); if (parcelOwner !== actorId) throw new Error('denied'); return warehouseRepository.update(canonical, req.body.patch); }",
        )],
    )?;
    Ok(())
}

#[test]
fn incomplete_or_wrong_resource_identity_never_becomes_a_barrier()
-> Result<(), Box<dyn std::error::Error>> {
    let variants = [
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const checked = await warehouseRepository.findUnique({ where: { id: key } }); const other = await warehouseRepository.findUnique({ where: { id: req.body.other } }); if (checked.tenantId !== session.principal.tenantId) throw new Error('denied'); if (checked.ownerId !== session.principal.id) throw new Error('denied'); return warehouseRepository.update(other.id, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const actor = req.body.actor; const parcel = await warehouseRepository.findUnique({ where: { id: key } }); if (parcel.tenantId !== actor.tenantId) throw new Error('denied'); if (parcel.ownerId !== actor.id) throw new Error('denied'); return warehouseRepository.update(parcel.id, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); if (parcel.tenantId !== session.principal.tenantId) throw new Error('denied'); return warehouseRepository.update(parcel.id, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); return warehouseRepository.update(parcel.id, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); if (parcel.tenantId !== session.principal.tenantId) console.warn('tenant'); if (parcel.ownerId !== session.principal.id) console.warn('owner'); return warehouseRepository.update(parcel.id, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); const result = warehouseRepository.update(parcel.id, req.body.patch); if (parcel.tenantId !== session.principal.tenantId) throw new Error('denied'); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); return result; }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); if (parcel.tenantId !== session.principal.tenantId) throw new Error('denied'); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); let canonical = parcel.id; canonical = req.body.other; return warehouseRepository.update(canonical, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); if (parcel.tenantId !== session.principal.tenantId) throw new Error('denied'); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); let canonical = parcel.id; canonical = parcel.id; return warehouseRepository.update(canonical, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); if (parcel.tenantId !== session.principal.tenantId) throw new Error('denied'); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); parcel.ownerId = session.principal.id; return warehouseRepository.update(parcel.id, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); if (parcel.tenantId !== session.principal.tenantId) throw new Error('denied'); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); return warehouseRepository.update(req.body.other, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); const decoy = await warehouseRepository.findUnique({ where: { id: req.body.other } }); const selected = req.query.mode ? parcel : decoy; if (parcel.tenantId !== session.principal.tenantId) throw new Error('denied'); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); return warehouseRepository.update(selected.id, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); try { if (parcel.tenantId !== session.principal.tenantId) throw new Error('denied'); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); } catch { console.info('continue'); } return warehouseRepository.update(parcel.id, req.body.patch); }",
        "export async function revise(req) { const key = req.params.key; const session = await identity.current(); const parcel = await warehouseRepository.findUnique({ where: { id: key } }); try { if (parcel.tenantId !== session.principal.tenantId) throw new Error('denied'); if (parcel.ownerId !== session.principal.id) throw new Error('denied'); } finally { audit(parcel); } return warehouseRepository.update(parcel.id, req.body.patch); }",
    ];
    for (index, source) in variants.into_iter().enumerate() {
        assert_vulnerable(
            "SE1007",
            &[(&format!("src/inventory/adversary-{index}.ts"), source)],
        )?;
    }
    Ok(())
}

#[test]
fn tranche2_spans_fingerprints_and_cache_are_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    let path = repository.path().join("src/inventory/handler.ts");
    fs::create_dir_all(path.parent().ok_or("fixture path has no parent")?)?;
    fs::write(&path, DIRECT_RESOURCE_CONTROL)?;
    let cache = TempDir::new()?;
    let mut request = ScanRequest::new(repository.path());
    request.cache = CacheControl {
        directory: Some(cache.path().to_path_buf()),
        clear_before_scan: false,
    };
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert_eq!(cold.facts, warm.facts);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.findings, warm.findings);
    assert!(cold.parsing.cache_writes > 0);
    assert!(warm.parsing.cache_hits > 0);
    assert!(cache.path().join("secure-parse-cache-v16").is_dir());
    Ok(())
}
