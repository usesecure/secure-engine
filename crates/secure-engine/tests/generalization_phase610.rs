//! Phase 6.10 Engine-owned authorization-summary and fail-closed regression corpus.

use std::fs;

use secure_engine::{CancellationToken, ScanReport, ScanRequest, scan_repository};
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

fn se1007_count(report: &ScanReport) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1007")
        .count()
}

fn assert_control(files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert_eq!(
        se1007_count(&report),
        0,
        "valid authorization control was reported: {:#?}",
        report.findings
    );
    Ok(())
}

fn assert_vulnerable(files: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(files)?;
    assert!(
        se1007_count(&report) > 0,
        "authorization near-miss was not reported"
    );
    Ok(())
}

#[test]
fn fail_closed_principal_wrappers_preserve_role_proofs_at_callers()
-> Result<(), Box<dyn std::error::Error>> {
    assert_control(&[(
        "src/jobs.js",
        "async function choose(headers) { const principal = await identity.current({ headers }); if (principal.role !== 'operator') return null; return principal; } async function endpoint(req, res) { const actor = await choose(req.headers); if (!actor) return res.status(403).end(); return recordStore.delete(req.body.recordId); } router.delete('/jobs/:id', endpoint);",
    )])?;
    assert_vulnerable(&[(
        "src/jobs.js",
        "async function choose(headers) { const principal = await identity.current({ headers }); return principal; } async function endpoint(req, res) { const actor = await choose(req.headers); if (!actor) return res.status(401).end(); return recordStore.delete(req.body.recordId); } router.delete('/jobs/:id', endpoint);",
    )])?;

    assert_control(&[
        (
            "app/api/catalog/route.ts",
            "import { select as load } from './principal'; export async function DELETE(request: Request) { const actor = await load(request.headers); if (!actor) return new Response('forbidden', { status: 403 }); const payload = await request.json(); return resourceService.remove(payload.recordId); }",
        ),
        (
            "app/api/catalog/principal.ts",
            "export async function select(headers: Headers) { const { principal } = await identity.current({ headers }); if (!principal || principal.role !== 'operator') return null; return principal; }",
        ),
    ])?;
    assert_vulnerable(&[
        (
            "app/api/catalog/route.ts",
            "import { select as load } from './principal'; export async function DELETE(request: Request) { const actor = await load(request.headers); if (!actor) return new Response('forbidden', { status: 403 }); const payload = await request.json(); return resourceService.remove(payload.recordId); }",
        ),
        (
            "app/api/catalog/principal.ts",
            "export async function select(headers: Headers) { const { principal } = await identity.current({ headers }); if (!principal) return null; return principal; }",
        ),
    ])?;

    assert_control(&[
        (
            "app/api/archive/route.ts",
            "import { choose } from '@/api/archive/access'; export async function DELETE(request: Request) { const context = await choose(); if (!context) return new Response('forbidden', { status: 403 }); const body = await request.json(); return recordStore.remove(body.recordId); }",
        ),
        (
            "app/api/archive/access.ts",
            "import { read } from '@/api/archive/context'; export async function choose() { const context = await read(); const level = context?.principal?.role?.toString().toLowerCase(); return level === 'operator' || level === 'maintainer' ? context : null; }",
        ),
        (
            "app/api/archive/context.ts",
            "export async function read() { return identity.current({ headers: await headers() }); }",
        ),
    ])?;
    Ok(())
}

#[test]
fn request_bound_boolean_helpers_preserve_authorization_proofs()
-> Result<(), Box<dyn std::error::Error>> {
    assert_control(&[(
        "src/router.jsx",
        "async function decide(request) { const principal = await identity.current({ headers: request.headers }); return principal?.role === 'operator'; } async function endpoint(req, res) { const accepted = await decide(req); if (!accepted) return res.status(403).end(); return database.update(req.body.recordId); } router.patch('/records/:id', endpoint);",
    )])?;
    assert_vulnerable(&[(
        "src/router.jsx",
        "async function decide(request) { const principal = await identity.current({ headers: request.headers }); return principal?.role === request.body.role; } async function endpoint(req, res) { const accepted = await decide(req); if (!accepted) return res.status(403).end(); return database.update(req.body.recordId); } router.patch('/records/:id', endpoint);",
    )])?;

    assert_control(&[
        (
            "app/actions/change.tsx",
            "'use server'; import { decide as check } from './decision'; export async function change(form: FormData) { const request = { headers: await headers() }; const accepted = await check(request); if (!accepted) redirect('/denied'); return repository.save(String(form.get('recordId') ?? '')); }",
        ),
        (
            "app/actions/decision.ts",
            "export async function decide(request: { headers: Headers }) { const principal = await identity.current({ headers: request.headers }); return principal?.permissions.includes('records:write') === true; }",
        ),
    ])?;
    assert_vulnerable(&[
        (
            "app/actions/change.tsx",
            "'use server'; import { decide as check } from './decision'; export async function change(form: FormData) { const request = { headers: await headers() }; const accepted = await check(request); if (!accepted) redirect('/denied'); return repository.save(String(form.get('recordId') ?? '')); }",
        ),
        (
            "app/actions/decision.ts",
            "export async function decide(request: { headers: Headers }) { const principal = await identity.current({ headers: request.headers }); return Boolean(principal); }",
        ),
    ])?;

    assert_control(&[
        (
            "app/api/plans/route.ts",
            "import { decide } from './decision'; export async function PATCH(request: Request) { const accepted = await decide(request); if (!accepted) return new Response('forbidden', { status: 403 }); const body = await request.json(); return resourceService.update(body.recordId); }",
        ),
        (
            "app/api/plans/decision.ts",
            "import { read } from './context'; export async function decide(request: Request) { const context = await read(request); const level = context?.principal?.role?.toString().toLowerCase(); return level === 'operator' || level === 'maintainer'; }",
        ),
        (
            "app/api/plans/context.ts",
            "export async function read(request: Request) { return identity.current({ headers: request.headers }); }",
        ),
    ])?;
    Ok(())
}

#[test]
fn compound_identity_authorization_binds_authenticated_and_server_values()
-> Result<(), Box<dyn std::error::Error>> {
    assert_control(&[(
        "app/api/bootstrap/route.ts",
        "export async function POST(request: Request) { const session = await identity.current({ headers: request.headers }); if (!session?.principal) return new Response('unauthorized', { status: 401 }); const designated = await database.account.findFirst({ orderBy: { createdAt: 'asc' } }); if (!designated || designated.id !== session.principal.id) return new Response('forbidden', { status: 403 }); const body = await request.json(); return database.account.create({ data: body }); }",
    )])?;
    assert_vulnerable(&[(
        "app/api/bootstrap/route.ts",
        "export async function POST(request: Request) { const session = await identity.current({ headers: request.headers }); if (!session?.principal) return new Response('unauthorized', { status: 401 }); const designated = await database.account.findFirst({ orderBy: { createdAt: 'asc' } }); const body = await request.json(); if (!designated || designated.id !== body.accountId) return new Response('forbidden', { status: 403 }); return database.account.create({ data: body }); }",
    )])?;

    assert_control(&[(
        "app/actions/bootstrap.tsx",
        "'use server'; export async function bootstrap(form: FormData) { const principal = await identity.current(); if (!principal) throw new Error('unauthenticated'); const designated = await accountRepository.findFirst({ orderBy: { createdAt: 'asc' } }); if (!designated || designated.id !== principal.id) throw new Error('forbidden'); return accountRepository.create({ data: { email: String(form.get('email') ?? '') } }); }",
    )])?;
    assert_vulnerable(&[(
        "app/actions/bootstrap.tsx",
        "'use server'; export async function bootstrap(form: FormData) { const principal = await identity.current(); if (!principal) throw new Error('unauthenticated'); const designated = await accountRepository.findFirst({ orderBy: { createdAt: 'asc' } }); if (!designated || designated.id !== principal.id) console.warn('forbidden'); return accountRepository.create({ data: { email: String(form.get('email') ?? '') } }); }",
    )])?;

    assert_control(&[
        (
            "app/api/setup/route.ts",
            "import { read } from '@/api/setup/context'; export async function POST(request: Request) { const context = await read(request); if (!context?.principal) return new Response('unauthorized', { status: 401 }); const designated = await accountRepository.findFirst({ orderBy: { createdAt: 'asc' } }); if (!designated || designated.id !== context.principal.id) return new Response('forbidden', { status: 403 }); const body = await request.json(); return accountRepository.create({ data: body }); }",
        ),
        (
            "app/api/setup/context.ts",
            "export async function read(request: Request) { return identity.current({ headers: request.headers }); }",
        ),
    ])?;

    assert_control(&[
        (
            "app/api/enrollment/route.ts",
            "import { load } from '@/api/enrollment/context'; export async function POST(request: Request) { try { const context = await load(request); if (!context?.principal) return new Response('unauthorized', { status: 401 }); const designated = await accountRepository.findFirst({ orderBy: { createdAt: 'asc' } }); if (!designated || designated.id !== context.principal.id) return new Response('forbidden', { status: 403 }); return accountRepository.create({ data: await request.json() }); } catch { return new Response('failed', { status: 500 }); } }",
        ),
        (
            "app/api/enrollment/context.ts",
            "export async function load(request: Request) { return identity.current({ headers: request.headers }); }",
        ),
    ])?;
    assert_vulnerable(&[
        (
            "app/api/enrollment/route.ts",
            "import { load } from '@/api/enrollment/context'; export async function POST(request: Request) { let context; let designated; try { context = await load(request); designated = await accountRepository.findFirst({ orderBy: { createdAt: 'asc' } }); if (!context?.principal || !designated || designated.id !== context.principal.id) throw new Error('forbidden'); } catch { console.info('continue'); } return accountRepository.create({ data: await request.json() }); }",
        ),
        (
            "app/api/enrollment/context.ts",
            "export async function load(request: Request) { return identity.current({ headers: request.headers }); }",
        ),
    ])?;
    Ok(())
}

#[test]
fn try_catch_finally_authorization_is_structural_and_conservative()
-> Result<(), Box<dyn std::error::Error>> {
    assert_control(&[(
        "src/operations.ts",
        "export async function PATCH(request: Request) { const actor = await identity.current({ headers: request.headers }); try { if (actor?.role !== 'operator') return new Response('forbidden', { status: 403 }); return recordStore.update((await request.json()).recordId); } catch { return new Response('failed', { status: 500 }); } }",
    )])?;
    assert_control(&[(
        "src/operations.tsx",
        "export async function PATCH(request: Request) { const actor = await identity.current({ headers: request.headers }); try { if (actor?.role !== 'operator') return new Response('forbidden', { status: 403 }); return recordStore.update((await request.json()).recordId); } catch { return new Response('failed', { status: 500 }); } finally { const completed = actor !== null; void completed; } }",
    )])?;

    let vulnerable = [
        "export async function PATCH(request: Request) { const actor = await identity.current({ headers: request.headers }); try { if (actor?.role !== 'operator') return new Response('forbidden', { status: 403 }); } catch { return new Response('failed', { status: 500 }); } finally { return recordStore.update((await request.json()).recordId); } }",
        "export async function PATCH(request: Request) { const actor = await identity.current({ headers: request.headers }); try { try { if (actor?.role !== 'operator') return new Response('forbidden', { status: 403 }); } finally { throw new Error('override'); } } catch {} return recordStore.update((await request.json()).recordId); }",
        "export async function PATCH(request: Request) { const actor = await identity.current({ headers: request.headers }); try { try { if (actor?.role !== 'operator') return new Response('forbidden', { status: 403 }); } finally { redirect('/elsewhere'); } } catch {} return recordStore.update((await request.json()).recordId); }",
        "export async function PATCH(request: Request) { let actor = await identity.current({ headers: request.headers }); try { if (actor?.role !== 'operator') return new Response('forbidden', { status: 403 }); } catch { return new Response('failed', { status: 500 }); } finally { actor = fallbackActor; } return recordStore.update((await request.json()).recordId); }",
        "export async function PATCH(request: Request) { const actor = await identity.current({ headers: request.headers }); for (let index = 0; index < 1; index += 1) { try { if (actor?.role !== 'operator') return new Response('forbidden', { status: 403 }); break; } finally { continue; } } return recordStore.update((await request.json()).recordId); }",
        "export async function PATCH(request: Request) { const actor = await identity.current({ headers: request.headers }); try { if (actor?.role !== 'operator') throw new Error('forbidden'); } catch {} return recordStore.update((await request.json()).recordId); }",
        "export async function PATCH(request: Request) { const actor = await identity.current({ headers: request.headers }); try { if (actor?.role !== 'operator') redirect('/elsewhere'); } catch {} return recordStore.update((await request.json()).recordId); }",
    ];
    for (index, source) in vulnerable.into_iter().enumerate() {
        let path = format!("src/scenario-{index}.jsx");
        let report = scan(&[(&path, source)])?;
        assert!(
            se1007_count(&report) > 0,
            "try/catch/finally near-miss {index} was not reported"
        );
    }
    Ok(())
}

#[test]
fn exceptional_rejection_requires_all_catch_paths_to_terminate()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') throw new Error('denied'); await ledgerRepository.update((await request.json()).entryId); return ledgerRepository.remove('expired'); } catch (failure) { throw failure; } }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') throw new Error('denied'); return ledgerRepository.update((await request.json()).entryId); } catch { return new Response('rejected', { status: 403 }); } }",
        "function leaveImmediately() { throw new Error('closed'); } export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') throw new Error('denied'); return ledgerRepository.update((await request.json()).entryId); } catch { leaveImmediately(); } }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') { if (request.headers.has('x-mode')) return new Response('rejected', { status: 403 }); throw new Error('denied'); } return ledgerRepository.update((await request.json()).entryId); } catch { return new Response('rejected', { status: 403 }); } }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { try { if (principal?.role !== 'operator') throw new Error('denied'); return ledgerRepository.update((await request.json()).entryId); } catch (failure) { throw failure; } } catch { return new Response('rejected', { status: 403 }); } finally { const observed = principal !== null; void observed; } }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        let path = format!("src/independent/control-{index}.ts");
        let report = scan(&[(&path, source)])?;
        assert_eq!(
            se1007_count(&report),
            0,
            "exceptional control {index} was reported: {:#?}",
            report.findings
        );
    }

    let vulnerable = [
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') throw new Error('denied'); } catch (failure) { console.info(failure); } return ledgerRepository.update((await request.json()).entryId); }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') throw new Error('denied'); } catch (failure) { if (request.headers.has('x-stop')) throw failure; } return ledgerRepository.update((await request.json()).entryId); }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') throw new Error('denied'); } catch {} return ledgerRepository.update((await request.json()).entryId); }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') throw new Error('denied'); } catch (failure) { throw failure; } finally { ledgerRepository.update((await request.json()).entryId); } }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); for (let index = 0; index < 1; index += 1) { try { if (principal?.role !== 'operator') throw new Error('denied'); break; } finally { continue; } } return ledgerRepository.update((await request.json()).entryId); }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); const proposed = await request.json(); try { if (proposed.role !== 'operator') throw new Error('denied'); return ledgerRepository.update(proposed.entryId); } catch (failure) { throw failure; } }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { try { if (principal?.role !== 'operator') throw new Error('denied'); } catch (failure) { throw failure; } } catch {} return ledgerRepository.update((await request.json()).entryId); }",
        "declare function maybeStops(): void; export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') throw new Error('denied'); } catch { maybeStops(); } return ledgerRepository.update((await request.json()).entryId); }",
        "function leaveImmediately() { return; } export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') throw new Error('denied'); } catch { leaveImmediately(); } return ledgerRepository.update((await request.json()).entryId); }",
        "export async function revise(request: Request) { const principal = await identity.current({ headers: request.headers }); try { if (principal?.role !== 'operator') redirect('/rejected'); } catch {} return ledgerRepository.update((await request.json()).entryId); }",
    ];
    for (index, source) in vulnerable.into_iter().enumerate() {
        let path = format!("src/independent/near-miss-{index}.tsx");
        let report = scan(&[(&path, source)])?;
        assert!(
            se1007_count(&report) > 0,
            "exceptional near-miss {index} was not reported"
        );
    }
    Ok(())
}

#[test]
fn adversarial_authorization_mutations_remain_findings() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        "'use server'; async function permissionGate() { return true; } export async function change(form) { if (!await permissionGate()) throw new Error('deny'); return recordStore.update(form.get('id')); }",
        "'use server'; async function oddlyNamedGuard(request) { const principal = await identity.current({ headers: request.headers }); return principal?.role === request.body.role; } export async function change(request) { if (!await oddlyNamedGuard(request)) return null; return recordStore.update(request.body.id); }",
        "'use server'; async function decide(request) { const principal = await identity.current({ headers: request.headers }); try { if (principal.role !== 'operator') throw new Error('deny'); } catch { console.info('continue'); } return true; } export async function change(request) { if (!await decide(request)) return null; return recordStore.update(request.body.id); }",
        "'use server'; async function choose() { const principal = await identity.current(); if (principal.role !== 'operator') return null; return principal ?? fallbackPrincipal; } export async function change(request) { if (!await choose()) return null; return recordStore.update(request.body.id); }",
        "'use server'; async function decide() { const principal = await identity.current(); return principal?.role === 'operator'; } export async function change(request) { const accepted = await decide(); const result = recordStore.update(request.body.id); if (!accepted) return null; return result; }",
        "'use server'; async function decide(request) { const principal = await identity.current({ headers: request.headers }); return principal?.role === 'operator'; } export async function change(request) { let accepted = await decide(request); accepted = true; if (!accepted) return null; return recordStore.update(request.body.id); }",
        "'use server'; export async function change(request) { const principal = await identity.current({ headers: request.headers }); const designated = await accountRepository.findFirst(); if (!designated || designated.id !== request.body.id) return null; return recordStore.update(request.body.target); }",
        "'use server'; async function getSession(request) { return request.body; } async function choose(request) { const principal = await getSession(request); if (principal.role !== 'operator') return null; return principal; } export async function change(request) { if (!await choose(request)) return null; return recordStore.update(request.body.id); }",
        "'use server'; async function choose() { const principal = await identity.current(); try { return principal.role === 'operator' ? principal : null; } catch { return fallbackPrincipal; } } export async function change(request) { if (!await choose()) return null; return recordStore.update(request.body.id); }",
    ];
    for source in cases {
        assert_vulnerable(&[("app/actions/adversarial.ts", source)])?;
    }

    let deceptive_report = scan(&[(
        "app/api/approved/safe/route.ts",
        "// This optimistic prose and every identifier are intentionally non-evidence.\nasync function guaranteedAuthorization() { return true; } export async function PATCH(request: Request) { if (!await guaranteedAuthorization()) return new Response('forbidden', { status: 403 }); return recordStore.update((await request.json()).recordId); }",
    )])?;
    assert!(
        se1007_count(&deceptive_report) > 0,
        "function names, comments, and optimistic paths became authorization evidence"
    );

    assert_vulnerable(&[
        (
            "app/api/ambiguous/route.ts",
            "import { decide } from './a'; import { decide } from './b'; export async function POST(request: Request) { if (!await decide(request)) return null; return recordStore.update((await request.json()).id); }",
        ),
        (
            "app/api/ambiguous/a.ts",
            "export async function decide(request) { const principal = await identity.current({ headers: request.headers }); return principal?.role === 'operator'; }",
        ),
        (
            "app/api/ambiguous/b.ts",
            "export async function decide() { return true; }",
        ),
    ])?;
    Ok(())
}
