//! Phase 6.11 tranche 3 independent redirect-origin and outbound-property fixtures.

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
fn constructed_redirects_remain_vulnerable_across_supported_topologies()
-> Result<(), Box<dyn std::error::Error>> {
    let vulnerable = [
        (
            "src/navigation.js",
            "const HOME = 'https://harbor.example'; export function navigate(req) { const destination = new URL(req.query.next); return Response.redirect(destination); }",
        ),
        (
            "src/navigation.jsx",
            "const HOME = 'https://harbor.example'; export function navigate(req) { const destination = new URL(req.body.next, HOME); return redirect(destination); }",
        ),
        (
            "src/navigation.ts",
            "const HOME = 'https://harbor.example'; function assemble(fragment: string) { return new URL(fragment, HOME); } export function navigate(req: any) { const destination = assemble(req.params.next); return Response.redirect(destination, 302); }",
        ),
        (
            "app/actions/navigation.tsx",
            "'use server'; const HOME = 'https://harbor.example'; function assemble(fragment: string) { const forwarded = fragment; return new URL(forwarded, HOME); } export async function navigate(form: FormData) { const fragment = String(form.get('next') ?? ''); return redirect(assemble(fragment)); }",
        ),
        (
            "src/property-navigation.tsx",
            "const HOME = 'https://harbor.example'; export function navigate(req: any) { const state = { destination: new URL(req.body.next, HOME), audit: 'fixed' }; return Response.redirect(state.destination); }",
        ),
    ];
    for (path, source) in vulnerable {
        assert_detected("SE1005", &[(path, source)])?;
    }
    assert_detected(
        "SE1005",
        &[
            (
                "app/api/navigation/route.ts",
                "import { assemble } from './destination'; export async function POST(request: Request) { const packet = await request.json(); const destination = assemble(String(packet.next ?? '')); return Response.redirect(destination, 307); }",
            ),
            (
                "app/api/navigation/destination.ts",
                "const HOME = 'https://harbor.example'; export function assemble(fragment: string) { return new URL(fragment, HOME); }",
            ),
        ],
    )?;
    Ok(())
}

#[test]
fn exact_origin_guard_cleans_only_the_same_unmodified_redirect_value()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "const HOME = 'https://harbor.example:8443'; export function navigate(req) { const destination = new URL(req.query.next, HOME); if (destination.origin !== HOME) throw new Error('outside'); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example:8443'; export function navigate(req) { const destination = new URL(req.query.next, HOME); const approved = destination; if (approved.origin !== HOME) return null; return Response.redirect(destination); }",
        "export function navigate(req) { const destination = new URL(req.query.next, 'https://harbor.example:8443'); if (destination.origin !== 'https://harbor.example:8443') throw new Error('outside'); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example:8443'; export function navigate(req) { const state = { destination: new URL(req.query.next, HOME), audit: 'fixed' }; if (state.destination.origin !== HOME) throw new Error('outside'); return Response.redirect(state.destination); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control("SE1005", &[(&format!("src/exact-{index}.tsx"), source)])?;
    }
    assert_control(
        "SE1005",
        &[
            (
                "app/api/approved-navigation/route.ts",
                "import { select } from './policy'; export async function POST(request: Request) { const packet = await request.json(); const destination = select(String(packet.next ?? '')); return Response.redirect(destination, 303); }",
            ),
            (
                "app/api/approved-navigation/policy.ts",
                "const HOME = 'https://harbor.example:8443'; export function select(fragment: string) { const destination = new URL(fragment, HOME); if (destination.origin !== HOME) throw new Error('outside'); return destination; }",
            ),
        ],
    )?;
    Ok(())
}

#[test]
fn redirect_near_misses_cannot_prove_exact_origin() -> Result<(), Box<dyn std::error::Error>> {
    let vulnerable = [
        "const HOME = 'https://harbor.example'; export function navigate(req) { const destination = new URL(req.query.next, HOME); if (!destination.href.startsWith(HOME)) throw new Error('outside'); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example'; export function navigate(req) { const destination = new URL(req.query.next, HOME); if (!destination.hostname.endsWith('harbor.example')) throw new Error('outside'); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example'; export function navigate(req) { const destination = new URL(req.query.next, HOME); if (destination.hostname !== 'harbor.example') throw new Error('outside'); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example'; export function navigate(req) { const destination = new URL(req.query.next, HOME); if (!destination.href.includes('@harbor.example')) throw new Error('outside'); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example'; export function navigate(req) { const destination = new URL(req.query.next, HOME); const approved = new Set([req.query.allowed]); if (!approved.has(destination.origin)) throw new Error('outside'); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example'; export function navigate(req) { const checked = new URL(req.query.next, HOME); if (checked.origin !== HOME) throw new Error('outside'); const destination = new URL(req.query.next, HOME); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example'; export function navigate(req) { const destination = new URL(req.query.next, HOME); const result = Response.redirect(destination); if (destination.origin !== HOME) throw new Error('late'); return result; }",
        "const HOME = 'https://harbor.example'; export function navigate(req) { let destination = new URL(req.query.next, HOME); if (destination.origin !== HOME) throw new Error('outside'); destination = new URL(req.body.fallback, HOME); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example'; export function navigate(req) { const destination = new URL(req.query.next, HOME); try { if (destination.origin !== HOME) throw new Error('outside'); } catch { console.warn('continuing'); } return Response.redirect(destination); }",
        "export function navigate(req) { const home = req.query.origin; const destination = new URL(req.query.next, home); if (destination.origin !== home) throw new Error('outside'); return Response.redirect(destination); }",
        "const HOME = 'https://harbor.example'; const BLOCKED = new Set(['https://malicious.example']); export function navigate(req) { const destination = new URL(req.query.next, HOME); if (BLOCKED.has(destination.origin)) throw new Error('outside'); return Response.redirect(destination); }",
    ];
    for (index, source) in vulnerable.into_iter().enumerate() {
        assert_detected(
            "SE1005",
            &[(&format!("src/redirect-near-miss-{index}.tsx"), source)],
        )?;
    }
    Ok(())
}

#[test]
fn outbound_properties_connect_through_remap_destructuring_helpers_and_imports()
-> Result<(), Box<dyn std::error::Error>> {
    let vulnerable = [
        "export function relay(req) { const parcel = { endpoint: req.body.target }; return fetch(parcel.endpoint); }",
        "export function relay(req) { const parcel = { endpoint: req.query.target }; const { endpoint: selected } = parcel; return fetch(selected); }",
        "export function relay(req) { const parcel = { transport: { endpoint: req.params.target } }; const { transport: { endpoint: selected } } = parcel; return fetch(selected); }",
        "function transmit({ endpoint }) { return fetch(endpoint); } export function relay(req) { const parcel = { endpoint: req.body.target, audit: 'fixed' }; return transmit(parcel); }",
    ];
    for (index, source) in vulnerable.into_iter().enumerate() {
        assert_detected("SE1004", &[(&format!("src/outbound-{index}.tsx"), source)])?;
    }
    let direct_source = vulnerable[0];
    let direct = scan(&[("src/span.js", direct_source)])?;
    let finding = direct
        .findings
        .iter()
        .find(|finding| finding.rule_id == "SE1004")
        .ok_or("direct property finding missing")?;
    let source = finding.source.as_ref().ok_or("source span missing")?;
    let sink = finding.sink.as_ref().ok_or("sink span missing")?;
    assert_eq!(
        &direct_source
            [usize::try_from(source.span.start_byte)?..usize::try_from(source.span.end_byte)?],
        "req.body.target"
    );
    assert_eq!(
        &direct_source
            [usize::try_from(sink.span.start_byte)?..usize::try_from(sink.span.end_byte)?],
        "fetch(parcel.endpoint)"
    );
    assert_detected(
        "SE1004",
        &[
            (
                "app/api/relay/route.ts",
                "import { transmit } from './transport'; export async function POST(request: Request) { const packet = await request.json(); const parcel = { endpoint: packet.target, audit: 'fixed' }; return transmit(parcel); }",
            ),
            (
                "app/api/relay/transport.ts",
                "export function transmit({ endpoint }: { endpoint: string }) { return fetch(endpoint); }",
            ),
        ],
    )?;
    Ok(())
}

#[test]
fn outbound_property_controls_preserve_field_and_argument_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let controls = [
        "export function relay(req) { const parcel = { endpoint: 'https://api.harbor.example/health', audit: req.body.target }; return fetch(parcel.endpoint); }",
        "export function relay(req) { const parcel = { endpoint: req.body.target }; const parsed = new URL(parcel.endpoint); if (parsed.protocol !== 'https:' || parsed.hostname !== 'api.harbor.example') throw new Error('outside'); return fetch(parsed); }",
        "export function relay(req) { const field = req.body.field; const parcel = { [field]: req.body.target, endpoint: 'https://api.harbor.example/health' }; return fetch(parcel.endpoint); }",
        "export function relay(req) { const source = { endpoint: req.body.target }; const parcel = { ...source }; return fetch(parcel.endpoint); }",
        "export function relay(req) { const parcel = { endpoint: req.body.target }; parcel.endpoint = 'https://api.harbor.example/health'; return fetch(parcel.endpoint); }",
        "export function relay(req) { let parcel = { endpoint: req.body.target }; parcel = { endpoint: 'https://api.harbor.example/health' }; return fetch(parcel.endpoint); }",
        "export function relay(req) { const parcel = { endpoint: 'https://api.harbor.example/health', secondary: req.body.target }; return fetch(parcel.endpoint); }",
        "export function relay(req) { const options = { audit: req.body.target }; return request('https://api.harbor.example/health', options); }",
        "function transmit({ endpoint }) { return fetch(endpoint); } export function relay(req) { return transmit({ ...req.body, endpoint: 'https://api.harbor.example/health' }); }",
        "function first(parcel) { return fetch('/health'); } function second(parcel) { return fetch('/health'); } export function relay(req) { const parcel = { endpoint: req.body.target }; const transmit = req.body.mode ? first : second; return transmit(parcel); }",
    ];
    for (index, source) in controls.into_iter().enumerate() {
        assert_control(
            "SE1004",
            &[(&format!("src/outbound-control-{index}.jsx"), source)],
        )?;
    }
    Ok(())
}

#[test]
fn outbound_property_near_misses_remain_conservative() -> Result<(), Box<dyn std::error::Error>> {
    let vulnerable = [
        "export function relay(req) { const parcel = { endpoint: req.body.target, other: 'https://api.harbor.example' }; const selected = parcel.endpoint; return fetch(selected); }",
        "function transmit(first, second) { void first; return fetch(second.endpoint); } export function relay(req) { const safe = { endpoint: 'https://api.harbor.example' }; const unsafe = { endpoint: req.body.target }; return transmit(safe, unsafe); }",
        "export function relay(req) { const parcel = { wrapper: { endpoint: req.body.target } }; const selected = parcel.wrapper.endpoint; return fetch(selected); }",
    ];
    for (index, source) in vulnerable.into_iter().enumerate() {
        assert_detected(
            "SE1004",
            &[(&format!("src/outbound-metamorphic-{index}.ts"), source)],
        )?;
    }
    Ok(())
}
