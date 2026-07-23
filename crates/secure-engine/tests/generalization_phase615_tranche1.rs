//! Phase 6.15 tranche 1 security-invariant fixtures.

use std::fs;

use secure_engine::{CancellationToken, ScanReport, ScanRequest, scan_repository};
use tempfile::TempDir;

fn scan(source: &str) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::write(repository.path().join("actions.ts"), source)?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(&request, &CancellationToken::new(), |_| {})?)
}

fn findings(report: &ScanReport) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1007")
        .count()
}

#[test]
fn ignored_local_async_guard_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "'use server'; async function authorizeMember() { return true; } \
         export async function change(form: FormData) { const id = String(form.get('id')); \
         authorizeMember(id); return memberRepository.update(id, { state: 'active' }); }",
    )?;
    assert_eq!(findings(&report), 1);
    Ok(())
}

#[test]
fn awaited_guard_for_canonical_identity_is_effective() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "'use server'; export async function change(form: FormData) { \
         const id = String(form.get('id')); \
         const canonical = decodeURIComponent(id).toLowerCase(); \
         await policy.authorizeMemberAsync(canonical); \
         return memberRepository.update(canonical, { state: 'active' }); }",
    )?;
    assert_eq!(findings(&report), 0);
    Ok(())
}

#[test]
fn authorization_before_identity_change_is_not_reused() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "'use server'; function authorizeMember() { return true; } \
         export async function change(form: FormData) { const id = String(form.get('id')); \
         authorizeMember(id); const canonical = decodeURIComponent(id); \
         return memberRepository.update(canonical, { state: 'active' }); }",
    )?;
    assert_eq!(findings(&report), 1);
    Ok(())
}
