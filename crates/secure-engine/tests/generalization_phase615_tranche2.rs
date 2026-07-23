//! Phase 6.15 tranche 2 archive/path confinement fixtures.

use std::fs;

use secure_engine::{CancellationToken, ScanReport, ScanRequest, scan_repository};
use tempfile::TempDir;

fn scan(source: &str) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let repository = TempDir::new()?;
    fs::write(repository.path().join("extract.ts"), source)?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(&request, &CancellationToken::new(), |_| {})?)
}

fn count(report: &ScanReport) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1003")
        .count()
}

#[test]
fn archive_member_path_reaching_write_is_reported() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "import path from 'node:path'; async function unpack(archive, root) { \
         for (const entry of archive.entries()) { \
         await fs.writeFile(path.join(root, entry.path), entry.bytes); } }",
    )?;
    assert_eq!(count(&report), 1);
    Ok(())
}

#[test]
fn unrelated_entry_property_is_not_an_archive_source() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "import path from 'node:path'; async function save(entry, root) { \
         await fs.writeFile(path.join(root, entry.path), entry.bytes); }",
    )?;
    assert_eq!(count(&report), 0);
    Ok(())
}

#[test]
fn generated_member_name_avoids_archive_traversal() -> Result<(), Box<dyn std::error::Error>> {
    let report = scan(
        "import path from 'node:path'; async function unpack(archive, root) { \
         for (const entry of archive.entries()) { \
         const generated = crypto.randomUUID(); \
         await fs.writeFile(path.join(root, generated), entry.bytes); } }",
    )?;
    assert_eq!(count(&report), 0);
    Ok(())
}
