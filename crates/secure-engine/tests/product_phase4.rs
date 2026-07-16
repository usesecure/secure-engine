//! Phase 4 baseline, SARIF, history, export, and safe source-preview coverage.

use std::fs;
use std::path::PathBuf;

use secure_engine::{
    Baseline, CancellationToken, ExportFormat, HistoryStore, ScanRequest, SourceLocation,
    SourcePreviewError, compare_baseline, create_baseline, load_source_preview, sarif_report,
    scan_repository, serialize_export, validate_baseline, write_export,
};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/phase3-rules")
}

fn report() -> Result<secure_engine::ScanReport, secure_engine::ScanError> {
    let mut request = ScanRequest::new(fixture());
    request.configuration.parse_cache_enabled = false;
    scan_repository(&request, &CancellationToken::new(), |_| {})
}

#[test]
fn baseline_is_deterministic_and_classifies_all_states() -> Result<(), Box<dyn std::error::Error>> {
    let original = report()?;
    let baseline = create_baseline(&original)?;
    validate_baseline(&baseline)?;
    assert_eq!(baseline, create_baseline(&original)?);
    let serialized = serde_json::to_string(&baseline)?;
    assert!(!serialized.contains("started_at"));
    assert!(!serialized.contains("finished_at"));

    let unchanged = compare_baseline(&baseline, &original)?;
    assert_eq!(unchanged.unchanged.len(), original.findings.len());
    assert!(!unchanged.has_changes());

    let mut current = original.clone();
    let resolved = current.findings.remove(0);
    current.findings[0].fingerprint = "a".repeat(64);
    let mut added = resolved;
    added.rule_id = "SE1999".into();
    added.finding_id = "fd_phase4_new".into();
    added.fingerprint = "b".repeat(64);
    current.findings.push(added);
    let comparison = compare_baseline(&baseline, &current)?;
    assert_eq!(comparison.new.len(), 1);
    assert_eq!(comparison.changed.len(), 1);
    assert_eq!(comparison.resolved.len(), 1);
    assert_eq!(
        comparison.unchanged.len(),
        original.findings.len().saturating_sub(2)
    );
    assert!(comparison.has_changes());
    Ok(())
}

#[test]
fn malformed_and_incompatible_baselines_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let report = report()?;
    let mut baseline = create_baseline(&report)?;
    baseline.format = "future-baseline".into();
    assert!(validate_baseline(&baseline).is_err());
    baseline.format = secure_engine::BASELINE_FORMAT.into();
    baseline.findings[0].fingerprint = "not-a-fingerprint".into();
    assert!(compare_baseline(&baseline, &report).is_err());
    let malformed = serde_json::from_str::<Baseline>("{\"format\":1}");
    assert!(malformed.is_err());
    Ok(())
}

#[test]
fn sarif_is_schema_valid_deterministic_and_private() -> Result<(), Box<dyn std::error::Error>> {
    let report = report()?;
    let first = sarif_report(&report);
    let second = sarif_report(&report);
    assert_eq!(first, second);
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/sarif-schema-2.1.0.json"))?;
    let validator = jsonschema::validator_for(&schema)?;
    if let Err(error) = validator.validate(&first) {
        return Err(format!("SARIF schema validation failed: {error}").into());
    }
    let serialized = serde_json::to_string(&first)?;
    assert!(!serialized.contains(fixture().to_string_lossy().as_ref()));
    assert!(!serialized.contains("cache"));
    assert!(!serialized.contains("intentionally malformed so"));
    assert_eq!(first["version"], "2.1.0");
    assert_eq!(
        first["runs"][0]["results"].as_array().map(Vec::len),
        Some(report.findings.len())
    );
    assert!(first["runs"][0]["results"][0]["codeFlows"].is_array());
    Ok(())
}

#[test]
fn exports_are_deterministic_atomic_and_cancel_safe() -> Result<(), Box<dyn std::error::Error>> {
    let report = report()?;
    assert_eq!(
        serialize_export(&report, ExportFormat::Sarif)?,
        serialize_export(&report, ExportFormat::Sarif)?
    );
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("report.sarif");
    write_export(
        &report,
        ExportFormat::Sarif,
        &output,
        &CancellationToken::new(),
    )?;
    assert!(output.is_file());
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let cancelled_output = directory.path().join("cancelled.json");
    assert!(
        write_export(
            &report,
            ExportFormat::SecureJson,
            &cancelled_output,
            &cancelled,
        )
        .is_err()
    );
    assert!(!cancelled_output.exists());
    assert!(fs::read_dir(directory.path())?.all(|entry| {
        entry
            .ok()
            .is_some_and(|entry| !entry.file_name().to_string_lossy().contains("secure-tmp"))
    }));
    Ok(())
}

#[test]
fn history_is_private_bounded_recoverable_and_explicitly_deletable()
-> Result<(), Box<dyn std::error::Error>> {
    let mut report = report()?;
    let directory = tempfile::tempdir()?;
    let repository = tempfile::tempdir()?;
    let store = HistoryStore::open(directory.path().to_path_buf(), 2)?;
    let cancellation = CancellationToken::new();
    let mut ids = Vec::new();
    for marker in ['c', 'd', 'e'] {
        report.report_fingerprint = marker.to_string().repeat(64);
        let summary = store.record(
            &report,
            Some(repository.path()),
            Some("Phase 4 fixture"),
            &cancellation,
        )?;
        ids.push(summary.scan_id);
    }
    let listing = store.list(&cancellation)?;
    assert_eq!(listing.scans.len(), 2);
    assert!(!listing.scans.iter().any(|scan| scan.scan_id == ids[0]));
    let entry = store.show(&ids[2], &cancellation)?;
    let public = serde_json::to_string(&entry)?;
    assert!(!public.contains(repository.path().to_string_lossy().as_ref()));
    assert_eq!(entry.summary.status, "complete");

    fs::write(directory.path().join("bad.json"), b"not json")?;
    let recovered = store.list(&cancellation)?;
    assert_eq!(recovered.corrupt_entries_recovered, 1);
    assert!(!directory.path().join("bad.json").exists());

    drop(repository);
    let moved = store.show(&ids[2], &cancellation)?;
    assert!(!moved.summary.repository_available);
    store.delete(&ids[2])?;
    assert!(store.show(&ids[2], &cancellation).is_err());

    report.scan.complete = false;
    assert!(
        store
            .record(&report, None, None, &CancellationToken::new())
            .is_err()
    );
    Ok(())
}

#[test]
fn source_preview_is_exact_bounded_cancel_safe_and_contained()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempfile::tempdir()?;
    fs::create_dir(repository.path().join("src"))?;
    fs::write(
        repository.path().join("src/app.ts"),
        "one\ntwo\nconst danger = input;\nfour\nfive\n",
    )?;
    let location = SourceLocation {
        path: "src/app.ts".into(),
        span: secure_engine::SourceSpan {
            start_byte: 8,
            end_byte: 20,
            start_line: 3,
            start_column: 1,
            end_line: 3,
            end_column: 13,
        },
    };
    let preview = load_source_preview(
        repository.path(),
        &location,
        1,
        1024,
        &CancellationToken::new(),
    )?;
    assert_eq!(preview.first_line, 2);
    assert_eq!(preview.last_line, 4);
    assert_eq!(preview.text, "two\nconst danger = input;\nfour");

    let mut escape = location.clone();
    escape.path = "../outside".into();
    assert!(matches!(
        load_source_preview(
            repository.path(),
            &escape,
            1,
            1024,
            &CancellationToken::new()
        ),
        Err(SourcePreviewError::Containment)
    ));

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", repository.path().join("src/link"))?;
        escape.path = "src/link".into();
        assert!(matches!(
            load_source_preview(
                repository.path(),
                &escape,
                1,
                1024,
                &CancellationToken::new()
            ),
            Err(SourcePreviewError::Containment)
        ));
    }

    assert!(matches!(
        load_source_preview(
            repository.path(),
            &location,
            1,
            4,
            &CancellationToken::new()
        ),
        Err(SourcePreviewError::Unsupported)
    ));
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(
        load_source_preview(repository.path(), &location, 1, 1024, &cancellation),
        Err(SourcePreviewError::Cancelled)
    ));
    Ok(())
}
