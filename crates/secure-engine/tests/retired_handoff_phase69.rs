//! Phase 6.9 provenance and aggregate accounting for the retired Phase 15 handoff.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

fn workspace_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

#[test]
fn retired_handoff_accounting_is_complete_and_does_not_import_benchmark_source()
-> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_path("fixtures/phase69-retired-handoff");
    let summary: Value = serde_json::from_slice(&fs::read(root.join("summary.json"))?)?;
    assert_eq!(
        summary["schema_version"],
        "secure-engine-phase69-retired-handoff-summary-v1"
    );
    assert_eq!(summary["population"]["retired_cases"], 112);
    assert_eq!(summary["population"]["vulnerable_cases"], 56);
    assert_eq!(summary["population"]["safe_controls"], 56);
    assert_eq!(summary["population"]["retained_findings"], 96);
    assert_eq!(summary["population"]["flagged_controls"], 40);
    assert_eq!(summary["population"]["clean_controls"], 16);
    assert_eq!(summary["primary_causes"]["scanner_source_identity"], 30);
    assert_eq!(summary["primary_causes"]["scanner_source_span"], 16);
    assert_eq!(
        summary["primary_causes"]["scanner_overbroad_false_positive"],
        40
    );
    assert_eq!(
        summary["contributing_causes"]["scanner_guard_recognition"],
        32
    );
    assert_eq!(
        summary["contributing_causes"]["scanner_sanitizer_recognition"],
        8
    );
    assert_eq!(
        summary["contributing_causes"]["scanner_dominance_reasoning"],
        40
    );
    assert_eq!(summary["scope"]["adapter_defect_is_engine_work"], false);
    assert_eq!(summary["scope"]["source_code_exported"], false);

    let entries = fs::read_dir(&root)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| {
        matches!(
            entry.path().file_name().and_then(|name| name.to_str()),
            Some("README.md" | "summary.json")
        )
    }));
    Ok(())
}

#[test]
fn all_permitted_handoff_hashes_are_pinned_without_case_specific_production_data()
-> Result<(), Box<dyn std::error::Error>> {
    let summary: Value = serde_json::from_slice(&fs::read(workspace_path(
        "fixtures/phase69-retired-handoff/summary.json",
    ))?)?;
    let inputs = summary["inputs"].as_object().ok_or("inputs missing")?;
    assert_eq!(inputs.len(), 7);
    assert!(inputs.values().all(|hash| {
        hash.as_str().is_some_and(|value| {
            value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }));

    let mut production = String::new();
    for entry in fs::read_dir(workspace_path("crates/secure-engine/src"))? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            production.push_str(&fs::read_to_string(path)?);
        }
    }
    for forbidden in ["v4-case-", "phase-13-holdout", "unit-001", "phase15-flow-"] {
        assert!(!production.contains(forbidden));
    }
    Ok(())
}
