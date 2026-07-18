//! Phase 6.10 aggregate provenance and implementation-boundary regressions.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

fn workspace_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

#[test]
fn frozen_aggregate_handoff_is_complete_and_source_free() -> Result<(), Box<dyn std::error::Error>>
{
    let root = workspace_path("fixtures/phase610-cms-nova-handoff");
    let summary: Value = serde_json::from_slice(&fs::read(root.join("summary.json"))?)?;
    assert_eq!(
        summary["schema_version"],
        "secure-engine-phase610-cms-nova-handoff-summary-v1"
    );
    assert_eq!(summary["population"]["raw_findings"], 56);
    assert_eq!(summary["population"]["se1007_findings"], 56);
    assert_eq!(summary["population"]["false_positives"], 56);
    assert_eq!(summary["population"]["validated_vulnerabilities"], 0);
    assert_eq!(
        summary["root_causes"]["fail_closed_principal_role_wrapper"],
        53
    );
    assert_eq!(
        summary["root_causes"]["request_bound_boolean_authorization"],
        2
    );
    assert_eq!(
        summary["root_causes"]["authenticated_primary_identity_equality"],
        1
    );
    assert_eq!(summary["scope"]["source_exported"], false);

    let entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
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
fn permitted_hashes_are_pinned_without_project_specific_production_logic()
-> Result<(), Box<dyn std::error::Error>> {
    let summary: Value = serde_json::from_slice(&fs::read(workspace_path(
        "fixtures/phase610-cms-nova-handoff/summary.json",
    ))?)?;
    let inputs = summary["inputs"].as_object().ok_or("inputs missing")?;
    assert_eq!(inputs.len(), 3);
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
    for forbidden in [
        "getAdminSession",
        "isRequestAdmin",
        "firstAdmin",
        "cms-nova",
        "api/users/create",
    ] {
        assert!(!production.contains(forbidden));
    }
    Ok(())
}
