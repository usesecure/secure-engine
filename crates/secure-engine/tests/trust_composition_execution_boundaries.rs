//! Neutral trust-composition and process-boundary acceptance matrix.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use secure_engine::{
    CacheControl, CancellationToken, EvidenceSemanticRole, SECURE_JSON_V1_SCHEMA, ScanReport,
    ScanRequest, compact_report_graph, rules, scan_repository,
};

fn workspace_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn scan_fixture(cache: Option<&Path>) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let mut request = ScanRequest::new(workspace_path(
        "fixtures/trust-composition-execution-boundaries",
    ));
    request.cache = CacheControl {
        directory: cache.map(Path::to_path_buf),
        clear_before_scan: false,
    };
    request.configuration.parse_cache_enabled = cache.is_some();
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

fn se1012(report: &ScanReport) -> Vec<&secure_engine::Finding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1012")
        .collect()
}

#[test]
fn neutral_matrix_flips_only_on_provenance_scope_state_or_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture(None)?;
    let findings = se1012(&report);
    let by_path = findings
        .iter()
        .fold(BTreeMap::new(), |mut counts, finding| {
            if let Some(sink) = &finding.sink {
                *counts.entry(sink.path.as_str()).or_insert(0_usize) += 1;
            }
            counts
        });

    for positive in [
        "workspace-positive.ts",
        "folder-positive.ts",
        "stale-transition.ts",
        "environment-positive.ts",
        "helper-calls.ts",
        "multi-root.ts",
    ] {
        assert!(
            by_path.contains_key(positive),
            "missing positive {positive}: {by_path:?}"
        );
    }
    assert_eq!(by_path.get("process-components.ts"), Some(&5));
    for control in [
        "workspace-control.ts",
        "folder-control.ts",
        "constant-controls.ts",
        "mutation-and-duplicates.ts",
    ] {
        assert!(
            !by_path.contains_key(control),
            "control emitted {control}: {by_path:?}"
        );
    }
    assert_eq!(by_path.get("multi-root.ts"), Some(&1));
    Ok(())
}

#[test]
fn evidence_names_exact_provenance_and_process_component() -> Result<(), Box<dyn std::error::Error>>
{
    let report = scan_fixture(None)?;
    let findings = se1012(&report);
    assert!(!findings.is_empty());
    let source_identities = findings
        .iter()
        .filter_map(|finding| finding.evidence_path.first())
        .filter_map(|step| step.semantic.as_ref())
        .map(|semantic| semantic.identity.as_str())
        .collect::<BTreeSet<_>>();
    assert!(source_identities.contains("configuration.workspace-value"));
    assert!(source_identities.contains("configuration.workspace-folder-value"));
    assert!(source_identities.contains("configuration.environment-value"));
    assert!(findings.iter().all(|finding| {
        finding
            .evidence_path
            .first()
            .and_then(|step| step.semantic.as_ref())
            .is_some_and(|semantic| semantic.role == EvidenceSemanticRole::ConfigurationSource)
    }));
    let sink_identities = findings
        .iter()
        .filter_map(|finding| finding.evidence_path.last())
        .filter_map(|step| step.semantic.as_ref())
        .map(|semantic| semantic.identity.as_str())
        .collect::<BTreeSet<_>>();
    for expected in [
        "sink.process-binary-selection",
        "sink.process-argv-element",
        "sink.process-environment-value",
        "sink.process-working-directory",
        "sink.process-shell-mode",
        "sink.process-shell-program",
    ] {
        assert!(
            sink_identities.contains(expected),
            "missing {expected}: {sink_identities:?}"
        );
    }
    Ok(())
}

#[test]
fn ambiguous_configuration_callbacks_and_cache_keys_abstain_explicitly()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture(None)?;
    assert!(se1012(&report).iter().all(|finding| {
        finding
            .evidence
            .iter()
            .all(|location| location.path != "ambiguous-abstentions.ts")
    }));
    let codes = report
        .limitations
        .iter()
        .map(|limitation| limitation.code.as_str())
        .collect::<BTreeSet<_>>();
    assert!(codes.contains("trust-composition-abstained"));
    assert!(codes.contains("decision-cache-scope-unresolved"));
    assert!(codes.contains("dynamic-resolution-limited"));
    Ok(())
}

#[test]
fn metamorphic_renames_preserve_outcome_and_semantic_fingerprint()
-> Result<(), Box<dyn std::error::Error>> {
    fn scan(source: &str) -> Result<ScanReport, Box<dyn std::error::Error>> {
        let repository = tempfile::tempdir()?;
        fs::write(repository.path().join("service.ts"), source)?;
        let mut request = ScanRequest::new(repository.path());
        request.configuration.parse_cache_enabled = false;
        Ok(scan_repository(
            &request,
            &CancellationToken::new(),
            |_| {},
        )?)
    }
    let first = scan(
        "import { workspace } from 'vscode'; import { spawn } from 'node:child_process'; export function launch() { const binary = workspace.getConfiguration('orion').inspect('binary')?.workspaceValue; if (binary) spawn(binary, ['serve'], { shell: false }); }",
    )?;
    let second = scan(
        "import { workspace as projectSpace } from 'vscode'; import { spawn as executeVector } from 'node:child_process'; export function begin() { const selectedTool = projectSpace.getConfiguration('orion').inspect('binary')?.workspaceValue; if (selectedTool) executeVector(selectedTool, ['serve'], { shell: false }); }",
    )?;
    let first = se1012(&first);
    let second = se1012(&second);
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert_eq!(
        first[0].semantic_fingerprint,
        second[0].semantic_fingerprint
    );
    Ok(())
}

#[test]
fn cache_and_repeated_runs_preserve_order_fingerprints_and_compact_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let cache = tempfile::tempdir()?;
    let stale = cache
        .path()
        .join("secure-parse-cache-v20/legacy/stale.json");
    fs::create_dir_all(stale.parent().ok_or("stale cache parent missing")?)?;
    fs::write(&stale, b"legacy-v20-envelope")?;
    let cold = scan_fixture(Some(cache.path()))?;
    let warm = scan_fixture(Some(cache.path()))?;
    assert_eq!(cold.findings, warm.findings);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert_eq!(cold.parsing.cache_hits, 0);
    assert!(warm.parsing.cache_hits > 0);
    assert!(stale.is_file());
    assert!(cache.path().join("secure-parse-cache-v22").is_dir());

    let mut compact = warm;
    let full_nodes = compact.graph.nodes.len();
    compact_report_graph(&mut compact)?;
    assert!(compact.graph.nodes.len() < full_nodes);
    let schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&serde_json::to_value(&compact)?));
    Ok(())
}

#[test]
fn rule_catalog_is_additive_and_existing_ids_remain() {
    let ids = rules()
        .into_iter()
        .map(|rule| rule.rule_id)
        .collect::<BTreeSet<_>>();
    for number in 1001..=1012 {
        assert!(ids.contains(&format!("SE{number}")));
    }
}
