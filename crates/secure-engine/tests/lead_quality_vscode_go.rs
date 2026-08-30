//! Regression coverage derived from the first bounded `SecureFlow` campaign.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use secure_engine::{
    CancellationToken, DisclosureLocality, EvidenceDataClass, EvidenceSemanticRole,
    EvidenceStateKind, SECURE_JSON_V1_SCHEMA, ScanReport, ScanRequest, compact_report_graph, rules,
    scan_repository,
};

fn workspace_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn scan_fixture() -> Result<ScanReport, Box<dyn std::error::Error>> {
    let mut request = ScanRequest::new(workspace_path("fixtures/lead-quality-vscode-go"));
    request.configuration.parse_cache_enabled = false;
    Ok(scan_repository(
        &request,
        &CancellationToken::new(),
        |_| {},
    )?)
}

#[test]
fn ordinary_vscode_configuration_and_local_state_do_not_satisfy_se1010()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    let se1010 = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1010")
        .collect::<Vec<_>>();
    assert_eq!(
        se1010.len(),
        2,
        "only the two positive controls should fire"
    );
    assert!(se1010.iter().all(|finding| {
        finding
            .source
            .as_ref()
            .is_some_and(|source| source.path == "positive-secrets.ts")
    }));
    for rejected_path in ["lint-config.ts", "local-debug.ts", "survey-state.ts"] {
        assert!(se1010.iter().all(|finding| {
            finding
                .evidence
                .iter()
                .all(|location| location.path != rejected_path)
        }));
    }
    Ok(())
}

#[test]
fn se1010_positive_controls_retain_typed_source_and_locality_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_fixture()?;
    let findings = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1010")
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 2);
    let localities = findings
        .iter()
        .filter_map(|finding| {
            finding
                .evidence_path
                .last()
                .and_then(|step| step.semantic.as_ref())
                .and_then(|semantic| semantic.locality.clone())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        localities,
        BTreeSet::from([
            DisclosureLocality::LocalDiagnostic,
            DisclosureLocality::RemoteService,
        ])
    );
    for finding in findings {
        let source = finding
            .evidence_path
            .first()
            .and_then(|step| step.semantic.as_ref())
            .ok_or("typed source semantic missing")?;
        assert_eq!(source.role, EvidenceSemanticRole::SensitiveSource);
        assert!(matches!(
            source.data_class,
            Some(EvidenceDataClass::Token | EvidenceDataClass::UnknownSensitive)
        ));
        assert_eq!(finding.verification_state, "semantic-path");
        assert_eq!(
            finding.evidence_state.as_ref().map(|state| &state.state),
            Some(&EvidenceStateKind::SemanticPath)
        );
        assert!(finding.lead_context.is_some());
    }
    Ok(())
}

#[test]
fn node_listener_is_one_bounded_lead_and_controls_abstain() -> Result<(), Box<dyn std::error::Error>>
{
    let report = scan_fixture()?;
    let listeners = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "SE1011")
        .collect::<Vec<_>>();
    assert_eq!(listeners.len(), 1);
    let finding = listeners[0];
    assert_eq!(finding.verification_state, "syntactic-lead");
    assert_eq!(
        finding.evidence_state.as_ref().map(|state| &state.state),
        Some(&EvidenceStateKind::SyntacticLead)
    );
    assert_eq!(
        finding
            .lead_context
            .as_ref()
            .map(|context| &context.locality),
        Some(&DisclosureLocality::NetworkListener)
    );
    let serialized = serde_json::to_string(finding)?;
    for required in [
        "user or automation",
        "connection-race",
        "firewall",
        "untrustedWorkspaces.supported=false",
        "not a vulnerability verdict",
    ] {
        assert!(
            serialized.contains(required),
            "missing listener qualifier: {required}"
        );
    }
    assert_eq!(
        finding.sink.as_ref().map(|sink| sink.path.as_str()),
        Some("network-listener.ts")
    );
    Ok(())
}

#[test]
fn workspace_trust_is_a_guard_not_authorization_proof() -> Result<(), Box<dyn std::error::Error>> {
    let repository = tempfile::tempdir()?;
    fs::write(
        repository.path().join("listener.ts"),
        "import * as net from 'node:net'; declare const vscode: any; \
         export function start(port: number) { if (!vscode.workspace.isTrusted) return; \
         const server = net.createServer(); server.listen(port); }",
    )?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.parse_cache_enabled = false;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "SE1011")
        .ok_or("listener lead missing")?;
    assert_eq!(finding.verification_state, "guard-aware-lead");
    assert!(!finding.guards.is_empty());
    let trust_guard = report
        .graph
        .nodes
        .iter()
        .filter_map(|node| node.semantic.as_ref())
        .find(|semantic| semantic.identity == "guard.platform-workspace-trust")
        .ok_or("workspace trust guard semantic missing")?;
    assert_eq!(trust_guard.role, EvidenceSemanticRole::Guard);
    assert!(trust_guard.authorization.is_none());
    Ok(())
}

#[test]
fn compact_projection_is_complete_deterministic_and_schema_valid()
-> Result<(), Box<dyn std::error::Error>> {
    let full = scan_fixture()?;
    let full_size = serde_json::to_vec_pretty(&full)?.len();
    let full_nodes = full.graph.nodes.len();
    let full_edges = full.graph.edges.len();
    let mut first = full.clone();
    let mut second = full;
    compact_report_graph(&mut first)?;
    compact_report_graph(&mut second)?;
    assert_eq!(first.report_fingerprint, second.report_fingerprint);
    assert_eq!(first.graph, second.graph);
    assert_eq!(first.graph.scope, "finding-evidence");
    assert_eq!(first.graph.total_nodes, full_nodes);
    assert_eq!(first.graph.total_edges, full_edges);
    assert!(first.graph.nodes.len() < full_nodes);
    assert!(serde_json::to_vec_pretty(&first)?.len() < full_size);

    let retained_nodes = first
        .graph
        .nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let retained_edges = first
        .graph
        .edges
        .iter()
        .map(|edge| edge.edge_id.as_str())
        .collect::<BTreeSet<_>>();
    for step in first
        .findings
        .iter()
        .flat_map(|finding| &finding.evidence_path)
    {
        assert!(retained_nodes.contains(step.node_id.as_str()));
        if let Some(edge) = &step.edge_id_from_previous {
            assert!(retained_edges.contains(edge.as_str()));
        }
    }

    let schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&serde_json::to_value(&first)?));
    Ok(())
}

#[test]
fn established_rule_ids_remain_and_listener_rule_is_additive() {
    let ids = rules()
        .into_iter()
        .map(|rule| rule.rule_id)
        .collect::<BTreeSet<_>>();
    for rule_number in 1001..=1011 {
        assert!(ids.contains(&format!("SE{rule_number}")));
    }
}
