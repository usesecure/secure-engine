//! Phase 3 evidence-graph, deterministic rule, suppression, and evaluation coverage.

use std::collections::BTreeSet;
use std::path::PathBuf;

use secure_engine::{
    CancellationToken, SECURE_JSON_V1_SCHEMA, ScanError, ScanRequest, Suppression, scan_repository,
};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/phase3-rules")
}

fn uncached_request() -> ScanRequest {
    let mut request = ScanRequest::new(fixture());
    request.configuration.parse_cache_enabled = false;
    request
}

#[test]
fn vulnerable_flows_cover_every_rule_and_safe_controls_remain_clean()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_repository(&uncached_request(), &CancellationToken::new(), |_| {})?;
    let rules = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        rules,
        BTreeSet::from([
            "SE1001", "SE1002", "SE1003", "SE1004", "SE1005", "SE1006", "SE1007"
        ])
    );
    assert_eq!(report.findings.len(), 12);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        report.findings.len()
    );
    assert!(report.findings.iter().all(|finding| {
        finding
            .sink
            .as_ref()
            .is_some_and(|sink| sink.path == "vulnerable.ts")
    }));
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "SE1007")
            .count(),
        6
    );
    assert_eq!(report.parser_diagnostics.len(), 1);
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "SE1005" && finding.severity == "medium" && finding.confidence == "high"
    }));
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "SE1006"
            && finding.severity == "critical"
            && finding.confidence == "high"
    }));
    Ok(())
}

#[test]
fn graph_paths_are_precise_complete_and_internally_referential()
-> Result<(), Box<dyn std::error::Error>> {
    let report = scan_repository(&uncached_request(), &CancellationToken::new(), |_| {})?;
    let nodes = report
        .graph
        .nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let edges = report
        .graph
        .edges
        .iter()
        .map(|edge| edge.edge_id.as_str())
        .collect::<BTreeSet<_>>();
    let edge_kinds = report
        .graph
        .edges
        .iter()
        .map(|edge| edge.kind.as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        BTreeSet::from([
            "containment",
            "imports",
            "calls",
            "argument-flow",
            "returns",
            "assignment",
            "control-flow",
            "guard-dominance",
            "sanitization",
            "source-to-sink-propagation",
        ])
        .is_subset(&edge_kinds)
    );
    for edge in &report.graph.edges {
        assert!(nodes.contains(edge.from_node.as_str()));
        assert!(nodes.contains(edge.to_node.as_str()));
    }
    for finding in &report.findings {
        assert!(finding.evidence_path.len() >= 2);
        assert_eq!(
            finding.source,
            finding
                .evidence_path
                .first()
                .map(|step| step.location.clone())
        );
        assert_eq!(
            finding.sink,
            finding
                .evidence_path
                .last()
                .map(|step| step.location.clone())
        );
        for (index, step) in finding.evidence_path.iter().enumerate() {
            assert!(nodes.contains(step.node_id.as_str()));
            assert!(step.location.span.end_byte > step.location.span.start_byte);
            if index == 0 {
                assert!(step.edge_id_from_previous.is_none());
            } else {
                assert!(
                    step.edge_id_from_previous
                        .as_deref()
                        .is_some_and(|edge| edges.contains(edge))
                );
            }
        }
    }
    Ok(())
}

#[test]
fn graph_findings_and_phase_two_fact_identifiers_are_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let first = scan_repository(&uncached_request(), &CancellationToken::new(), |_| {})?;
    let second = scan_repository(&uncached_request(), &CancellationToken::new(), |_| {})?;
    assert_eq!(first.graph, second.graph);
    assert_eq!(first.findings, second.findings);
    assert_eq!(first.report_fingerprint, second.report_fingerprint);

    let mut phase_two = ScanRequest::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/phase2-js-ts"),
    );
    phase_two.configuration.parse_cache_enabled = false;
    let phase_two = scan_repository(&phase_two, &CancellationToken::new(), |_| {})?;
    assert!(
        phase_two
            .facts
            .iter()
            .any(|fact| fact.fact_id == "sf_b53e989c55945ff77f5c8acf")
    );
    Ok(())
}

#[test]
fn cache_reuse_preserves_graph_and_finding_results() -> Result<(), Box<dyn std::error::Error>> {
    let cache = tempfile::tempdir()?;
    let mut request = ScanRequest::new(fixture());
    request.cache.directory = Some(cache.path().to_path_buf());
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(cold.parsing.cache_misses, 4);
    assert_eq!(warm.parsing.cache_hits, 4);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.findings, warm.findings);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    Ok(())
}

#[test]
fn exact_suppressions_apply_and_invalid_stale_or_broad_scopes_are_reported()
-> Result<(), Box<dyn std::error::Error>> {
    let baseline = scan_repository(&uncached_request(), &CancellationToken::new(), |_| {})?;
    let command = baseline
        .findings
        .iter()
        .find(|finding| finding.rule_id == "SE1001")
        .and_then(|finding| finding.sink.clone())
        .ok_or("missing command finding")?;
    let mut request = uncached_request();
    request.configuration.suppressions = vec![
        Suppression {
            rule_id: "SE1001".into(),
            path: command.path,
            start_byte: command.span.start_byte,
            reason: "Reviewed fixed command allowlist".into(),
        },
        Suppression {
            rule_id: "SE9999".into(),
            path: "vulnerable.ts".into(),
            start_byte: 0,
            reason: "Unknown rule remains visible".into(),
        },
        Suppression {
            rule_id: "SE1002".into(),
            path: "*.ts".into(),
            start_byte: 0,
            reason: "Broad scope must be rejected".into(),
        },
        Suppression {
            rule_id: "SE1003".into(),
            path: "vulnerable.ts".into(),
            start_byte: 0,
            reason: "No current finding at this byte".into(),
        },
        Suppression {
            rule_id: "SE1004".into(),
            path: "vulnerable.ts".into(),
            start_byte: 785,
            reason: "short".into(),
        },
    ];
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SE1001")
    );
    assert_eq!(report.analysis.findings_suppressed, 1);
    let codes = report
        .suppression_diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        codes,
        BTreeSet::from([
            "applied",
            "invalid-reason",
            "invalid-rule",
            "invalid-scope",
            "stale",
        ])
    );
    Ok(())
}

#[test]
fn bounds_cancellation_schema_and_privacy_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let mut bounded = uncached_request();
    bounded.configuration.max_graph_nodes = 20;
    bounded.configuration.max_graph_edges = 20;
    let bounded = scan_repository(&bounded, &CancellationToken::new(), |_| {})?;
    assert!(bounded.analysis.truncated);
    assert!(bounded.graph.nodes.len() <= 20);
    assert!(bounded.graph.edges.len() <= 20);

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(
        scan_repository(&uncached_request(), &cancellation, |_| {}),
        Err(ScanError::Cancelled)
    ));

    let report = scan_repository(&uncached_request(), &CancellationToken::new(), |_| {})?;
    let document = serde_json::to_value(&report)?;
    let schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&document));
    let serialized = serde_json::to_string(&document)?;
    assert!(!serialized.contains(fixture().to_string_lossy().as_ref()));
    assert!(!serialized.contains("intentionally malformed so"));
    Ok(())
}
