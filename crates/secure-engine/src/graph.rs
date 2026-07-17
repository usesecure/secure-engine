use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tree_sitter::Node;

use crate::{
    AnalysisSummary, CancellationToken, EvidenceEdge, EvidenceGraph, EvidenceNode,
    EvidencePathStep, EvidenceSemantic, Finding, NormalizedFact, ParserProvenance, RuleMetadata,
    ScanConfiguration, ScanError, SourceLocation, SourceSpan, SuppressionDiagnostic,
};

pub(crate) const GRAPH_EXTRACTOR_VERSION: &str = "secure-evidence-graph-v1";
const MAX_RECORD_NAME_BYTES: usize = 512;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProgramUnit {
    pub(crate) path: String,
    pub(crate) provenance: ParserProvenance,
    pub(crate) records: Vec<ProgramRecord>,
    pub(crate) truncated: bool,
}

pub(crate) fn empty_program(path: &str, parser_provenance: &ParserProvenance) -> ProgramUnit {
    let mut provenance = parser_provenance.clone();
    provenance.extractor_version = GRAPH_EXTRACTOR_VERSION.into();
    ProgramUnit {
        path: path.into(),
        provenance,
        records: Vec::new(),
        truncated: false,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct ProgramRecord {
    record_id: String,
    kind: String,
    name: Option<String>,
    function: Option<String>,
    inputs: Vec<String>,
    output: Option<String>,
    callee: Option<String>,
    location: SourceLocation,
    provenance: ParserProvenance,
    #[serde(default)]
    dominance_start: Option<u64>,
    #[serde(default)]
    dominance_end: Option<u64>,
    #[serde(default)]
    semantic: Option<EvidenceSemantic>,
    fingerprint: String,
}

pub(crate) struct AnalysisResult {
    pub(crate) graph: EvidenceGraph,
    pub(crate) summary: AnalysisSummary,
    pub(crate) findings: Vec<Finding>,
    pub(crate) suppression_diagnostics: Vec<SuppressionDiagnostic>,
    pub(crate) limitations: Vec<crate::Limitation>,
}

#[derive(Clone)]
struct FunctionInfo {
    name: String,
    qualified_name: String,
    location: SourceLocation,
    parameters: Vec<(String, SourceLocation)>,
    handler: bool,
    server_action: bool,
    exported: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct Trace {
    nodes: Vec<String>,
    edges: Vec<String>,
    source_function: Option<String>,
    sanitizers: BTreeSet<String>,
    values: BTreeSet<String>,
    source_specificity: u8,
}

#[derive(Clone)]
struct Candidate {
    rule_id: &'static str,
    trace: Trace,
    sink_node: String,
    guards: Vec<String>,
}

struct CandidateTarget<'a> {
    node: &'a str,
    guards: Vec<String>,
    record: &'a ProgramRecord,
}

struct GraphBuilder {
    nodes: BTreeMap<String, EvidenceNode>,
    edges: BTreeMap<String, EvidenceEdge>,
    max_nodes: usize,
    max_edges: usize,
    truncated: bool,
}

impl GraphBuilder {
    fn new(configuration: &ScanConfiguration) -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            max_nodes: configuration.max_graph_nodes,
            max_edges: configuration.max_graph_edges,
            truncated: false,
        }
    }

    fn node(
        &mut self,
        kind: &str,
        name: Option<&str>,
        location: &SourceLocation,
        provenance: &ParserProvenance,
    ) -> String {
        self.node_with_semantic(kind, name, None, location, provenance)
    }

    fn node_with_semantic(
        &mut self,
        kind: &str,
        name: Option<&str>,
        semantic: Option<EvidenceSemantic>,
        location: &SourceLocation,
        provenance: &ParserProvenance,
    ) -> String {
        let fingerprint = graph_fingerprint(kind, name, location, provenance);
        let node_id = format!("gn_{}", &fingerprint[..24]);
        if !self.nodes.contains_key(&node_id) {
            if self.nodes.len() >= self.max_nodes {
                self.truncated = true;
                return node_id;
            }
            self.nodes.insert(
                node_id.clone(),
                EvidenceNode {
                    node_id: node_id.clone(),
                    kind: kind.into(),
                    name: name.map(str::to_owned),
                    semantic,
                    location: location.clone(),
                    provenance: provenance.clone(),
                    fingerprint,
                },
            );
        }
        node_id
    }

    fn edge(
        &mut self,
        kind: &str,
        from_node: &str,
        to_node: &str,
        location: &SourceLocation,
        provenance: &ParserProvenance,
    ) -> Option<String> {
        if !self.nodes.contains_key(from_node) || !self.nodes.contains_key(to_node) {
            self.truncated = true;
            return None;
        }
        let fingerprint = edge_fingerprint(kind, from_node, to_node, location, provenance);
        let edge_id = format!("ge_{}", &fingerprint[..24]);
        if !self.edges.contains_key(&edge_id) {
            if self.edges.len() >= self.max_edges {
                self.truncated = true;
                return None;
            }
            self.edges.insert(
                edge_id.clone(),
                EvidenceEdge {
                    edge_id: edge_id.clone(),
                    kind: kind.into(),
                    from_node: from_node.into(),
                    to_node: to_node.into(),
                    location: location.clone(),
                    provenance: provenance.clone(),
                    fingerprint,
                },
            );
        }
        Some(edge_id)
    }
}

pub(crate) fn extract_program(
    path: &str,
    content: &[u8],
    root: Node<'_>,
    parser_provenance: &ParserProvenance,
    global_use_server: bool,
    maximum_records: usize,
    cancellation: &CancellationToken,
) -> Result<ProgramUnit, ScanError> {
    let mut graph_provenance = parser_provenance.clone();
    graph_provenance.extractor_version = GRAPH_EXTRACTOR_VERSION.into();
    let handler_names = route_handler_names(root, content, maximum_records);
    let functions = collect_functions(
        path,
        content,
        root,
        global_use_server,
        &handler_names,
        maximum_records,
    );
    let aliases = collect_aliases(root, content, maximum_records);
    let mut records = Vec::new();
    let mut truncated = false;
    for function in &functions {
        if records.len() >= maximum_records {
            truncated = true;
            break;
        }
        records.push(record(
            if function.handler {
                "handler"
            } else {
                "function"
            },
            Some(&function.name),
            Some(&function.qualified_name),
            Vec::new(),
            None,
            None,
            function.location.clone(),
            &graph_provenance,
        ));
        for (index, (parameter, location)) in function.parameters.iter().enumerate() {
            if records.len() >= maximum_records {
                truncated = true;
                break;
            }
            let is_source = function.handler && (function.server_action || index == 0);
            records.push(record(
                if is_source { "source" } else { "argument" },
                Some(if is_source {
                    if function.server_action {
                        "server-action-parameter"
                    } else {
                        "request-parameter"
                    }
                } else {
                    parameter
                }),
                Some(&function.qualified_name),
                Vec::new(),
                Some(parameter),
                None,
                location.clone(),
                &graph_provenance,
            ));
        }
    }

    let mut stack = vec![root];
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        if records.len() >= maximum_records {
            truncated = true;
            break;
        }
        visited = visited.saturating_add(1);
        if visited.is_multiple_of(256) && cancellation.is_cancelled() {
            return Err(ScanError::Cancelled);
        }
        let function = containing_function(node, &functions);
        extract_record_for_node(
            path,
            content,
            node,
            function,
            &graph_provenance,
            &aliases,
            &mut records,
        );
        let child_count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
        for index in (0..child_count).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    records.sort();
    records.dedup_by(|left, right| left.record_id == right.record_id);
    Ok(ProgramUnit {
        path: path.into(),
        provenance: graph_provenance,
        records,
        truncated,
    })
}

pub(crate) fn validate_program(unit: &ProgramUnit, expected_path: &str, maximum: usize) -> bool {
    unit.path == expected_path
        && unit.provenance.extractor_version == GRAPH_EXTRACTOR_VERSION
        && unit.records.len() <= maximum
        && unit.records.iter().all(|item| {
            item.location.path == expected_path
                && item.provenance == unit.provenance
                && item.inputs.iter().all(|value| normalized(value))
                && item.name.as_deref().is_none_or(normalized)
                && item.output.as_deref().is_none_or(normalized)
                && item.callee.as_deref().is_none_or(normalized)
                && record_with_dominance(
                    &item.kind,
                    item.name.as_deref(),
                    item.function.as_deref(),
                    item.inputs.clone(),
                    item.output.as_deref(),
                    item.callee.as_deref(),
                    item.location.clone(),
                    &item.provenance,
                    item.dominance_start.zip(item.dominance_end),
                ) == *item
        })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn analyze(
    facts: &[NormalizedFact],
    units: &[ProgramUnit],
    configuration: &ScanConfiguration,
    cancellation: &CancellationToken,
) -> Result<AnalysisResult, ScanError> {
    let started = Instant::now();
    let mut builder = GraphBuilder::new(configuration);
    builder.truncated = units.iter().any(|unit| unit.truncated);
    let mut file_nodes = BTreeMap::<String, (String, String)>::new();
    for unit in units {
        check_cancelled(cancellation)?;
        let location = start_location(&unit.path);
        let file = builder.node("file", Some(&unit.path), &location, &unit.provenance);
        let module = builder.node("module", Some(&unit.path), &location, &unit.provenance);
        let _edge = builder.edge("containment", &file, &module, &location, &unit.provenance);
        file_nodes.insert(unit.path.clone(), (file, module));
    }
    for fact in facts {
        check_cancelled(cancellation)?;
        let (_, module) = file_nodes
            .entry(fact.location.path.clone())
            .or_insert_with(|| {
                let location = start_location(&fact.location.path);
                let file = builder.node(
                    "file",
                    Some(&fact.location.path),
                    &location,
                    &fact.provenance,
                );
                let module = builder.node(
                    "module",
                    Some(&fact.location.path),
                    &location,
                    &fact.provenance,
                );
                let _edge =
                    builder.edge("containment", &file, &module, &location, &fact.provenance);
                (file, module)
            })
            .clone();
        let fact_kind = graph_kind_for_fact(&fact.kind);
        let node = builder.node(
            fact_kind,
            fact.name.as_deref(),
            &fact.location,
            &fact.provenance,
        );
        let _edge = builder.edge(
            "containment",
            &module,
            &node,
            &fact.location,
            &fact.provenance,
        );
        for relationship in &fact.relationships {
            let target = builder.node(
                "module-reference",
                Some(&relationship.target),
                &fact.location,
                &fact.provenance,
            );
            let edge_kind = relationship_edge_kind(&relationship.kind);
            let _edge = builder.edge(edge_kind, &node, &target, &fact.location, &fact.provenance);
        }
    }

    let mut record_nodes = BTreeMap::<String, String>::new();
    let mut function_nodes = BTreeMap::<String, String>::new();
    let mut raw_functions = BTreeMap::<String, Vec<String>>::new();
    let mut parameter_records = BTreeMap::<String, Vec<&ProgramRecord>>::new();
    let mut all_records = units
        .iter()
        .flat_map(|unit| unit.records.iter())
        .collect::<Vec<_>>();
    all_records.sort_by(|left, right| {
        (
            &left.location.path,
            left.location.span.start_byte,
            &left.record_id,
        )
            .cmp(&(
                &right.location.path,
                right.location.span.start_byte,
                &right.record_id,
            ))
    });
    for record in &all_records {
        let node = builder.node_with_semantic(
            graph_kind_for_record(&record.kind, record.name.as_deref()),
            record
                .name
                .as_deref()
                .or(record.output.as_deref())
                .or(record.callee.as_deref()),
            record.semantic.clone(),
            &record.location,
            &record.provenance,
        );
        record_nodes.insert(record.record_id.clone(), node.clone());
        if let Some((_, module)) = file_nodes.get(&record.location.path) {
            let _edge = builder.edge(
                "containment",
                module,
                &node,
                &record.location,
                &record.provenance,
            );
        }
        if matches!(record.kind.as_str(), "function" | "handler")
            && let (Some(qualified), Some(raw)) = (&record.function, &record.name)
        {
            function_nodes.insert(qualified.clone(), node.clone());
            raw_functions
                .entry(function_resolution_key(raw, &record.provenance))
                .or_default()
                .push(qualified.clone());
        }
        if (record.kind == "argument" || (record.kind == "source" && record.output.is_some()))
            && let Some(function) = &record.function
        {
            parameter_records
                .entry(function.clone())
                .or_default()
                .push(record);
        }
    }
    for parameters in parameter_records.values_mut() {
        parameters.sort_by_key(|record| record.location.span.start_byte);
    }
    add_control_and_call_edges(
        &all_records,
        &record_nodes,
        &function_nodes,
        &raw_functions,
        &mut builder,
    );

    let handlers = all_records
        .iter()
        .filter(|record| record.kind == "handler")
        .filter_map(|record| record.function.clone())
        .collect::<BTreeSet<_>>();
    let function_ends = all_records
        .iter()
        .filter(|record| matches!(record.kind.as_str(), "function" | "handler"))
        .filter_map(|record| {
            record
                .function
                .as_ref()
                .map(|function| (function.clone(), record.location.span.end_byte))
        })
        .collect::<BTreeMap<_, _>>();
    let helper_guard_policies = all_records
        .iter()
        .filter(|record| {
            record.kind == "guard"
                && (record
                    .name
                    .as_deref()
                    .is_none_or(|policy| !crate::semantics::is_operation_authorization(policy))
                    || guard_is_authorization(record, &all_records))
        })
        .filter_map(|record| {
            let function = record.function.as_ref()?;
            let function_end = function_ends.get(function)?;
            (record.dominance_end == Some(*function_end))
                .then(|| (function.clone(), record.name.clone().unwrap_or_default()))
        })
        .fold(
            BTreeMap::<String, BTreeSet<String>>::new(),
            |mut policies, (function, policy)| {
                if !policy.is_empty() {
                    policies.entry(function).or_default().insert(policy);
                }
                policies
            },
        );
    let propagated_guards = all_records
        .iter()
        .filter(|record| matches!(record.kind.as_str(), "call" | "guard"))
        .filter_map(|record| {
            let callee = record.callee.as_deref()?;
            let target = unique_function(callee, &raw_functions, &record.provenance)?;
            let policies = helper_guard_policies.get(target)?;
            Some(policies.iter().map(|policy| {
                let mut propagated = (*record).clone();
                propagated.kind = "guard".into();
                propagated.name = Some(policy.clone());
                propagated
            }))
        })
        .flatten()
        .collect::<Vec<_>>();
    let mut guards = BTreeMap::<String, Vec<&ProgramRecord>>::new();
    for record in all_records.iter().filter(|record| record.kind == "guard") {
        let resolves_locally = record
            .callee
            .as_deref()
            .and_then(|callee| unique_function(callee, &raw_functions, &record.provenance))
            .is_some();
        if !resolves_locally && let Some(function) = &record.function {
            guards.entry(function.clone()).or_default().push(record);
        } else if record.callee.is_none()
            && let Some(function) = &record.function
        {
            guards.entry(function.clone()).or_default().push(record);
        }
    }
    for record in &propagated_guards {
        if let Some(function) = &record.function {
            guards.entry(function.clone()).or_default().push(record);
        }
    }
    let handler_traces = unguarded_handler_traces(
        &handlers,
        &all_records,
        &raw_functions,
        &guards,
        &record_nodes,
        &function_nodes,
        &mut builder,
        configuration.max_interprocedural_depth,
    );
    for sink in all_records.iter().filter(|record| record.kind == "sink") {
        let Some(sink_node) = record_nodes.get(&sink.record_id) else {
            continue;
        };
        for guard_node in dominating_guards(sink, &guards, &record_nodes) {
            let _edge = builder.edge(
                "guard-dominance",
                &guard_node,
                sink_node,
                &sink.location,
                &sink.provenance,
            );
        }
    }
    let mut taints = BTreeMap::<(String, String), Trace>::new();
    let mut candidates = BTreeMap::<String, Candidate>::new();
    let candidate_budget = configuration
        .max_findings
        .saturating_mul(configuration.max_interprocedural_depth.saturating_add(1))
        .min(configuration.max_graph_edges);
    let mut candidate_limit_reached = false;
    let passes = configuration.max_interprocedural_depth.saturating_add(2);
    for _pass in 0..passes {
        let before = taints.len();
        let snapshot = taints.clone();
        for record in &all_records {
            check_cancelled(cancellation)?;
            let Some(record_node) = record_nodes.get(&record.record_id) else {
                continue;
            };
            let function = record.function.clone().unwrap_or_default();
            match record.kind.as_str() {
                "source" => {
                    if let Some(output) = &record.output {
                        insert_trace(
                            &mut taints,
                            (function.clone(), output.clone()),
                            Trace {
                                nodes: vec![record_node.clone()],
                                edges: Vec::new(),
                                source_function: record.function.clone(),
                                sanitizers: BTreeSet::new(),
                                values: BTreeSet::from([output.clone()]),
                                source_specificity: if matches!(
                                    record.name.as_deref(),
                                    Some("request-parameter" | "server-action-parameter")
                                ) {
                                    1
                                } else {
                                    2
                                },
                            },
                        );
                    }
                }
                "assignment" | "alias" | "transformation" => {
                    let trace =
                        trace_for_transformation(&snapshot, &function, record, &raw_functions);
                    if let (Some(output), Some(trace)) = (&record.output, trace) {
                        let edge_kind = if matches!(record.kind.as_str(), "assignment" | "alias") {
                            "assignment"
                        } else {
                            "source-to-sink-propagation"
                        };
                        let mut trace = extend_trace(
                            trace,
                            record_node,
                            builder.edge(
                                edge_kind,
                                trace.nodes.last().map_or(record_node, String::as_str),
                                record_node,
                                &record.location,
                                &record.provenance,
                            ),
                        );
                        trace.values.insert(output.clone());
                        insert_trace(&mut taints, (function.clone(), output.clone()), trace);
                    }
                }
                "sanitizer" => {
                    if let Some(trace) = trace_for_inputs(&snapshot, &function, &record.inputs) {
                        let edge = builder.edge(
                            "sanitization",
                            trace.nodes.last().map_or(record_node, String::as_str),
                            record_node,
                            &record.location,
                            &record.provenance,
                        );
                        let policies = sanitizer_policies(record);
                        if let Some(output) = &record.output
                            && !policies.is_empty()
                        {
                            let mut sanitized = extend_trace(trace, record_node, edge);
                            sanitized.values.insert(output.clone());
                            for policy in policies {
                                sanitized.sanitizers.insert(policy.into());
                            }
                            insert_trace(
                                &mut taints,
                                (function.clone(), output.clone()),
                                sanitized,
                            );
                        }
                    }
                }
                "call" => propagate_local_call(
                    record,
                    record_node,
                    &snapshot,
                    &mut taints,
                    &raw_functions,
                    &parameter_records,
                    &record_nodes,
                    &mut builder,
                ),
                "return" => {
                    if let Some(trace) = trace_for_inputs(&snapshot, &function, &record.inputs) {
                        let mut trace = extend_trace(
                            trace,
                            record_node,
                            builder.edge(
                                "returns",
                                trace.nodes.last().map_or(record_node, String::as_str),
                                record_node,
                                &record.location,
                                &record.provenance,
                            ),
                        );
                        trace.values.insert("@return".into());
                        let dominant = dominating_guard_records(record, &guards);
                        for guard in dominant {
                            let Some(policy) = guard.name.as_deref() else {
                                continue;
                            };
                            if guard_applies_to_trace(guard, &trace)
                                && (required_sanitizer_policy("SE1001") == Some(policy)
                                    || required_sanitizer_policy("SE1002") == Some(policy)
                                    || required_sanitizer_policy("SE1004") == Some(policy)
                                    || required_sanitizer_policy("SE1005") == Some(policy)
                                    || required_sanitizer_policy("SE1006") == Some(policy)
                                    || (policy == "filesystem-path-confinement"
                                        && trace_has_path_normalization(&trace, &builder)
                                        && guard_has_separator_boundary(guard, &all_records)))
                            {
                                trace.sanitizers.insert(policy.into());
                            }
                        }
                        insert_trace(&mut taints, (function.clone(), "@return".into()), trace);
                    }
                }
                "sink" => {
                    let tainted_trace = trace_for_inputs(&snapshot, &function, &record.inputs);
                    if let Some(trace) = tainted_trace
                        && let Some(rule_id) = rule_for_sink(record)
                    {
                        let dominant = dominating_guard_records(record, &guards);
                        if !trace_is_sanitized_for(
                            rule_id,
                            trace,
                            &dominant,
                            &builder,
                            &all_records,
                        ) {
                            let guard_nodes = dominant
                                .iter()
                                .filter_map(|guard| record_nodes.get(&guard.record_id).cloned())
                                .collect();
                            candidate_limit_reached |= add_candidate(
                                rule_id,
                                trace,
                                CandidateTarget {
                                    node: record_node,
                                    guards: guard_nodes,
                                    record,
                                },
                                &mut builder,
                                &mut candidates,
                                candidate_budget,
                            );
                        }
                    }
                    if record.name.as_deref() == Some("sensitive-mutation")
                        && !dominating_guard_records(record, &guards)
                            .iter()
                            .any(|guard| guard_is_authorization(guard, &all_records))
                        && let Some(handler_trace) =
                            tainted_trace.or_else(|| handler_traces.get(&function))
                    {
                        candidate_limit_reached |= add_candidate(
                            "SE1007",
                            handler_trace,
                            CandidateTarget {
                                node: record_node,
                                guards: Vec::new(),
                                record,
                            },
                            &mut builder,
                            &mut candidates,
                            candidate_budget,
                        );
                    }
                }
                _ => {}
            }
        }
        if taints.len() == before {
            break;
        }
    }

    let mut graph = EvidenceGraph {
        nodes: builder.nodes.into_values().collect(),
        edges: builder.edges.into_values().collect(),
    };
    graph
        .nodes
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));
    graph
        .edges
        .sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    let candidate_count = candidates.len();
    let (mut findings, suppression_diagnostics, suppressed) =
        findings_from_candidates(candidates.into_values().collect(), &graph, configuration);
    let findings_were_truncated = findings.len() > configuration.max_findings;
    findings.truncate(configuration.max_findings);
    let truncated = builder.truncated || findings_were_truncated || candidate_limit_reached;
    let limitations =
        analysis_limitations(configuration, truncated, candidate_limit_reached, units);
    Ok(AnalysisResult {
        summary: AnalysisSummary {
            nodes: graph.nodes.len(),
            edges: graph.edges.len(),
            candidate_paths: candidate_count,
            rules_evaluated: RULES.len(),
            findings: findings.len(),
            findings_suppressed: suppressed,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            truncated,
        },
        graph,
        findings,
        suppression_diagnostics,
        limitations,
    })
}

pub(crate) fn explain<'a>(report: &'a crate::ScanReport, finding_id: &str) -> Option<&'a Finding> {
    report
        .findings
        .iter()
        .find(|finding| finding.finding_id == finding_id)
}

#[must_use]
/// Returns the stable public catalog of built-in deterministic Phase 3 rules.
pub fn rules() -> Vec<RuleMetadata> {
    RULES
        .iter()
        .copied()
        .map(RuleDefinition::metadata)
        .collect()
}

#[derive(Clone, Copy)]
struct RuleDefinition {
    id: &'static str,
    title: &'static str,
    category: &'static str,
    severity: &'static str,
    confidence: &'static str,
    invariant: &'static str,
    prerequisites: &'static [&'static str],
    impact: &'static str,
    remediation: &'static str,
}

impl RuleDefinition {
    fn metadata(self) -> RuleMetadata {
        RuleMetadata {
            rule_id: self.id.into(),
            title: self.title.into(),
            category: self.category.into(),
            severity: self.severity.into(),
            confidence: self.confidence.into(),
            invariant: self.invariant.into(),
            taxonomy: crate::taxonomy::coordinates(self.id),
            primary_cwe: crate::taxonomy::primary_cwe(self.id),
            taxonomy_provenance: crate::taxonomy::provenance(self.id),
        }
    }
}

const RULES: [RuleDefinition; 7] = [
    RuleDefinition {
        id: "SE1001",
        title: "Untrusted input reaches command execution",
        category: "command-injection",
        severity: "high",
        confidence: "high",
        invariant: "Command execution arguments must not be controlled by untrusted input",
        prerequisites: &[
            "An attacker can control the demonstrated request value",
            "The process has permission to execute the sink",
        ],
        impact: "Arbitrary command execution with the application process privileges",
        remediation: "Avoid shell construction; use fixed executables and allowlisted arguments",
    },
    RuleDefinition {
        id: "SE1002",
        title: "Untrusted input reaches a raw SQL query",
        category: "sql-injection",
        severity: "high",
        confidence: "high",
        invariant: "Raw database query text must not be controlled by untrusted input",
        prerequisites: &[
            "An attacker can control the demonstrated request value",
            "The query reaches the configured database",
        ],
        impact: "Unauthorized database reads, writes, or destructive statements",
        remediation: "Use parameterized queries or typed query builders and keep SQL structure constant",
    },
    RuleDefinition {
        id: "SE1003",
        title: "Untrusted path reaches a filesystem operation",
        category: "path-traversal",
        severity: "high",
        confidence: "high",
        invariant: "Filesystem paths must be constrained to an authorized root",
        prerequisites: &[
            "An attacker can control the demonstrated path value",
            "The process can access the target filesystem location",
        ],
        impact: "Unauthorized file disclosure or modification",
        remediation: "Resolve against a fixed root, reject traversal, and enforce an allowlist",
    },
    RuleDefinition {
        id: "SE1004",
        title: "Untrusted URL reaches an outbound request",
        category: "server-side-request-forgery",
        severity: "high",
        confidence: "high",
        invariant: "Outbound request destinations must be constrained by policy",
        prerequisites: &[
            "An attacker can control the demonstrated URL",
            "The application can reach the target network",
        ],
        impact: "Requests to internal services or attacker-controlled destinations",
        remediation: "Parse the URL and enforce scheme, host, port, and redirect allowlists",
    },
    RuleDefinition {
        id: "SE1005",
        title: "Untrusted URL reaches a redirect",
        category: "open-redirect",
        severity: "medium",
        confidence: "high",
        invariant: "Redirect destinations must be constrained to trusted locations",
        prerequisites: &["An attacker can control the demonstrated redirect target"],
        impact: "Phishing or trust-boundary bypass through an attacker-selected redirect",
        remediation: "Use relative destinations or a strict destination allowlist",
    },
    RuleDefinition {
        id: "SE1006",
        title: "Untrusted input reaches dynamic code execution",
        category: "code-injection",
        severity: "critical",
        confidence: "high",
        invariant: "Dynamic code must never be constructed from untrusted input",
        prerequisites: &[
            "An attacker can control the demonstrated input",
            "The dynamic execution path is reachable",
        ],
        impact: "Arbitrary JavaScript execution in the application process",
        remediation: "Remove dynamic evaluation and use explicit parsing or dispatch",
    },
    RuleDefinition {
        id: "SE1007",
        title: "Exposed handler reaches a sensitive operation without an authorization guard",
        category: "missing-authorization",
        severity: "high",
        confidence: "high",
        invariant: "Exposed server handlers must enforce authentication or authorization before sensitive operations",
        prerequisites: &[
            "The demonstrated handler is externally reachable",
            "No framework-level guard exists outside the analyzed handler",
        ],
        impact: "Unauthenticated access to a sensitive operation",
        remediation: "Require an explicit authentication or authorization guard before the sink",
    },
];

fn collect_functions(
    path: &str,
    content: &[u8],
    root: Node<'_>,
    global_use_server: bool,
    route_handlers: &BTreeSet<String>,
    maximum: usize,
) -> Vec<FunctionInfo> {
    let mut functions = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if functions.len() >= maximum {
            break;
        }
        if is_function(node) {
            let raw_name = function_name(node, content)
                .unwrap_or_else(|| format!("anonymous@{}", node.start_byte()));
            let next_handler = file_name(path).starts_with("route.") && is_http_method(&raw_name);
            let server_action =
                (global_use_server && is_exported(node)) || function_has_use_server(node, content);
            let exported = is_exported(node);
            let handler = next_handler || server_action || route_handlers.contains(&raw_name);
            let parameters = node
                .child_by_field_name("parameters")
                .map(|parameters| parameter_names(path, content, parameters))
                .unwrap_or_default();
            functions.push(FunctionInfo {
                qualified_name: format!("{path}::{raw_name}"),
                name: raw_name,
                location: location_for_node(path, content, node),
                parameters,
                handler,
                server_action,
                exported,
            });
        }
        let child_count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
        for index in (0..child_count).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    functions.sort_by_key(|item| item.location.span.start_byte);
    functions
}

fn route_handler_names(root: Node<'_>, content: &[u8], maximum: usize) -> BTreeSet<String> {
    let mut handlers = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if handlers.len() >= maximum {
            break;
        }
        if node.kind() == "call_expression"
            && let Some(callee) = node
                .child_by_field_name("function")
                .and_then(|item| expression_name(item, content))
            && callee.rsplit_once('.').is_some_and(|(object, method)| {
                is_http_method(method)
                    && object
                        .rsplit('.')
                        .next()
                        .is_some_and(|name| matches!(name, "app" | "router" | "server"))
            })
            && let Some(arguments) = node.child_by_field_name("arguments")
            && let Some(last) = arguments.named_child(
                u32::try_from(arguments.named_child_count().saturating_sub(1)).unwrap_or(u32::MAX),
            )
            && let Some(handler) =
                expression_name(last, content).or_else(|| function_name(last, content))
        {
            handlers.insert(handler);
        }
        let count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
        for index in (0..count).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    handlers
}

fn collect_aliases(root: Node<'_>, content: &[u8], maximum: usize) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if aliases.len() >= maximum {
            break;
        }
        if node.kind() == "import_specifier" {
            let imported = node
                .child_by_field_name("name")
                .and_then(|child| expression_name(child, content));
            let local = node
                .child_by_field_name("alias")
                .and_then(|child| expression_name(child, content))
                .or_else(|| imported.clone());
            if let (Some(local), Some(imported)) = (local, imported) {
                aliases.insert(local, imported);
            }
        }
        if node.kind() == "variable_declarator"
            && let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            )
            && let Some(target) = expression_name(value, content)
        {
            if let Some(local) = expression_name(name, content) {
                if local != target {
                    aliases.insert(local, target.clone());
                }
            } else if matches!(name.kind(), "object_pattern" | "object") {
                collect_destructured_aliases(name, content, &target, &mut aliases, maximum);
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    aliases
}

fn collect_destructured_aliases(
    pattern: Node<'_>,
    content: &[u8],
    target: &str,
    aliases: &mut BTreeMap<String, String>,
    maximum: usize,
) {
    for index in 0..pattern.named_child_count() {
        if aliases.len() >= maximum {
            return;
        }
        let Some(item) = pattern.named_child(u32::try_from(index).unwrap_or(u32::MAX)) else {
            continue;
        };
        let key = item
            .child_by_field_name("key")
            .and_then(|child| expression_name(child, content));
        let local = item
            .child_by_field_name("value")
            .and_then(|child| expression_name(child, content));
        if let (Some(key), Some(local)) = (key, local) {
            aliases.insert(local, format!("{target}.{key}"));
        } else if let Some(local) = expression_name(item, content) {
            aliases.insert(local.clone(), format!("{target}.{local}"));
        }
    }
}

fn resolve_alias(name: &str, aliases: &BTreeMap<String, String>) -> String {
    let mut resolved = name.to_owned();
    for _ in 0..8 {
        let (head, suffix) = resolved
            .split_once('.')
            .map_or((resolved.as_str(), ""), |(head, suffix)| (head, suffix));
        let Some(target) = aliases.get(head) else {
            break;
        };
        let next = if suffix.is_empty() {
            target.clone()
        } else {
            format!("{target}.{suffix}")
        };
        if next == resolved {
            break;
        }
        resolved = next;
    }
    resolved
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn extract_record_for_node(
    path: &str,
    content: &[u8],
    node: Node<'_>,
    function: Option<&FunctionInfo>,
    provenance: &ParserProvenance,
    aliases: &BTreeMap<String, String>,
    records: &mut Vec<ProgramRecord>,
) {
    let function_name = function.map(|item| item.qualified_name.as_str());
    match node.kind() {
        "member_expression" | "subscript_expression" => {
            if let Some(name) = expression_name(node, content)
                && let Some(source_kind) = framework_member_source(function, &name)
                && !nested_in_more_specific_source(node, content, function)
            {
                records.push(record(
                    "source",
                    Some(source_kind.record_name()),
                    function_name,
                    Vec::new(),
                    Some(&name),
                    None,
                    location_for_node(path, content, node),
                    provenance,
                ));
            }
        }
        "variable_declarator" => {
            let output = node
                .child_by_field_name("name")
                .and_then(|item| expression_name(item, content));
            let value = node.child_by_field_name("value");
            if let (Some(output), Some(value)) = (output, value) {
                let callee =
                    call_callee(value, content).map(|callee| resolve_alias(&callee, aliases));
                let mut inputs = value_names(value, content);
                if callee.is_some() {
                    inputs.push(call_output_key(value));
                }
                let constant_destination = safe_constant_mapping_fallback(node, value, content);
                let kind =
                    if constant_destination || callee.as_deref().is_some_and(is_sanitizer_name) {
                        "sanitizer"
                    } else if is_transformation(value) {
                        "transformation"
                    } else {
                        "assignment"
                    };
                records.push(record(
                    kind,
                    if constant_destination {
                        Some("safe-redirect-destination")
                    } else {
                        callee.as_deref()
                    },
                    function_name,
                    inputs,
                    Some(&output),
                    callee.as_deref(),
                    location_for_node(path, content, node),
                    provenance,
                ));
            }
        }
        "assignment_expression" | "augmented_assignment_expression" => {
            let output = node
                .child_by_field_name("left")
                .and_then(|item| expression_name(item, content));
            let value = node.child_by_field_name("right");
            if let (Some(output), Some(value)) = (output, value) {
                records.push(record(
                    "assignment",
                    None,
                    function_name,
                    value_names(value, content),
                    Some(&output),
                    call_callee(value, content).as_deref(),
                    location_for_node(path, content, node),
                    provenance,
                ));
            }
        }
        "call_expression" => {
            let raw_callee = node
                .child_by_field_name("function")
                .and_then(|item| expression_name(item, content));
            let expression = node.utf8_text(content).unwrap_or_default();
            let source_inputs = value_names(node, content);
            let source_kind = framework_call_source(
                function,
                raw_callee.as_deref().unwrap_or_default(),
                expression,
                &source_inputs,
            );
            if raw_callee.is_none() {
                if let Some(source_kind) = source_kind
                    && let Some(output) = source_inputs.first()
                {
                    records.push(record(
                        "source",
                        Some(source_kind.record_name()),
                        function_name,
                        Vec::new(),
                        Some(output),
                        None,
                        location_for_node(path, content, node),
                        provenance,
                    ));
                }
                return;
            }
            let raw_callee = raw_callee.unwrap_or_default();
            let callee = resolve_alias(&raw_callee, aliases);
            let inputs = argument_values(node, content);
            let mut sink = sink_kind(&callee);
            if sink == Some("process-execution")
                && fixed_executable_with_shell_disabled(node, content, &callee)
            {
                sink = Some("process-argument-execution");
            }
            if matches!(sink, Some("redirect" | "network-request"))
                && destination_has_safe_fallback(node, content)
            {
                sink = Some("destination-policy-selected");
            }
            let kind = if sink.is_some() {
                "sink"
            } else if is_guard_name(&callee) {
                "guard"
            } else if is_sanitizer_name(&callee) {
                "sanitizer"
            } else if source_kind.is_some() {
                "source"
            } else {
                "call"
            };
            let name = if kind == "source" {
                source_kind.map(crate::framework_sources::FrameworkSourceKind::record_name)
            } else if sink == Some("database-access")
                && is_parameterized_database_call(node, content)
            {
                Some("database-parameterized")
            } else {
                sink.or(Some(callee.as_str()))
            };
            let call_output = call_output_key(node);
            let output = if matches!(kind, "source" | "call" | "guard" | "sanitizer") {
                Some(call_output.as_str())
            } else {
                None
            };
            let dominance = if matches!(kind, "guard" | "call") {
                direct_call_dominance(node, function)
            } else {
                None
            };
            let guard_name = (kind == "guard")
                .then(|| authorization_policy_name(&callee))
                .or(name);
            records.push(record_with_dominance(
                kind,
                guard_name,
                function_name,
                inputs,
                output,
                Some(&callee),
                location_for_node(path, content, node),
                provenance,
                dominance,
            ));
        }
        "new_expression" => {
            if node
                .child_by_field_name("constructor")
                .and_then(|item| expression_name(item, content))
                .as_deref()
                == Some("Function")
            {
                records.push(record(
                    "sink",
                    Some("dynamic-code-execution"),
                    function_name,
                    argument_values(node, content),
                    None,
                    Some("Function"),
                    location_for_node(path, content, node),
                    provenance,
                ));
            }
        }
        "return_statement" => {
            if let Some(value) = node.named_child(0) {
                records.push(record(
                    "return",
                    None,
                    function_name,
                    value_names(value, content),
                    Some("@return"),
                    None,
                    location_for_node(path, content, node),
                    provenance,
                ));
            }
        }
        "import_statement" => {
            let name = node
                .child_by_field_name("source")
                .and_then(|item| string_value(item, content));
            records.push(record(
                "import",
                name.as_deref(),
                function_name,
                Vec::new(),
                None,
                None,
                location_for_node(path, content, node),
                provenance,
            ));
        }
        "if_statement" => {
            if let Some(condition) = node.child_by_field_name("condition") {
                let inputs = value_names(condition, content);
                if let Some(policy) = guard_policy(condition, content, &inputs)
                    && let Some(dominance) = if_guard_dominance(node, condition, content, function)
                {
                    records.push(record_with_dominance(
                        "guard",
                        Some(policy),
                        function_name,
                        inputs,
                        None,
                        None,
                        location_for_node(path, content, condition),
                        provenance,
                        Some(dominance),
                    ));
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record(
    kind: &str,
    name: Option<&str>,
    function: Option<&str>,
    inputs: Vec<String>,
    output: Option<&str>,
    callee: Option<&str>,
    location: SourceLocation,
    provenance: &ParserProvenance,
) -> ProgramRecord {
    record_with_dominance(
        kind, name, function, inputs, output, callee, location, provenance, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_with_dominance(
    kind: &str,
    name: Option<&str>,
    function: Option<&str>,
    mut inputs: Vec<String>,
    output: Option<&str>,
    callee: Option<&str>,
    location: SourceLocation,
    provenance: &ParserProvenance,
    dominance: Option<(u64, u64)>,
) -> ProgramRecord {
    let mut seen_inputs = BTreeSet::new();
    inputs.retain(|input| seen_inputs.insert(input.clone()));
    let (dominance_start, dominance_end) = dominance.unzip();
    let mut hasher = blake3::Hasher::new();
    for value in [
        kind,
        name.unwrap_or(""),
        function.unwrap_or(""),
        output.unwrap_or(""),
        callee.unwrap_or(""),
        &location.path,
        &location.span.start_byte.to_string(),
        &location.span.end_byte.to_string(),
        &provenance.extractor_version,
    ] {
        hash_value(&mut hasher, value.as_bytes());
    }
    for input in &inputs {
        hash_value(&mut hasher, input.as_bytes());
    }
    if let Some((start, end)) = dominance {
        hash_value(&mut hasher, b"dominance-v1");
        hash_value(&mut hasher, &start.to_le_bytes());
        hash_value(&mut hasher, &end.to_le_bytes());
    }
    let fingerprint = hasher.finalize().to_hex().to_string();
    ProgramRecord {
        record_id: format!("pr_{}", &fingerprint[..24]),
        kind: kind.into(),
        name: name.map(str::to_owned),
        function: function.map(str::to_owned),
        inputs,
        output: output.map(str::to_owned),
        callee: callee.map(str::to_owned),
        location,
        provenance: provenance.clone(),
        dominance_start,
        dominance_end,
        semantic: crate::semantics::for_record(kind, name, callee),
        fingerprint,
    }
}

fn add_control_and_call_edges(
    records: &[&ProgramRecord],
    record_nodes: &BTreeMap<String, String>,
    function_nodes: &BTreeMap<String, String>,
    raw_functions: &BTreeMap<String, Vec<String>>,
    builder: &mut GraphBuilder,
) {
    let mut previous = BTreeMap::<String, &ProgramRecord>::new();
    for record in records {
        let Some(node) = record_nodes.get(&record.record_id) else {
            continue;
        };
        if let Some(function) = &record.function {
            if let Some(function_node) = function_nodes.get(function) {
                let _edge = builder.edge(
                    "containment",
                    function_node,
                    node,
                    &record.location,
                    &record.provenance,
                );
            }
            if !matches!(
                record.kind.as_str(),
                "function" | "handler" | "argument" | "source"
            ) && let Some(prior) = previous.insert(function.clone(), record)
                && let Some(prior_node) = record_nodes.get(&prior.record_id)
            {
                let _edge = builder.edge(
                    "control-flow",
                    prior_node,
                    node,
                    &record.location,
                    &record.provenance,
                );
            }
        }
        if record.kind == "call"
            && let Some(callee) = record
                .callee
                .as_ref()
                .and_then(|name| unique_function(name, raw_functions, &record.provenance))
            && let Some(target) = function_nodes.get(callee)
        {
            let _edge = builder.edge("calls", node, target, &record.location, &record.provenance);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn unguarded_handler_traces(
    handlers: &BTreeSet<String>,
    records: &[&ProgramRecord],
    functions: &BTreeMap<String, Vec<String>>,
    guards: &BTreeMap<String, Vec<&ProgramRecord>>,
    record_nodes: &BTreeMap<String, String>,
    function_nodes: &BTreeMap<String, String>,
    builder: &mut GraphBuilder,
    maximum_depth: usize,
) -> BTreeMap<String, Trace> {
    let mut traces = handlers
        .iter()
        .filter_map(|handler| {
            let node = function_nodes.get(handler)?;
            Some((
                handler.clone(),
                Trace {
                    nodes: vec![node.clone()],
                    edges: Vec::new(),
                    source_function: Some(handler.clone()),
                    sanitizers: BTreeSet::new(),
                    values: BTreeSet::new(),
                    source_specificity: 0,
                },
            ))
        })
        .collect::<BTreeMap<_, _>>();
    for _ in 0..maximum_depth {
        let before = traces.clone();
        let snapshot = traces.clone();
        for record in records
            .iter()
            .filter(|record| matches!(record.kind.as_str(), "call" | "guard" | "sanitizer"))
        {
            let Some(caller) = record.function.as_ref() else {
                continue;
            };
            let Some(trace) = snapshot.get(caller) else {
                continue;
            };
            if dominating_guard_records(record, guards)
                .iter()
                .any(|guard| guard_is_authorization(guard, records))
            {
                continue;
            }
            let Some(target) = record
                .callee
                .as_deref()
                .and_then(|callee| unique_function(callee, functions, &record.provenance))
            else {
                continue;
            };
            let Some(call_node) = record_nodes.get(&record.record_id) else {
                continue;
            };
            let Some(target_node) = function_nodes.get(target) else {
                continue;
            };
            let control_edge = builder.edge(
                "control-flow",
                trace.nodes.last().map_or(call_node, String::as_str),
                call_node,
                &record.location,
                &record.provenance,
            );
            let via_call = extend_trace(trace, call_node, control_edge);
            let call_edge = builder.edge(
                "calls",
                call_node,
                target_node,
                &record.location,
                &record.provenance,
            );
            let target_trace = extend_trace(&via_call, target_node, call_edge);
            traces
                .entry(target.clone())
                .and_modify(|existing| {
                    if target_trace < *existing {
                        existing.clone_from(&target_trace);
                    }
                })
                .or_insert(target_trace);
        }
        if traces == before {
            break;
        }
    }
    traces
}

#[allow(clippy::too_many_arguments)]
fn propagate_local_call(
    record: &ProgramRecord,
    record_node: &str,
    taints: &BTreeMap<(String, String), Trace>,
    updates: &mut BTreeMap<(String, String), Trace>,
    functions: &BTreeMap<String, Vec<String>>,
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
    record_nodes: &BTreeMap<String, String>,
    builder: &mut GraphBuilder,
) {
    let Some(callee_function) = record
        .callee
        .as_ref()
        .and_then(|name| unique_function(name, functions, &record.provenance))
    else {
        return;
    };
    let Some(arguments) = parameters.get(callee_function) else {
        return;
    };
    let origin_context = record.function.clone().unwrap_or_default();
    for (input, parameter) in record.inputs.iter().zip(arguments) {
        let Some(trace) = trace_for_inputs(taints, &origin_context, std::slice::from_ref(input))
        else {
            continue;
        };
        let Some(parameter_node) = record_nodes.get(&parameter.record_id) else {
            continue;
        };
        let call_edge = builder.edge(
            "argument-flow",
            trace.nodes.last().map_or(record_node, String::as_str),
            record_node,
            &record.location,
            &record.provenance,
        );
        let via_call = extend_trace(trace, record_node, call_edge);
        let parameter_edge = builder.edge(
            "argument-flow",
            record_node,
            parameter_node,
            &parameter.location,
            &parameter.provenance,
        );
        let mut parameter_trace = extend_trace(&via_call, parameter_node, parameter_edge);
        if let Some(output) = &parameter.output {
            parameter_trace.values.insert(output.clone());
            insert_trace(
                updates,
                (callee_function.clone(), output.clone()),
                parameter_trace,
            );
        }
    }
    if let (Some(output), Some(return_trace)) = (
        record.output.as_ref(),
        taints.get(&(callee_function.clone(), "@return".into())),
    ) {
        let edge = builder.edge(
            "returns",
            return_trace
                .nodes
                .last()
                .map_or(record_node, String::as_str),
            record_node,
            &record.location,
            &record.provenance,
        );
        let mut caller_trace = extend_trace(return_trace, record_node, edge);
        caller_trace.values.insert(output.clone());
        insert_trace(updates, (origin_context, output.clone()), caller_trace);
    }
}

fn add_candidate(
    rule_id: &'static str,
    trace: &Trace,
    target: CandidateTarget<'_>,
    builder: &mut GraphBuilder,
    candidates: &mut BTreeMap<String, Candidate>,
    maximum_candidates: usize,
) -> bool {
    if candidates.len() >= maximum_candidates {
        return true;
    }
    let edge = builder.edge(
        "source-to-sink-propagation",
        trace.nodes.last().map_or(target.node, String::as_str),
        target.node,
        &target.record.location,
        &target.record.provenance,
    );
    let extended = extend_trace(trace, target.node, edge);
    if !trace_is_realizable(&extended, builder) {
        return false;
    }
    let key = format!("{rule_id}:{}", target.node);
    let candidate = Candidate {
        rule_id,
        trace: extended,
        sink_node: target.node.into(),
        guards: target.guards,
    };
    if candidates.get(&key).is_none_or(|existing| {
        candidate.trace.source_specificity > existing.trace.source_specificity
            || (candidate.trace.source_specificity == existing.trace.source_specificity
                && candidate.trace < existing.trace)
    }) {
        candidates.insert(key, candidate);
    }
    candidates.len() >= maximum_candidates
}

#[allow(clippy::too_many_lines)]
fn findings_from_candidates(
    candidates: Vec<Candidate>,
    graph: &EvidenceGraph,
    configuration: &ScanConfiguration,
) -> (Vec<Finding>, Vec<SuppressionDiagnostic>, usize) {
    let nodes = graph
        .nodes
        .iter()
        .map(|node| (node.node_id.clone(), node))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    for candidate in candidates {
        let Some(rule) = RULES.iter().find(|rule| rule.id == candidate.rule_id) else {
            continue;
        };
        let steps = candidate
            .trace
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(index, node_id)| {
                let node = nodes.get(node_id)?;
                let edge_id = index
                    .checked_sub(1)
                    .and_then(|edge_index| candidate.trace.edges.get(edge_index))
                    .cloned();
                Some(EvidencePathStep {
                    node_id: node.node_id.clone(),
                    edge_id_from_previous: edge_id,
                    kind: node.kind.clone(),
                    semantic: node.semantic.clone(),
                    location: node.location.clone(),
                    provenance: node.provenance.clone(),
                    fingerprint: path_step_fingerprint(node_id, index),
                })
            })
            .collect::<Vec<_>>();
        let Some(source) = steps.first().map(|step| step.location.clone()) else {
            continue;
        };
        let Some(sink) = nodes
            .get(&candidate.sink_node)
            .map(|node| node.location.clone())
        else {
            continue;
        };
        let transformations = steps
            .iter()
            .filter(|step| {
                matches!(
                    step.kind.as_str(),
                    "assignment" | "alias" | "transformation" | "argument" | "return"
                )
            })
            .map(|step| step.location.clone())
            .collect::<Vec<_>>();
        let guards = candidate
            .guards
            .iter()
            .filter_map(|id| nodes.get(id).map(|node| node.location.clone()))
            .collect::<Vec<_>>();
        let fingerprint = finding_fingerprint(rule.id, &source, &sink, &steps);
        let semantic_fingerprint = semantic_fingerprint(rule.id, &steps);
        let taxonomy = crate::taxonomy::coordinates(rule.id);
        let evidence_contract_v2 =
            crate::evidence_contract::finding_contract_v2(taxonomy.as_ref(), rule.id, &steps);
        findings.push(Finding {
            rule_id: rule.id.into(),
            finding_id: format!("fd_{}", &fingerprint[..24]),
            title: rule.title.into(),
            category: rule.category.into(),
            severity: rule.severity.into(),
            confidence: rule.confidence.into(),
            evidence: steps.iter().map(|step| step.location.clone()).collect(),
            source: Some(source),
            transformations,
            guards,
            sink: Some(sink),
            evidence_path: steps,
            invariant: rule.invariant.into(),
            taxonomy,
            primary_cwe: crate::taxonomy::primary_cwe(rule.id),
            taxonomy_provenance: crate::taxonomy::provenance(rule.id),
            prerequisites: rule
                .prerequisites
                .iter()
                .map(|item| (*item).into())
                .collect(),
            impact: rule.impact.into(),
            remediation: rule.remediation.into(),
            verification_state: "verified-deterministic-path".into(),
            limitations: vec![
                "Bounded static analysis does not model runtime framework middleware".into(),
            ],
            fingerprint,
            semantic_fingerprint: Some(semantic_fingerprint),
            evidence_contract_v2,
        });
    }
    findings.sort_by(|left, right| {
        left.evidence_contract_v2
            .as_ref()
            .map(|contract| &contract.duplicate_fingerprint)
            .cmp(
                &right
                    .evidence_contract_v2
                    .as_ref()
                    .map(|contract| &contract.duplicate_fingerprint),
            )
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });
    findings.dedup_by(|left, right| {
        left.evidence_contract_v2
            .as_ref()
            .zip(right.evidence_contract_v2.as_ref())
            .is_some_and(|(left, right)| left.duplicate_fingerprint == right.duplicate_fingerprint)
            || left.fingerprint == right.fingerprint
    });
    apply_suppressions(findings, configuration)
}

fn apply_suppressions(
    mut findings: Vec<Finding>,
    configuration: &ScanConfiguration,
) -> (Vec<Finding>, Vec<SuppressionDiagnostic>, usize) {
    let valid_rules = RULES.iter().map(|rule| rule.id).collect::<BTreeSet<_>>();
    let mut diagnostics = Vec::new();
    let mut suppressed_ids = BTreeSet::new();
    for suppression in &configuration.suppressions {
        let mut code = "stale";
        let mut message = "Suppression did not match a current finding";
        let valid_path = !suppression.path.is_empty()
            && !suppression.path.starts_with('/')
            && !suppression.path.contains("..")
            && !suppression.path.contains('*')
            && !suppression.path.contains('?');
        if !valid_rules.contains(suppression.rule_id.as_str()) {
            code = "invalid-rule";
            message = "Suppression references an unknown rule";
        } else if !valid_path {
            code = "invalid-scope";
            message = "Suppression scope must be one exact repository-relative sink location";
        } else if suppression.reason.trim().len() < 8 {
            code = "invalid-reason";
            message = "Suppression reason must contain at least eight characters";
        } else if let Some(finding) = findings.iter().find(|finding| {
            finding.rule_id == suppression.rule_id
                && finding.sink.as_ref().is_some_and(|sink| {
                    sink.path == suppression.path && sink.span.start_byte == suppression.start_byte
                })
        }) {
            code = "applied";
            message = "Exact project suppression applied";
            suppressed_ids.insert(finding.finding_id.clone());
        }
        let fingerprint = suppression_fingerprint(
            &suppression.rule_id,
            &suppression.path,
            suppression.start_byte,
            &suppression.reason,
            code,
        );
        diagnostics.push(SuppressionDiagnostic {
            suppression_id: format!("sd_{}", &fingerprint[..24]),
            code: code.into(),
            rule_id: suppression.rule_id.clone(),
            path: valid_path.then(|| suppression.path.clone()),
            message: message.into(),
        });
    }
    let suppressed = suppressed_ids.len();
    findings.retain(|finding| !suppressed_ids.contains(&finding.finding_id));
    diagnostics.sort();
    (findings, diagnostics, suppressed)
}

fn analysis_limitations(
    configuration: &ScanConfiguration,
    truncated: bool,
    candidate_limit_reached: bool,
    units: &[ProgramUnit],
) -> Vec<crate::Limitation> {
    let mut limitations = vec![
        crate::Limitation { code: "bounded-interprocedural-analysis".into(), message: format!("Local inter-procedural propagation is bounded to {} traversal levels", configuration.max_interprocedural_depth) },
        crate::Limitation { code: "dynamic-resolution-limited".into(), message: "Dynamic imports, non-unique aliases, callbacks, recursion, and unresolved calls are not followed".into() },
        crate::Limitation { code: "semantic-resolution-bounded".into(), message: "Semantic identities, aliases, guards, and value correspondence are resolved only from deterministic local syntax within configured graph and inter-procedural bounds".into() },
        crate::Limitation { code: "framework-middleware-not-modeled".into(), message: "Authentication supplied only by external framework middleware is not proven by this phase".into() },
    ];
    if units
        .iter()
        .flat_map(|unit| &unit.records)
        .any(|record| record.name.as_deref() == Some("filesystem-operation"))
    {
        limitations.push(crate::Limitation {
            code: "filesystem-symlink-safety-not-proven".into(),
            message: "Lexical path confinement does not prove runtime symlink, mount, junction, race, or filesystem permission safety".into(),
        });
    }
    if units
        .iter()
        .flat_map(|unit| &unit.records)
        .any(|record| record.name.as_deref() == Some("process-argument-execution"))
    {
        limitations.push(crate::Limitation {
            code: "process-argument-semantics-not-modeled".into(),
            message: "A fixed executable with an argument array and shell processing disabled is not shell injection; executable-specific argument injection semantics remain unsupported".into(),
        });
    }
    if truncated {
        limitations.push(crate::Limitation {
            code: "analysis-limit-reached".into(),
            message: "A configured graph or finding bound truncated Phase 3 analysis".into(),
        });
    }
    if candidate_limit_reached {
        limitations.push(crate::Limitation {
            code: "candidate-path-limit-reached".into(),
            message: "Candidate evidence paths reached the conservative bound derived from finding, graph-edge, and inter-procedural limits".into(),
        });
    }
    let grammars = units
        .iter()
        .map(|unit| unit.provenance.grammar.as_str())
        .collect::<Vec<_>>();
    if grammars
        .iter()
        .any(|grammar| grammar.contains("tree-sitter-rust"))
    {
        limitations.push(crate::Limitation {
            code: "rust-dynamic-dispatch-limited".into(),
            message: "Trait-object dispatch, macros beyond their parsed invocation, and generated Rust are not expanded".into(),
        });
    }
    if grammars
        .iter()
        .any(|grammar| grammar.contains("tree-sitter-python"))
    {
        limitations.push(crate::Limitation {
            code: "python-dynamic-runtime-limited".into(),
            message: "Monkey patching, dynamic attributes, metaclasses, and runtime decorator behavior are not resolved".into(),
        });
    }
    if grammars
        .iter()
        .any(|grammar| grammar.contains("tree-sitter-go"))
    {
        limitations.push(crate::Limitation {
            code: "go-interface-callback-limited".into(),
            message: "Ambiguous interface dispatch, callbacks, reflection, and generated Go are not resolved".into(),
        });
    }
    limitations
}

fn trace_for_inputs<'a>(
    taints: &'a BTreeMap<(String, String), Trace>,
    function: &str,
    inputs: &[String],
) -> Option<&'a Trace> {
    let mut best = None;
    for input in inputs {
        let mut candidate = input.as_str();
        loop {
            if let Some(trace) = taints.get(&(function.to_owned(), candidate.to_owned())) {
                if best.is_none_or(|existing: &Trace| {
                    trace.source_specificity > existing.source_specificity
                        || (trace.source_specificity == existing.source_specificity
                            && trace < existing)
                }) {
                    best = Some(trace);
                }
                break;
            }
            let Some((prefix, _)) = candidate.rsplit_once('.') else {
                break;
            };
            candidate = prefix;
        }
    }
    best
}

fn trace_for_transformation<'a>(
    taints: &'a BTreeMap<(String, String), Trace>,
    function: &str,
    record: &ProgramRecord,
    functions: &BTreeMap<String, Vec<String>>,
) -> Option<&'a Trace> {
    if record
        .callee
        .as_deref()
        .and_then(|callee| unique_function(callee, functions, &record.provenance))
        .is_some()
        && let Some(marker) = record
            .inputs
            .iter()
            .find(|input| input.starts_with("@call:"))
    {
        return taints.get(&(function.to_owned(), marker.clone()));
    }
    trace_for_inputs(taints, function, &record.inputs)
}

fn insert_trace(
    taints: &mut BTreeMap<(String, String), Trace>,
    key: (String, String),
    trace: Trace,
) {
    if taints.get(&key).is_none_or(|existing| {
        trace.source_specificity > existing.source_specificity
            || (trace.source_specificity == existing.source_specificity && trace < *existing)
    }) {
        taints.insert(key, trace);
    }
}

fn extend_trace(trace: &Trace, node: &str, edge: Option<String>) -> Trace {
    let mut extended = trace.clone();
    if extended.nodes.last().is_none_or(|last| last != node) {
        if let Some(edge) = edge {
            extended.edges.push(edge);
        }
        extended.nodes.push(node.into());
    }
    extended
}

fn trace_is_realizable(trace: &Trace, builder: &GraphBuilder) -> bool {
    if trace.nodes.is_empty() || trace.edges.len().saturating_add(1) != trace.nodes.len() {
        return false;
    }
    trace.edges.iter().enumerate().all(|(index, edge_id)| {
        let Some(edge) = builder.edges.get(edge_id) else {
            return false;
        };
        let Some(from) = trace.nodes.get(index) else {
            return false;
        };
        let Some(to) = trace.nodes.get(index.saturating_add(1)) else {
            return false;
        };
        if edge.from_node != *from || edge.to_node != *to {
            return false;
        }
        if matches!(edge.kind.as_str(), "argument-flow" | "returns" | "calls") {
            return true;
        }
        let Some(from_node) = builder.nodes.get(from) else {
            return false;
        };
        let Some(to_node) = builder.nodes.get(to) else {
            return false;
        };
        locations_are_ordered(&from_node.location, &to_node.location)
    })
}

fn locations_are_ordered(from: &SourceLocation, to: &SourceLocation) -> bool {
    from.path != to.path
        || to.span.start_byte >= from.span.start_byte
        || (to.span.start_byte <= from.span.start_byte && to.span.end_byte >= from.span.end_byte)
}

fn sanitizer_policies(record: &ProgramRecord) -> Vec<&'static str> {
    crate::semantics::sanitizer_policy(
        record
            .callee
            .as_deref()
            .or(record.name.as_deref())
            .unwrap_or_default(),
    )
    .into_iter()
    .collect()
}

fn required_sanitizer_policy(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "SE1001" => Some("command-control-data-separation"),
        "SE1002" => Some("sql-control-data-separation"),
        "SE1003" => Some("filesystem-path-confinement"),
        "SE1004" => Some("outbound-destination-policy"),
        "SE1005" => Some("redirect-destination-policy"),
        "SE1006" => Some("dynamic-code-control-data-separation"),
        _ => None,
    }
}

fn dominating_guards(
    record: &ProgramRecord,
    guards: &BTreeMap<String, Vec<&ProgramRecord>>,
    record_nodes: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut nodes = dominating_guard_records(record, guards)
        .into_iter()
        .filter_map(|guard| record_nodes.get(&guard.record_id).cloned())
        .collect::<Vec<_>>();
    nodes.sort();
    nodes.dedup();
    nodes
}

fn dominating_guard_records<'a>(
    record: &ProgramRecord,
    guards: &'a BTreeMap<String, Vec<&'a ProgramRecord>>,
) -> Vec<&'a ProgramRecord> {
    record
        .function
        .as_ref()
        .and_then(|function| guards.get(function))
        .into_iter()
        .flatten()
        .copied()
        .filter(|guard| {
            guard
                .dominance_start
                .zip(guard.dominance_end)
                .is_some_and(|(start, end)| {
                    start <= record.location.span.start_byte && end >= record.location.span.end_byte
                })
                || ((!guard.provenance.grammar.contains("javascript")
                    && !guard.provenance.grammar.contains("typescript"))
                    && guard.location.span.start_byte < record.location.span.start_byte)
        })
        .collect()
}

fn trace_is_sanitized_for(
    rule_id: &str,
    trace: &Trace,
    guards: &[&ProgramRecord],
    builder: &GraphBuilder,
    records: &[&ProgramRecord],
) -> bool {
    let Some(policy) = required_sanitizer_policy(rule_id) else {
        return false;
    };
    if trace.sanitizers.contains(policy) {
        return true;
    }
    guards.iter().any(|guard| {
        guard.name.as_deref() == Some(policy)
            && guard_applies_to_trace(guard, trace)
            && (rule_id != "SE1003"
                || (trace_has_path_normalization(trace, builder)
                    && guard_has_separator_boundary(guard, records)))
    })
}

fn guard_is_authorization(guard: &ProgramRecord, records: &[&ProgramRecord]) -> bool {
    if !guard
        .name
        .as_deref()
        .is_some_and(crate::semantics::is_operation_authorization)
    {
        return false;
    }
    if guard.callee.is_some()
        || guard
            .function
            .as_deref()
            .and_then(|function| function.rsplit("::").next())
            .is_some_and(is_guard_name)
    {
        return true;
    }
    guard.inputs.iter().any(|input| {
        let root = input.split(['.', '[']).next().unwrap_or(input);
        records.iter().any(|record| {
            record.function == guard.function
                && record.location.span.end_byte <= guard.location.span.start_byte
                && record.output.as_deref() == Some(root)
                && record.callee.as_deref().is_some_and(is_identity_resolver)
        })
    })
}

fn is_identity_resolver(callee: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    [
        "identity.current",
        "currentuser",
        "current_user",
        "getprincipal",
        "getsession",
        "auth.session",
        "session.current",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn guard_has_separator_boundary(guard: &ProgramRecord, records: &[&ProgramRecord]) -> bool {
    let guard_has_separator = guard.inputs.iter().any(|value| {
        let lower = value.to_ascii_lowercase();
        terminal_identifier(&lower) == "sep"
    });
    let guard_has_root = guard.inputs.iter().any(|value| {
        let lower = value.to_ascii_lowercase();
        ["root", "base", "directory", "storage", "upload"]
            .iter()
            .any(|marker| lower.contains(marker))
    });
    if guard_has_separator
        && guard_has_root
        && guard.inputs.iter().any(|input| {
            let root = input.split(['.', '[']).next().unwrap_or(input);
            records.iter().any(|record| {
                record.function == guard.function
                    && record.location.span.end_byte <= guard.location.span.start_byte
                    && record.output.as_deref() == Some(root)
                    && record.callee.as_deref().is_some_and(|callee| {
                        let lower = callee.to_ascii_lowercase();
                        lower.contains("resolve")
                            || lower.contains("normalize")
                            || lower.contains("canonical")
                    })
            })
        })
    {
        return true;
    }
    guard.inputs.iter().any(|input| {
        let root = input.split(['.', '[']).next().unwrap_or(input);
        records.iter().any(|record| {
            record.function == guard.function
                && record.location.span.end_byte <= guard.location.span.start_byte
                && record.output.as_deref() == Some(root)
                && record.inputs.iter().any(|value| {
                    let lower = value.to_ascii_lowercase();
                    terminal_identifier(&lower) == "sep"
                })
                && record.inputs.iter().any(|value| {
                    let lower = value.to_ascii_lowercase();
                    lower.contains("resolve")
                        || lower.contains("normalize")
                        || lower.contains("canonical")
                })
                && record.inputs.iter().any(|value| {
                    let lower = value.to_ascii_lowercase();
                    ["root", "base", "directory", "storage", "upload"]
                        .iter()
                        .any(|marker| lower.contains(marker))
                })
        })
    })
}

fn guard_applies_to_trace(guard: &ProgramRecord, trace: &Trace) -> bool {
    guard.inputs.is_empty()
        || guard.inputs.iter().any(|guard_value| {
            trace
                .values
                .iter()
                .any(|trace_value| values_correspond(guard_value, trace_value))
        })
}

fn values_correspond(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with(['.', '[']))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with(['.', '[']))
}

fn trace_has_path_normalization(trace: &Trace, builder: &GraphBuilder) -> bool {
    trace.nodes.iter().any(|node_id| {
        builder
            .nodes
            .get(node_id)
            .and_then(|node| node.name.as_deref())
            .is_some_and(|name| {
                let lower = name.to_ascii_lowercase().replace("::", ".");
                [
                    "resolve",
                    "normalize",
                    "relative",
                    "realpath",
                    "canonicalize",
                ]
                .iter()
                .any(|leaf| lower.rsplit('.').next() == Some(*leaf))
            })
    })
}

fn rule_for_sink(record: &ProgramRecord) -> Option<&'static str> {
    match record.name.as_deref()? {
        "process-execution" => Some("SE1001"),
        "database-access" if record.callee.as_deref().is_some_and(is_raw_database_call) => {
            Some("SE1002")
        }
        "filesystem-operation" => Some("SE1003"),
        "network-request" => Some("SE1004"),
        "redirect" => Some("SE1005"),
        "dynamic-code-execution" => Some("SE1006"),
        _ => None,
    }
}

fn unique_function<'a>(
    callee: &str,
    functions: &'a BTreeMap<String, Vec<String>>,
    provenance: &ParserProvenance,
) -> Option<&'a String> {
    let leaf = callee
        .rsplit(['.', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(callee);
    let matches = functions.get(&function_resolution_key(leaf, provenance))?;
    (matches.len() == 1).then(|| &matches[0])
}

fn function_resolution_key(name: &str, provenance: &ParserProvenance) -> String {
    let namespace = if provenance.grammar.contains("tree-sitter-javascript")
        || provenance.grammar.contains("tree-sitter-typescript")
    {
        "javascript-typescript"
    } else if provenance.grammar.contains("tree-sitter-rust") {
        "rust"
    } else if provenance.grammar.contains("tree-sitter-python") {
        "python"
    } else if provenance.grammar.contains("tree-sitter-go") {
        "go"
    } else {
        "unknown"
    };
    format!("{namespace}:{name}")
}

fn containing_function<'a>(
    node: Node<'_>,
    functions: &'a [FunctionInfo],
) -> Option<&'a FunctionInfo> {
    functions
        .iter()
        .filter(|function| {
            function.location.span.start_byte
                <= u64::try_from(node.start_byte()).unwrap_or(u64::MAX)
                && function.location.span.end_byte
                    >= u64::try_from(node.end_byte()).unwrap_or(u64::MAX)
        })
        .min_by_key(|function| {
            function
                .location
                .span
                .end_byte
                .saturating_sub(function.location.span.start_byte)
        })
}

fn graph_kind_for_fact(kind: &str) -> &str {
    match kind {
        "function" => "function",
        "method" => "method",
        "http-route" | "http-route-handler" | "server-action-handler" => "handler",
        "guard-candidate" => "guard",
        "environment-access" => "configuration",
        "module-import" | "module-export" => "module",
        "process-execution"
        | "database-access"
        | "filesystem-operation"
        | "network-request"
        | "redirect"
        | "template-render"
        | "deserialization"
        | "dynamic-code-execution" => "sink",
        _ => "syntax-fact",
    }
}

fn graph_kind_for_record(kind: &str, name: Option<&str>) -> &'static str {
    match kind {
        "source" => "source",
        "assignment" => "assignment",
        "alias" | "transformation" => "transformation",
        "argument" => "argument",
        "return" => "return",
        "guard" => "guard",
        "sanitizer" => "sanitizer",
        "sink" => "sink",
        "handler" => "handler",
        "function" => "function",
        "import" => "module",
        "call" => "call",
        _ if name == Some("environment-access") => "configuration",
        _ => "syntax-fact",
    }
}

fn relationship_edge_kind(kind: &str) -> &str {
    match kind {
        "imports" | "re-exports" => "imports",
        "calls" | "invokes" | "constructs" | "handler" => "calls",
        "guards-branch" => "guard-dominance",
        "handles" | "exports" | "exports-server-action" => "containment",
        _ => "control-flow",
    }
}

fn sink_kind(callee: &str) -> Option<&'static str> {
    let lower = callee.to_ascii_lowercase();
    let leaf = lower.rsplit('.').next().unwrap_or(lower.as_str());
    if matches!(
        leaf,
        "exec" | "execsync" | "execfile" | "execfilesync" | "spawn" | "spawnsync" | "fork"
    ) || lower.starts_with("child_process.")
    {
        return Some("process-execution");
    }
    if matches!(
        leaf,
        "query" | "execute" | "raw" | "$queryraw" | "$executeraw"
    ) {
        return Some("database-access");
    }
    if matches!(
        leaf,
        "readfile"
            | "readfilesync"
            | "writefile"
            | "writefilesync"
            | "appendfile"
            | "unlink"
            | "rm"
            | "rename"
            | "mkdir"
            | "readdir"
            | "createreadstream"
            | "createwritestream"
    ) && (lower.starts_with("fs.") || !lower.contains('.'))
    {
        return Some("filesystem-operation");
    }
    if leaf == "fetch"
        || lower.starts_with("axios.")
        || matches!(
            lower.as_str(),
            "axios" | "http.get" | "http.request" | "https.get" | "https.request"
        )
    {
        return Some("network-request");
    }
    if leaf == "redirect" {
        return Some("redirect");
    }
    if leaf == "eval" || leaf == "function" {
        return Some("dynamic-code-execution");
    }
    if matches!(leaf, "revalidatepath" | "revalidatetag")
        || (matches!(
            leaf,
            "create"
                | "insert"
                | "update"
                | "upsert"
                | "delete"
                | "remove"
                | "destroy"
                | "save"
                | "publish"
                | "archive"
                | "erase"
                | "revoke"
                | "mutate"
        ) && [
            "db",
            "database",
            "prisma",
            "repository",
            "repo",
            "store",
            "model",
            "service",
            "vault",
            "resource",
            "record",
        ]
        .iter()
        .any(|marker| lower.contains(marker)))
    {
        return Some("sensitive-mutation");
    }
    None
}

fn fixed_executable_with_shell_disabled(call: Node<'_>, content: &[u8], callee: &str) -> bool {
    let leaf = callee
        .to_ascii_lowercase()
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_owned();
    if !matches!(
        leaf.as_str(),
        "spawn" | "spawnsync" | "execfile" | "execfilesync"
    ) {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let Some(executable) = arguments.named_child(0) else {
        return false;
    };
    let Some(argument_array) = arguments.named_child(1) else {
        return false;
    };
    let Some(options) = arguments.named_child(2) else {
        return false;
    };
    let fixed = matches!(executable.kind(), "string" | "string_fragment");
    let array = matches!(argument_array.kind(), "array" | "array_expression");
    fixed && array && object_has_false_property(options, content, "shell")
}

fn object_has_false_property(object: Node<'_>, content: &[u8], property: &str) -> bool {
    (0..object.named_child_count()).any(|index| {
        let Some(pair) = object.named_child(u32::try_from(index).unwrap_or(u32::MAX)) else {
            return false;
        };
        let Some(key) = pair.child_by_field_name("key") else {
            return false;
        };
        let Some(value) = pair.child_by_field_name("value") else {
            return false;
        };
        let key_text = key
            .utf8_text(content)
            .unwrap_or_default()
            .trim_matches(['\'', '"']);
        key_text == property && value.utf8_text(content).unwrap_or_default().trim() == "false"
    })
}

fn destination_has_safe_fallback(call: Node<'_>, content: &[u8]) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let Some(selection) = arguments.named_child(0) else {
        return false;
    };
    if !matches!(
        selection.kind(),
        "ternary_expression" | "conditional_expression"
    ) {
        return false;
    }
    let Some(condition) = selection.child_by_field_name("condition") else {
        return false;
    };
    let Some(consequence) = selection.child_by_field_name("consequence") else {
        return false;
    };
    let Some(alternative) = selection.child_by_field_name("alternative") else {
        return false;
    };
    let condition_text = condition
        .utf8_text(content)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let named_allowlist = condition_text.contains("allow")
        || condition_text.contains("trusted")
        || condition_text.contains("approved");
    let membership = condition_text.contains(".has(") || condition_text.contains(".includes(");
    let unsafe_shape = [
        "blocked",
        "denied",
        "rejected",
        "endswith(",
        "substring(",
        "indexof(",
        "userinfo",
        "username",
        "password",
    ]
    .iter()
    .any(|marker| condition_text.contains(marker));
    if !named_allowlist || !membership || unsafe_shape {
        return false;
    }
    let consequence_name = expression_name(consequence, content);
    let alternative_name = expression_name(alternative, content);
    let consequence_constant = fixed_string(consequence, content);
    let alternative_constant = fixed_string(alternative, content);
    let compact = condition_text.replace(char::is_whitespace, "");
    let negated = compact.starts_with('!')
        || ["!allowed", "!approved", "!trusted"]
            .iter()
            .any(|marker| compact.contains(marker));
    if negated {
        consequence_constant
            && alternative_name
                .as_deref()
                .is_some_and(|value| condition_mentions_value(&condition_text, value))
    } else {
        alternative_constant
            && consequence_name
                .as_deref()
                .is_some_and(|value| condition_mentions_value(&condition_text, value))
    }
}

fn safe_constant_mapping_fallback(declaration: Node<'_>, value: Node<'_>, content: &[u8]) -> bool {
    if value.kind() != "binary_expression"
        || !value
            .utf8_text(content)
            .is_ok_and(|text| text.contains("??"))
    {
        return false;
    }
    let Some(selection) = value.child_by_field_name("left") else {
        return false;
    };
    let Some(fallback) = value.child_by_field_name("right") else {
        return false;
    };
    if selection.kind() != "subscript_expression" || !fixed_string(fallback, content) {
        return false;
    }
    let Some(map_name) = selection
        .child_by_field_name("object")
        .and_then(|node| expression_name(node, content))
    else {
        return false;
    };
    let mut root = declaration;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= declaration.start_byte() {
            continue;
        }
        if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .and_then(|name| expression_name(name, content))
                .as_deref()
                == Some(map_name.as_str())
            && node
                .child_by_field_name("value")
                .is_some_and(|object| object_has_only_fixed_values(object, content))
        {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    false
}

fn object_has_only_fixed_values(object: Node<'_>, content: &[u8]) -> bool {
    if !matches!(object.kind(), "object" | "object_expression") || object.named_child_count() == 0 {
        return false;
    }
    (0..object.named_child_count()).all(|index| {
        object
            .named_child(u32::try_from(index).unwrap_or(u32::MAX))
            .and_then(|pair| pair.child_by_field_name("value"))
            .is_some_and(|value| fixed_string(value, content))
    })
}

fn fixed_string(node: Node<'_>, content: &[u8]) -> bool {
    matches!(node.kind(), "string" | "string_fragment")
        && node.utf8_text(content).is_ok_and(|value| {
            !value.contains("${") && !value.contains('+') && !value.contains('`')
        })
}

fn condition_mentions_value(condition: &str, value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    !value.is_empty()
        && condition
            .to_ascii_lowercase()
            .split(|character: char| {
                !character.is_alphanumeric() && character != '_' && character != '.'
            })
            .any(|part| part == value)
}

fn is_raw_database_call(callee: &str) -> bool {
    let normalized = callee.to_ascii_lowercase().replace("::", ".");
    matches!(
        normalized.rsplit('.').next(),
        Some("query" | "execute" | "raw" | "$queryraw" | "$executeraw")
    )
}
fn is_parameterized_database_call(call: Node<'_>, content: &[u8]) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    arguments.named_child_count() >= 2
        && arguments.named_child(0).is_some_and(|first| {
            matches!(first.kind(), "string" | "template_string")
                && !value_names(first, content)
                    .iter()
                    .any(|name| is_untrusted_source(name))
        })
}
fn is_sanitizer_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "sanitize",
        "escape",
        "validate",
        "assertsafe",
        "allowlist",
        "normalizesafepath",
        "safeurl",
        "saferedirect",
        "parameterize",
    ]
    .iter()
    .any(|token| lower.contains(token))
}
fn is_guard_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "auth",
        "authoriz",
        "permission",
        "requireuser",
        "session",
        "role",
        "policy",
        "guard",
        "owner",
        "tenant",
        "member",
        "canaccess",
        "enforce",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn authorization_policy_name(name: &str) -> &'static str {
    match crate::semantics::authorization_kind(name) {
        Some(crate::AuthorizationKind::Authentication) => {
            "authentication-before-sensitive-operation"
        }
        Some(crate::AuthorizationKind::Role) => "role-authorization-before-sensitive-operation",
        Some(crate::AuthorizationKind::Ownership) => {
            "ownership-authorization-before-sensitive-operation"
        }
        Some(crate::AuthorizationKind::Tenant) => "tenant-authorization-before-sensitive-operation",
        Some(crate::AuthorizationKind::General) | None => {
            "authorization-before-sensitive-operation"
        }
    }
}

fn function_has_use_server(function: Node<'_>, content: &[u8]) -> bool {
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    for index in 0..body.named_child_count().min(4) {
        let Some(statement) = body.named_child(u32::try_from(index).unwrap_or(u32::MAX)) else {
            break;
        };
        if statement.kind() != "expression_statement" {
            break;
        }
        let text = statement
            .utf8_text(content)
            .unwrap_or_default()
            .trim()
            .trim_end_matches(';')
            .trim();
        if matches!(text, "\"use server\"" | "'use server'") {
            return true;
        }
    }
    false
}

fn direct_call_dominance(call: Node<'_>, function: Option<&FunctionInfo>) -> Option<(u64, u64)> {
    let function = function?;
    let mut current = call.parent();
    while let Some(ancestor) = current {
        if u64::try_from(ancestor.start_byte()).ok()? <= function.location.span.start_byte
            && u64::try_from(ancestor.end_byte()).ok()? >= function.location.span.end_byte
        {
            break;
        }
        if matches!(
            ancestor.kind(),
            "if_statement"
                | "switch_statement"
                | "for_statement"
                | "for_in_statement"
                | "while_statement"
                | "do_statement"
                | "try_statement"
                | "catch_clause"
                | "ternary_expression"
        ) {
            return None;
        }
        current = ancestor.parent();
    }
    Some((
        u64::try_from(call.end_byte()).ok()?,
        function.location.span.end_byte,
    ))
}

fn guard_policy(condition: Node<'_>, content: &[u8], inputs: &[String]) -> Option<&'static str> {
    let lower = condition.utf8_text(content).ok()?.to_ascii_lowercase();
    if [
        "scope",
        "permission",
        "role",
        "capability",
        "owner",
        "tenant",
        "member",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return Some(authorization_policy_name(&lower));
    }
    let named_allowlist =
        lower.contains("allow") || lower.contains("trusted") || lower.contains("approved");
    let unsafe_destination_check = [
        "blocked",
        "denied",
        "rejected",
        "endswith(",
        "substring(",
        "indexof(",
        "userinfo",
        "username",
        "password",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        || ["hostname.includes(", ".host.includes(", "origin.includes("]
            .iter()
            .any(|marker| lower.contains(marker));
    let allowlist = named_allowlist
        && (lower.contains(".has(") || lower.contains(".includes("))
        && !unsafe_destination_check;
    let parsed_destination =
        lower.contains("protocol") && (lower.contains("hostname") || lower.contains(".host"));
    let exact_destination =
        parsed_destination && destination_components_compare_to_literals(condition, content);
    let origin_policy = lower.contains("origin") && allowlist;
    if (parsed_destination && (allowlist || exact_destination) && !unsafe_destination_check)
        || origin_policy
    {
        return Some("outbound-destination-policy");
    }
    let separator_boundary = lower.contains("sep")
        || lower.contains("relative(")
        || lower.contains("isabsolute(")
        || lower.contains("../")
        || lower.contains("..\\");
    if (lower.contains("startswith(") || lower.contains("relative("))
        && (separator_boundary || inputs.len() >= 2)
    {
        return Some("filesystem-path-confinement");
    }
    if allowlist
        && ["redirect", "destination", "next", "returnurl", "callback"]
            .iter()
            .any(|marker| lower.contains(marker))
    {
        return Some("redirect-destination-policy");
    }
    inputs
        .iter()
        .find(|name| is_guard_name(name))
        .map(|name| authorization_policy_name(name))
}

fn destination_components_compare_to_literals(condition: Node<'_>, content: &[u8]) -> bool {
    let mut protocol = false;
    let mut hostname = false;
    let mut stack = vec![condition];
    while let Some(node) = stack.pop() {
        if node.kind() == "binary_expression" {
            let operator = node
                .child_by_field_name("operator")
                .and_then(|item| item.utf8_text(content).ok())
                .unwrap_or_default();
            if matches!(operator, "==" | "===" | "!=" | "!==")
                && let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                )
            {
                let component = if is_fixed_string_literal(left, content) {
                    expression_name(right, content)
                } else if is_fixed_string_literal(right, content) {
                    expression_name(left, content)
                } else {
                    None
                };
                if let Some(component) = component {
                    let lower = component.to_ascii_lowercase();
                    protocol |= terminal_identifier(&lower) == "protocol";
                    hostname |= matches!(terminal_identifier(&lower), "hostname" | "host");
                }
            }
        }
        let count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
        for index in 0..count {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    protocol && hostname
}

fn is_fixed_string_literal(node: Node<'_>, content: &[u8]) -> bool {
    match node.kind() {
        "string" => true,
        "template_string" => !node.utf8_text(content).unwrap_or_default().contains("${"),
        _ => false,
    }
}

fn terminal_identifier(value: &str) -> &str {
    value.rsplit('.').next().unwrap_or(value)
}

fn if_guard_dominance(
    statement: Node<'_>,
    condition: Node<'_>,
    content: &[u8],
    function: Option<&FunctionInfo>,
) -> Option<(u64, u64)> {
    let function = function?;
    let consequence = statement.child_by_field_name("consequence")?;
    let condition_text = condition.utf8_text(content).ok()?;
    if condition_rejects_invalid(condition_text) && branch_terminates(consequence) {
        return Some((
            u64::try_from(statement.end_byte()).ok()?,
            function.location.span.end_byte,
        ));
    }
    if !condition_rejects_invalid(condition_text) {
        return Some((
            u64::try_from(consequence.start_byte()).ok()?,
            u64::try_from(consequence.end_byte()).ok()?,
        ));
    }
    None
}

fn condition_rejects_invalid(condition: &str) -> bool {
    let compact = condition
        .to_ascii_lowercase()
        .replace(char::is_whitespace, "");
    compact.contains('!')
        || compact.contains("==null")
        || compact.contains("===null")
        || compact.contains("==false")
        || compact.contains("===false")
        || compact.contains("==undefined")
        || compact.contains("===undefined")
}

fn branch_terminates(node: Node<'_>) -> bool {
    if matches!(node.kind(), "return_statement" | "throw_statement") {
        return true;
    }
    if node.kind() == "statement_block" {
        return node
            .named_child_count()
            .checked_sub(1)
            .and_then(|index| node.named_child(u32::try_from(index).ok()?))
            .is_some_and(branch_terminates);
    }
    if node.kind() == "if_statement" {
        return node
            .child_by_field_name("consequence")
            .is_some_and(branch_terminates)
            && node
                .child_by_field_name("alternative")
                .is_some_and(branch_terminates);
    }
    false
}

fn framework_member_source(
    function: Option<&FunctionInfo>,
    name: &str,
) -> Option<crate::framework_sources::FrameworkSourceKind> {
    let function = function?;
    let parameters = function
        .parameters
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    crate::framework_sources::classify_member_access(
        name,
        &parameters,
        function.handler || function.exported,
    )
}

fn framework_call_source(
    function: Option<&FunctionInfo>,
    callee: &str,
    expression: &str,
    inputs: &[String],
) -> Option<crate::framework_sources::FrameworkSourceKind> {
    let function = function?;
    let parameters = function
        .parameters
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    crate::framework_sources::classify_call(
        callee,
        expression,
        inputs,
        &parameters,
        function.handler || function.exported,
        function.server_action,
    )
}

fn nested_in_more_specific_source(
    node: Node<'_>,
    content: &[u8],
    function: Option<&FunctionInfo>,
) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "call_expression" {
            let callee = current
                .child_by_field_name("function")
                .and_then(|item| expression_name(item, content))
                .unwrap_or_default();
            let expression = current.utf8_text(content).unwrap_or_default();
            let inputs = value_names(current, content);
            return framework_call_source(function, &callee, expression, &inputs).is_some();
        }
        if is_function(current) || current.kind() == "variable_declarator" {
            break;
        }
        ancestor = current.parent();
    }
    false
}

fn is_untrusted_source(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.starts_with("req.") || lower.starts_with("request.") || lower.starts_with("formdata."))
        && [
            "param",
            "query",
            "body",
            "header",
            "cookie",
            "url",
            "searchparam",
            "formdata",
        ]
        .iter()
        .any(|token| lower.contains(token))
}
fn is_transformation(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "template_string"
            | "binary_expression"
            | "ternary_expression"
            | "call_expression"
            | "new_expression"
    )
}
fn is_function(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
    )
}
fn is_http_method(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD" | "ALL"
    )
}

fn function_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    node.child_by_field_name("name")
        .and_then(|item| expression_name(item, content))
        .or_else(|| {
            let parent = node.parent()?;
            (parent.kind() == "variable_declarator")
                .then(|| parent.child_by_field_name("name"))
                .flatten()
                .and_then(|item| expression_name(item, content))
        })
}

fn parameter_names(
    path: &str,
    content: &[u8],
    parameters: Node<'_>,
) -> Vec<(String, SourceLocation)> {
    let mut result = Vec::new();
    let mut stack = vec![parameters];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier"
            && let Some(name) = expression_name(node, content)
        {
            result.push((name, location_for_node(path, content, node)));
            continue;
        }
        let count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
        for index in (0..count).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    result
}

fn value_names(node: Node<'_>, content: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut stack = vec![node];
    while let Some(item) = stack.pop() {
        if item.kind() == "call_expression" {
            names.push(call_output_key(item));
        }
        if matches!(item.kind(), "member_expression" | "subscript_expression")
            && let Some(name) = expression_name(item, content)
        {
            names.push(name);
            continue;
        }
        if item.kind() == "identifier"
            && let Some(name) = expression_name(item, content)
        {
            names.push(name);
        }
        let count = u32::try_from(item.named_child_count()).unwrap_or(u32::MAX);
        for index in (0..count).rev() {
            if let Some(child) = item.named_child(index) {
                stack.push(child);
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

fn argument_values(call: Node<'_>, content: &[u8]) -> Vec<String> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let count = u32::try_from(arguments.named_child_count()).unwrap_or(u32::MAX);
    (0..count)
        .filter_map(|index| arguments.named_child(index))
        .flat_map(|argument| {
            if argument.kind() == "call_expression" {
                vec![call_output_key(argument)]
            } else {
                expression_name(argument, content)
                    .map_or_else(|| value_names(argument, content), |name| vec![name])
            }
        })
        .collect()
}

fn call_output_key(call: Node<'_>) -> String {
    format!("@call:{}", call.start_byte())
}

fn call_callee(node: Node<'_>, content: &[u8]) -> Option<String> {
    if node.kind() == "call_expression" {
        return node
            .child_by_field_name("function")
            .and_then(|item| expression_name(item, content));
    }
    if matches!(node.kind(), "parenthesized_expression" | "await_expression") {
        return node
            .named_child(0)
            .and_then(|item| call_callee(item, content));
    }
    None
}

fn expression_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" | "private_property_identifier" | "this" => {
            normalize(node.utf8_text(content).ok()?)
        }
        "member_expression" => {
            let object = node
                .child_by_field_name("object")
                .and_then(|item| expression_name(item, content))?;
            let property = node
                .child_by_field_name("property")
                .and_then(|item| expression_name(item, content))?;
            normalize(&format!("{object}.{property}"))
        }
        "subscript_expression" => {
            let object = node
                .child_by_field_name("object")
                .and_then(|item| expression_name(item, content))?;
            let index = node.child_by_field_name("index").and_then(|item| {
                string_value(item, content).or_else(|| expression_name(item, content))
            })?;
            normalize(&format!("{object}.{index}"))
        }
        "parenthesized_expression" | "await_expression" => node
            .named_child(0)
            .and_then(|item| expression_name(item, content)),
        _ => None,
    }
}

fn string_value(node: Node<'_>, content: &[u8]) -> Option<String> {
    let text = node.utf8_text(content).ok()?.trim();
    let value = text
        .strip_prefix(['\'', '"', '`'])
        .and_then(|item| item.strip_suffix(['\'', '"', '`']))
        .unwrap_or(text);
    normalize(value)
}
fn normalize(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= MAX_RECORD_NAME_BYTES
        && !value.chars().any(char::is_control))
    .then(|| value.into())
}
fn normalized(value: &str) -> bool {
    normalize(value).as_deref() == Some(value)
}
fn is_exported(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "export_statement" {
            return true;
        }
        if matches!(parent.kind(), "program" | "statement_block") {
            return false;
        }
        current = parent.parent();
    }
    false
}
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn location_for_node(path: &str, content: &[u8], node: Node<'_>) -> SourceLocation {
    location_for_range(path, content, node.start_byte(), node.end_byte())
}
fn location_for_range(path: &str, content: &[u8], start: usize, end: usize) -> SourceLocation {
    let start = start.min(content.len());
    let end = end.min(content.len()).max(start);
    let (start_line, start_column) = line_column(content, start);
    let (end_line, end_column) = line_column(content, end);
    SourceLocation {
        path: path.into(),
        span: SourceSpan {
            start_byte: u64::try_from(start).unwrap_or(u64::MAX),
            end_byte: u64::try_from(end).unwrap_or(u64::MAX),
            start_line,
            start_column,
            end_line,
            end_column,
        },
    }
}
fn line_column(content: &[u8], offset: usize) -> (u32, u32) {
    let before = &content[..offset.min(content.len())];
    let line = before.iter().fold(1_u32, |line, byte| {
        if *byte == b'\n' {
            line.saturating_add(1)
        } else {
            line
        }
    });
    let line_start = before
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index.saturating_add(1));
    let column = std::str::from_utf8(&before[line_start..]).map_or(1, |text| {
        u32::try_from(text.chars().count())
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    });
    (line, column)
}
fn start_location(path: &str) -> SourceLocation {
    SourceLocation {
        path: path.into(),
        span: SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
        },
    }
}

fn graph_fingerprint(
    kind: &str,
    name: Option<&str>,
    location: &SourceLocation,
    provenance: &ParserProvenance,
) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [
        kind,
        name.unwrap_or(""),
        &location.path,
        &location.span.start_byte.to_string(),
        &location.span.end_byte.to_string(),
        &provenance.parser,
        &provenance.grammar,
        &provenance.extractor_version,
    ] {
        hash_value(&mut hasher, value.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}
fn edge_fingerprint(
    kind: &str,
    from: &str,
    to: &str,
    location: &SourceLocation,
    provenance: &ParserProvenance,
) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [
        kind,
        from,
        to,
        &location.path,
        &location.span.start_byte.to_string(),
        &provenance.extractor_version,
    ] {
        hash_value(&mut hasher, value.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}
fn path_step_fingerprint(node: &str, index: usize) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_value(&mut hasher, node.as_bytes());
    hash_value(&mut hasher, &index.to_le_bytes());
    hasher.finalize().to_hex().to_string()
}
fn finding_fingerprint(
    rule: &str,
    source: &SourceLocation,
    sink: &SourceLocation,
    steps: &[EvidencePathStep],
) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [
        rule,
        &source.path,
        &source.span.start_byte.to_string(),
        &sink.path,
        &sink.span.start_byte.to_string(),
    ] {
        hash_value(&mut hasher, value.as_bytes());
    }
    for step in steps {
        hash_value(&mut hasher, step.node_id.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}
fn semantic_fingerprint(rule: &str, steps: &[EvidencePathStep]) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_value(&mut hasher, b"secure-semantic-fingerprint-v1");
    hash_value(&mut hasher, rule.as_bytes());
    let source = steps
        .first()
        .and_then(|step| step.semantic.as_ref())
        .map_or("source.handler", |semantic| semantic.identity.as_str());
    let sink = steps
        .last()
        .and_then(|step| step.semantic.as_ref())
        .map_or("sink.unknown", |semantic| semantic.identity.as_str());
    hash_value(&mut hasher, source.as_bytes());
    hash_value(&mut hasher, sink.as_bytes());
    hasher.finalize().to_hex().to_string()
}
fn suppression_fingerprint(rule: &str, path: &str, start: u64, reason: &str, code: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [rule, path, &start.to_string(), reason, code] {
        hash_value(&mut hasher, value.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}
fn hash_value(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}
fn check_cancelled(cancellation: &CancellationToken) -> Result<(), ScanError> {
    if cancellation.is_cancelled() {
        Err(ScanError::Cancelled)
    } else {
        Ok(())
    }
}
