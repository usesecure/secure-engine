use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
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
const MAX_FIXED_POINT_PASSES: usize = 8;

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
    parameters: Vec<ParameterInfo>,
    handler: bool,
    server_action: bool,
    exported: bool,
}

#[derive(Clone)]
struct ParameterInfo {
    name: String,
    location: SourceLocation,
    argument_index: usize,
    property_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct Trace {
    nodes: Vec<String>,
    edges: Vec<String>,
    source_function: Option<String>,
    source_node: String,
    source_path: String,
    source_start: u64,
    source_end: u64,
    value_identity: String,
    field_sensitive: bool,
    sanitizers: BTreeSet<String>,
    values: BTreeSet<String>,
    source_specificity: u8,
    interprocedural_depth: usize,
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum AuthorizationSummaryMode {
    Principal,
    FilteredPrincipal,
    Boolean,
    Enforced,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AuthorizationSummary {
    function: String,
    policy: String,
    mode: AuthorizationSummaryMode,
    parameter_bindings: BTreeSet<usize>,
}

#[derive(Clone, Debug)]
struct ImportBinding {
    imported: String,
    local: String,
    module: String,
}

type AliasMap = BTreeMap<(String, String), BTreeSet<String>>;

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

#[allow(clippy::too_many_lines)]
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
    let aliases = collect_aliases(root, content, &functions, maximum_records);
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
        for parameter in &function.parameters {
            if records.len() >= maximum_records {
                truncated = true;
                break;
            }
            let is_source = function.handler && function.server_action;
            records.push(record(
                if is_source { "source" } else { "argument" },
                Some(if is_source {
                    if function.server_action {
                        "server-action-parameter"
                    } else {
                        "request-parameter"
                    }
                } else {
                    &parameter.name
                }),
                Some(&function.qualified_name),
                parameter_markers(parameter),
                Some(&parameter.name),
                None,
                parameter.location.clone(),
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
    append_authorization_candidates(
        path,
        content,
        root,
        &functions,
        &graph_provenance,
        &mut records,
        maximum_records,
    );
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
    let mut records_by_function = BTreeMap::<String, Vec<&ProgramRecord>>::new();
    for record in &all_records {
        if let Some(function) = &record.function {
            records_by_function
                .entry(function.clone())
                .or_default()
                .push(record);
        }
    }
    let import_bindings = all_records
        .iter()
        .filter(|record| record.kind == "import-binding")
        .filter_map(|record| {
            Some((
                record.location.path.clone(),
                ImportBinding {
                    imported: record.output.clone()?,
                    local: record.name.clone()?,
                    module: record.callee.clone()?,
                },
            ))
        })
        .fold(
            BTreeMap::<String, Vec<ImportBinding>>::new(),
            |mut bindings, (path, binding)| {
                bindings.entry(path).or_default().push(binding);
                bindings
            },
        );
    for record in &all_records {
        if matches!(
            record.kind.as_str(),
            "authorization-candidate" | "control-gate"
        ) {
            continue;
        }
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
        &import_bindings,
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
    let authorization_summaries = authorization_summaries(
        &all_records,
        &raw_functions,
        &import_bindings,
        &parameter_records,
        configuration.max_interprocedural_depth,
    );
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
    let mut propagated_guards = all_records
        .iter()
        .filter(|record| matches!(record.kind.as_str(), "call" | "guard"))
        .filter_map(|record| {
            let callee = record.callee.as_deref()?;
            let target = unique_function(callee, record, &raw_functions, &import_bindings)?;
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
    propagated_guards.extend(summary_authorization_guards(
        &all_records,
        &authorization_summaries,
        &raw_functions,
        &import_bindings,
        &parameter_records,
    ));
    let mut guards = BTreeMap::<String, Vec<&ProgramRecord>>::new();
    for record in all_records.iter().filter(|record| record.kind == "guard") {
        let resolves_locally = record
            .callee
            .as_deref()
            .and_then(|callee| unique_function(callee, record, &raw_functions, &import_bindings))
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
        &import_bindings,
        &guards,
        &record_nodes,
        &function_nodes,
        &mut builder,
        configuration.max_interprocedural_depth,
    );
    let resource_authorized_sinks = all_records
        .iter()
        .copied()
        .filter(|record| record.kind == "sink")
        .filter(|record| record.name.as_deref() == Some("sensitive-mutation"))
        .filter(|record| {
            dominating_guard_records(record, &guards)
                .iter()
                .any(|guard| {
                    guard
                        .function
                        .as_ref()
                        .and_then(|function| records_by_function.get(function))
                        .is_some_and(|function_records| {
                            resource_authorization_applies_to_sink(guard, record, function_records)
                        })
                })
        })
        .map(|record| record.record_id.clone())
        .collect::<BTreeSet<_>>();
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
    let legacy_passes = configuration.max_interprocedural_depth.saturating_add(2);
    let passes = legacy_passes.max(MAX_FIXED_POINT_PASSES);
    for pass in 0..passes {
        let before = taints.clone();
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
                                source_node: record_node.clone(),
                                source_path: record.location.path.clone(),
                                source_start: record.location.span.start_byte,
                                source_end: record.location.span.end_byte,
                                value_identity: String::new(),
                                field_sensitive: source_is_field_container(record),
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
                                interprocedural_depth: 0,
                            },
                        );
                    }
                }
                "assignment" | "alias" | "transformation" => {
                    let trace = trace_for_transformation(
                        &snapshot,
                        &function,
                        record,
                        &raw_functions,
                        &import_bindings,
                    );
                    if let Some(output) = &record.output {
                        if let Some(trace) = trace {
                            let edge_kind =
                                if matches!(record.kind.as_str(), "assignment" | "alias") {
                                    "assignment"
                                } else {
                                    "source-to-sink-propagation"
                                };
                            let mut trace = extend_trace(
                                &trace,
                                record_node,
                                builder.edge(
                                    edge_kind,
                                    trace.nodes.last().map_or(record_node, String::as_str),
                                    record_node,
                                    &record.location,
                                    &record.provenance,
                                ),
                            );
                            if record.kind == "transformation"
                                && !record.callee.as_deref().is_some_and(source_container_call)
                            {
                                trace.field_sensitive = false;
                            }
                            if record.kind == "transformation"
                                && trace.sanitizers.contains("filesystem-path-confinement")
                                && !record.callee.as_deref().is_some_and(|callee| {
                                    transparent_value_coercion(callee)
                                        || unique_function(
                                            callee,
                                            record,
                                            &raw_functions,
                                            &import_bindings,
                                        )
                                        .is_some()
                                })
                            {
                                trace.sanitizers.remove("filesystem-path-confinement");
                            }
                            trace.values.insert(output.clone());
                            insert_trace(&mut taints, (function.clone(), output.clone()), trace);
                        } else if record.kind == "assignment"
                            && record.dominance_start.is_some()
                            && record.dominance_end.is_some()
                            && !record
                                .inputs
                                .iter()
                                .any(|input| values_correspond(input, output))
                        {
                            taints.remove(&(function.clone(), output.clone()));
                        }
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
                            let mut sanitized = extend_trace(&trace, record_node, edge);
                            sanitized.field_sensitive = false;
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
                    &import_bindings,
                    &guards,
                    &all_records,
                    &parameter_records,
                    &record_nodes,
                    &mut builder,
                    configuration.max_interprocedural_depth,
                ),
                "return" => {
                    if let Some(trace) = trace_for_inputs(&snapshot, &function, &record.inputs) {
                        let mut trace = extend_trace(
                            &trace,
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
                            if guard_applies_to_trace(guard, &trace, &snapshot)
                                && (policy == crate::semantics::POLICY_EXACT_ALLOWLIST
                                    || required_sanitizer_policy("SE1001") == Some(policy)
                                    || required_sanitizer_policy("SE1002") == Some(policy)
                                    || required_sanitizer_policy("SE1004") == Some(policy)
                                    || required_sanitizer_policy("SE1005") == Some(policy)
                                    || required_sanitizer_policy("SE1006") == Some(policy)
                                    || (policy == "filesystem-path-confinement"
                                        && filesystem_guard_proves_values(
                                            guard,
                                            &record.inputs,
                                            record,
                                            &trace,
                                            &all_records,
                                            &snapshot,
                                        )))
                            {
                                trace.sanitizers.insert(policy.into());
                            }
                        }
                        insert_trace(&mut taints, (function.clone(), "@return".into()), trace);
                    }
                }
                "sink" => {
                    let sink_inputs = sensitive_sink_inputs(record);
                    let tainted_trace = trace_for_inputs(&snapshot, &function, &sink_inputs);
                    if let Some(trace) = tainted_trace.as_ref()
                        && let Some(rule_id) = rule_for_sink(record)
                    {
                        let dominant = dominating_guard_records(record, &guards);
                        if trace_is_sanitized_for(
                            rule_id,
                            trace,
                            &dominant,
                            &all_records,
                            &snapshot,
                            record,
                        ) {
                            candidates.remove(&format!("{rule_id}:{record_node}"));
                        } else if extended_round_candidate_allowed(
                            rule_id,
                            pass,
                            legacy_passes,
                            candidates.contains_key(&format!("{rule_id}:{record_node}")),
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
                    let authorization_trace = tainted_trace
                        .as_ref()
                        .or_else(|| handler_traces.get(&function));
                    let has_effective_authorization = authorization_trace.is_some_and(|trace| {
                        trace
                            .sanitizers
                            .iter()
                            .any(|policy| crate::semantics::is_operation_authorization(policy))
                            || resource_authorized_sinks.contains(&record.record_id)
                            || dominating_guard_records(record, &guards)
                                .iter()
                                .any(|guard| {
                                    guard_is_authorization(guard, &all_records)
                                        && authorization_applies_to_trace(guard, trace, &snapshot)
                                })
                    });
                    if record.name.as_deref() == Some("sensitive-mutation")
                        && !has_effective_authorization
                        && let Some(handler_trace) = tainted_trace
                            .as_ref()
                            .or_else(|| handler_traces.get(&function))
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
                    } else if record.name.as_deref() == Some("sensitive-mutation") {
                        candidates.remove(&format!("SE1007:{record_node}"));
                    }
                }
                _ => {}
            }
        }
        if taints == before {
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

fn collect_aliases(
    root: Node<'_>,
    content: &[u8],
    functions: &[FunctionInfo],
    maximum: usize,
) -> AliasMap {
    let mut aliases = AliasMap::new();
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
                insert_alias(&mut aliases, "", &local, &imported);
            }
        }
        if node.kind() == "variable_declarator"
            && let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            )
            && let Some(target) = expression_name(value, content)
        {
            let scope = containing_function(node, functions)
                .map(|function| function.qualified_name.as_str())
                .unwrap_or_default();
            if let Some(local) = expression_name(name, content) {
                if local != target {
                    insert_alias(&mut aliases, scope, &local, &target);
                }
            } else if matches!(name.kind(), "object_pattern" | "object") {
                collect_destructured_aliases(name, content, &target, scope, &mut aliases, maximum);
            }
        }
        if matches!(
            node.kind(),
            "assignment_expression" | "augmented_assignment_expression"
        ) && let (Some(local), Some(target)) = (
            node.child_by_field_name("left")
                .and_then(|value| expression_name(value, content)),
            node.child_by_field_name("right")
                .and_then(|value| expression_name(value, content)),
        ) {
            let scope = containing_function(node, functions)
                .map(|function| function.qualified_name.as_str())
                .unwrap_or_default();
            insert_alias(&mut aliases, scope, &local, &target);
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
    scope: &str,
    aliases: &mut AliasMap,
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
            insert_alias(aliases, scope, &local, &format!("{target}.{key}"));
        } else if let Some(local) = expression_name(item, content) {
            insert_alias(aliases, scope, &local, &format!("{target}.{local}"));
        }
    }
}

fn insert_alias(aliases: &mut AliasMap, scope: &str, local: &str, target: &str) {
    aliases
        .entry((scope.to_owned(), local.to_owned()))
        .or_default()
        .insert(target.to_owned());
}

fn resolve_alias(name: &str, function: Option<&FunctionInfo>, aliases: &AliasMap) -> String {
    let mut resolved = name.to_owned();
    let scope = function
        .map(|function| function.qualified_name.as_str())
        .unwrap_or_default();
    for _ in 0..8 {
        let (head, suffix) = resolved
            .split_once('.')
            .map_or((resolved.as_str(), ""), |(head, suffix)| (head, suffix));
        let targets = aliases
            .get(&(scope.to_owned(), head.to_owned()))
            .or_else(|| aliases.get(&(String::new(), head.to_owned())));
        let Some(target) = targets.and_then(|targets| {
            (targets.len() == 1)
                .then(|| targets.iter().next())
                .flatten()
        }) else {
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
    aliases: &AliasMap,
    records: &mut Vec<ProgramRecord>,
) {
    let function_name = function.map(|item| item.qualified_name.as_str());
    match node.kind() {
        "member_expression" | "subscript_expression" => {
            if let Some(name) = expression_name(node, content)
                && let Some(source_kind) =
                    framework_member_source(function, &resolve_alias(&name, function, aliases))
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
            let name_node = node.child_by_field_name("name");
            let output = name_node.and_then(|item| expression_name(item, content));
            let value = node.child_by_field_name("value");
            if let (Some(pattern), Some(value)) = (name_node, value)
                && matches!(pattern.kind(), "object_pattern" | "array_pattern")
            {
                append_destructuring_records(
                    path, content, pattern, value, function, provenance, aliases, records,
                );
                return;
            }
            if let (Some(output), Some(value)) = (output, value) {
                let callee = call_callee(value, content)
                    .map(|callee| resolve_alias(&callee, function, aliases));
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
                records.push(record_with_dominance(
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
                    direct_call_dominance(node, function),
                ));
            }
        }
        "assignment_expression" | "augmented_assignment_expression" => {
            let output = node
                .child_by_field_name("left")
                .and_then(|item| expression_name(item, content));
            let value = node.child_by_field_name("right");
            if let (Some(output), Some(value)) = (output, value) {
                records.push(record_with_dominance(
                    "assignment",
                    None,
                    function_name,
                    value_names(value, content),
                    Some(&output),
                    call_callee(value, content).as_deref(),
                    location_for_node(path, content, node),
                    provenance,
                    direct_call_dominance(node, function),
                ));
            }
        }
        "call_expression" => {
            let raw_callee = node
                .child_by_field_name("function")
                .and_then(|item| expression_name(item, content));
            let dynamic_callee = unshadowed_dynamic_code_callee(node, content, function, aliases);
            let expression = node.utf8_text(content).unwrap_or_default();
            let source_inputs = value_names(node, content);
            let resolved_callee = raw_callee
                .as_deref()
                .map(|callee| resolve_alias(callee, function, aliases))
                .unwrap_or_default();
            let source_kind =
                framework_call_source(function, &resolved_callee, expression, &source_inputs);
            if raw_callee.is_none() && dynamic_callee.is_none() {
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
            let callee = dynamic_callee.map_or_else(
                || resolve_alias(&raw_callee, function, aliases),
                str::to_owned,
            );
            let inputs = argument_values(node, content);
            let mut sink = if dynamic_callee.is_some() {
                Some("dynamic-code-execution")
            } else {
                sink_kind(&callee)
            };
            if sink == Some("process-execution")
                && fixed_executable_without_shell(node, content, &callee)
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
            let module = node
                .child_by_field_name("source")
                .and_then(|item| string_value(item, content));
            records.push(record(
                "import",
                module.as_deref(),
                function_name,
                Vec::new(),
                None,
                None,
                location_for_node(path, content, node),
                provenance,
            ));
            if let Some(module) = module.as_deref() {
                append_import_bindings(
                    path,
                    content,
                    node,
                    module,
                    function_name,
                    provenance,
                    records,
                );
            }
        }
        "if_statement" => {
            if let Some(condition) = node.child_by_field_name("condition") {
                let mut inputs = value_names(condition, content);
                if condition_contains_conjunction(condition, content) {
                    inputs.push("@conditional-conjunction".into());
                }
                if let Some(dominance) = if_guard_dominance(node, condition, content, function)
                    && function.is_some_and(|function| {
                        authorization_guard_survives_try_context(node, function, content)
                    })
                {
                    inputs.extend(filesystem_confinement_markers(node, condition, content));
                    records.push(record_with_dominance(
                        "control-gate",
                        None,
                        function_name,
                        inputs.clone(),
                        None,
                        None,
                        location_for_node(path, content, condition),
                        provenance,
                        Some(dominance),
                    ));
                    if let Some(policy) = guard_policy(condition, content, &inputs) {
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
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn append_destructuring_records(
    path: &str,
    content: &[u8],
    pattern: Node<'_>,
    value: Node<'_>,
    function: Option<&FunctionInfo>,
    provenance: &ParserProvenance,
    aliases: &AliasMap,
    records: &mut Vec<ProgramRecord>,
) {
    let Some(base) = expression_name(value, content)
        .or_else(|| nested_call_expression(value).map(call_output_key))
    else {
        return;
    };
    let resolved_base = resolve_alias(&base, function, aliases);
    for index in 0..pattern.named_child_count() {
        let Some(item) = pattern.named_child(u32::try_from(index).unwrap_or(u32::MAX)) else {
            continue;
        };
        let key = item
            .child_by_field_name("key")
            .and_then(|child| expression_name(child, content))
            .or_else(|| expression_name(item, content));
        let output = item
            .child_by_field_name("value")
            .and_then(|child| expression_name(child, content))
            .or_else(|| expression_name(item, content));
        let (Some(key), Some(output)) = (key, output) else {
            continue;
        };
        let selected = format!("{base}.{key}");
        let resolved_selected = format!("{resolved_base}.{key}");
        let source = framework_member_source(function, &resolved_selected);
        records.push(record(
            if source.is_some() {
                "source"
            } else {
                "assignment"
            },
            source.map(crate::framework_sources::FrameworkSourceKind::record_name),
            function.map(|item| item.qualified_name.as_str()),
            if source.is_some() {
                Vec::new()
            } else {
                vec![selected]
            },
            Some(&output),
            None,
            location_for_node(path, content, item),
            provenance,
        ));
    }
}

fn nested_call_expression(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "call_expression" {
            return Some(node);
        }
        if !matches!(
            node.kind(),
            "parenthesized_expression" | "await_expression" | "as_expression"
        ) {
            return None;
        }
        node = node.named_child(0)?;
    }
}

#[allow(clippy::too_many_arguments)]
fn append_import_bindings(
    path: &str,
    content: &[u8],
    import: Node<'_>,
    module: &str,
    function: Option<&str>,
    provenance: &ParserProvenance,
    records: &mut Vec<ProgramRecord>,
) {
    let mut stack = vec![import];
    while let Some(node) = stack.pop() {
        if node.kind() == "import_specifier" {
            let imported = node
                .child_by_field_name("name")
                .and_then(|item| expression_name(item, content));
            let local = node
                .child_by_field_name("alias")
                .and_then(|item| expression_name(item, content))
                .or_else(|| imported.clone());
            if let (Some(imported), Some(local)) = (imported, local) {
                records.push(record(
                    "import-binding",
                    Some(&local),
                    function,
                    Vec::new(),
                    Some(&imported),
                    Some(module),
                    location_for_node(path, content, node),
                    provenance,
                ));
            }
            continue;
        }
        if node.kind() == "namespace_import"
            && let Some(local) = (0..node.named_child_count()).find_map(|index| {
                node.named_child(u32::try_from(index).unwrap_or(u32::MAX))
                    .and_then(|item| expression_name(item, content))
            })
        {
            records.push(record(
                "import-binding",
                Some(&local),
                function,
                Vec::new(),
                Some("*"),
                Some(module),
                location_for_node(path, content, node),
                provenance,
            ));
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
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
    if inputs.iter().any(|input| input.starts_with("@summary:")) {
        let mut seen_in_segment = BTreeSet::new();
        inputs.retain(|input| {
            if input.starts_with('@') {
                seen_in_segment.clear();
                true
            } else {
                seen_in_segment.insert(input.clone())
            }
        });
    } else if inputs.iter().any(|input| input.starts_with("@argument:")) {
        let mut seen_in_slot = BTreeSet::new();
        inputs.retain(|input| {
            if input.starts_with("@argument:") || input.starts_with("@property:") {
                seen_in_slot.clear();
                true
            } else {
                seen_in_slot.insert(input.clone())
            }
        });
    } else {
        let mut seen_inputs = BTreeSet::new();
        inputs.retain(|input| seen_inputs.insert(input.clone()));
    }
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
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
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
                .and_then(|name| unique_function(name, record, raw_functions, import_bindings))
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
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
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
                    source_node: node.clone(),
                    source_path: String::new(),
                    source_start: 0,
                    source_end: 0,
                    value_identity: String::new(),
                    field_sensitive: false,
                    sanitizers: BTreeSet::new(),
                    values: BTreeSet::new(),
                    source_specificity: 0,
                    interprocedural_depth: 0,
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
                .and_then(|callee| unique_function(callee, record, functions, import_bindings))
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
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
    guards: &BTreeMap<String, Vec<&ProgramRecord>>,
    records: &[&ProgramRecord],
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
    record_nodes: &BTreeMap<String, String>,
    builder: &mut GraphBuilder,
    max_interprocedural_depth: usize,
) {
    let Some(callee_function) = record
        .callee
        .as_ref()
        .and_then(|name| unique_function(name, record, functions, import_bindings))
    else {
        return;
    };
    let Some(arguments) = parameters.get(callee_function) else {
        return;
    };
    let origin_context = record.function.clone().unwrap_or_default();
    let slots = argument_slots(&record.inputs);
    for (fallback_index, parameter) in arguments.iter().enumerate() {
        let argument_index = parameter
            .inputs
            .iter()
            .find_map(|input| input.strip_prefix("@parameter:"))
            .and_then(|index| index.parse::<usize>().ok())
            .unwrap_or(fallback_index);
        let Some(slot) = slots.get(argument_index) else {
            continue;
        };
        let property_path = parameter
            .inputs
            .iter()
            .find_map(|input| input.strip_prefix("@property:"));
        let inputs =
            property_path.map_or_else(|| slot_values(slot), |path| property_values(slot, path));
        let Some(trace) = trace_for_inputs(taints, &origin_context, &inputs) else {
            continue;
        };
        if trace.interprocedural_depth >= max_interprocedural_depth {
            continue;
        }
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
        let via_call = extend_trace(&trace, record_node, call_edge);
        let parameter_edge = builder.edge(
            "argument-flow",
            record_node,
            parameter_node,
            &parameter.location,
            &parameter.provenance,
        );
        let mut parameter_trace = extend_trace(&via_call, parameter_node, parameter_edge);
        parameter_trace.interprocedural_depth =
            parameter_trace.interprocedural_depth.saturating_add(1);
        for guard in dominating_guard_records(record, guards) {
            let Some(policy) = guard.name.as_deref() else {
                continue;
            };
            let applies = if crate::semantics::is_operation_authorization(policy) {
                guard_is_authorization(guard, records)
                    && authorization_applies_to_trace(guard, &trace, taints)
            } else {
                guard_applies_to_trace(guard, &trace, taints)
            };
            if applies {
                parameter_trace.sanitizers.insert(policy.to_owned());
            }
        }
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
    if candidates
        .get(&key)
        .is_none_or(|existing| trace_is_preferred(&candidate.trace, &existing.trace))
    {
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

fn trace_for_inputs(
    taints: &BTreeMap<(String, String), Trace>,
    function: &str,
    inputs: &[String],
) -> Option<Trace> {
    let mut best = None::<Trace>;
    for input in inputs {
        let mut candidate = input.as_str();
        loop {
            if let Some(trace) = taints.get(&(function.to_owned(), candidate.to_owned())) {
                let mut derived = trace.clone();
                if derived.field_sensitive
                    && candidate != input
                    && let Some(suffix) = input.strip_prefix(candidate)
                {
                    let suffix = suffix.trim_start_matches('.');
                    if !suffix.is_empty() {
                        derived.value_identity = append_value_identity(
                            &derived.value_identity,
                            &suffix.replace('[', ".").replace(']', ""),
                        );
                    }
                }
                if best
                    .as_ref()
                    .is_none_or(|existing| trace_is_preferred(&derived, existing))
                {
                    best = Some(derived);
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

fn source_is_field_container(record: &ProgramRecord) -> bool {
    if matches!(
        record.name.as_deref(),
        Some("request-parameter" | "server-action-parameter")
    ) || record.callee.as_deref().is_some_and(source_container_call)
    {
        return true;
    }
    record.output.as_deref().is_some_and(|output| {
        matches!(
            terminal_identifier(&output.to_ascii_lowercase()),
            "body" | "query" | "params" | "headers" | "cookies" | "form"
        )
    })
}

fn source_container_call(callee: &str) -> bool {
    matches!(
        terminal_identifier(&callee.to_ascii_lowercase()),
        "json" | "formdata" | "cookies" | "headers"
    )
}

fn transparent_value_coercion(callee: &str) -> bool {
    matches!(
        terminal_identifier(&callee.to_ascii_lowercase()),
        "string" | "tostring" | "valueof"
    )
}

fn append_value_identity(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        suffix.to_owned()
    } else {
        format!("{prefix}.{suffix}")
    }
}

fn trace_for_transformation(
    taints: &BTreeMap<(String, String), Trace>,
    function: &str,
    record: &ProgramRecord,
    functions: &BTreeMap<String, Vec<String>>,
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
) -> Option<Trace> {
    if record
        .callee
        .as_deref()
        .and_then(|callee| unique_function(callee, record, functions, import_bindings))
        .is_some()
        && let Some(marker) = record
            .inputs
            .iter()
            .find(|input| input.starts_with("@call:"))
    {
        return taints.get(&(function.to_owned(), marker.clone())).cloned();
    }
    trace_for_inputs(taints, function, &record.inputs)
}

fn insert_trace(
    taints: &mut BTreeMap<(String, String), Trace>,
    key: (String, String),
    trace: Trace,
) {
    if taints
        .get(&key)
        .is_none_or(|existing| trace_is_preferred(&trace, existing))
    {
        taints.insert(key, trace);
    }
}

fn trace_is_preferred(candidate: &Trace, existing: &Trace) -> bool {
    if candidate.source_specificity != existing.source_specificity {
        return candidate.source_specificity > existing.source_specificity;
    }
    let candidate_source = (
        &candidate.source_path,
        candidate.source_start,
        candidate.source_end,
        &candidate.source_node,
    );
    let existing_source = (
        &existing.source_path,
        existing.source_start,
        existing.source_end,
        &existing.source_node,
    );
    if candidate_source != existing_source {
        return candidate_source < existing_source;
    }
    if candidate.value_identity != existing.value_identity {
        return candidate.value_identity < existing.value_identity;
    }
    let same_path = candidate.nodes == existing.nodes && candidate.edges == existing.edges;
    if same_path && candidate.sanitizers != existing.sanitizers {
        return candidate.sanitizers.is_superset(&existing.sanitizers);
    }
    if !same_path && candidate.sanitizers.len() != existing.sanitizers.len() {
        return candidate.sanitizers.len() < existing.sanitizers.len();
    }
    candidate < existing
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

fn authorization_summaries(
    records: &[&ProgramRecord],
    functions: &BTreeMap<String, Vec<String>>,
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
    maximum_depth: usize,
) -> Vec<AuthorizationSummary> {
    let mut summaries = BTreeSet::new();
    for _ in 0..maximum_depth.saturating_add(2) {
        let before = summaries.clone();
        for candidate in records
            .iter()
            .filter(|record| record.kind == "authorization-candidate")
        {
            let Some(function) = candidate.function.as_deref() else {
                continue;
            };
            let Some(mode) = summary_mode(candidate) else {
                continue;
            };
            let checked = candidate_segment(&candidate.inputs, None, Some("@accepted"));
            let accepted = candidate_segment(&candidate.inputs, Some("@accepted"), None);
            let trusted = checked.iter().find_map(|value| {
                trusted_principal_bindings(
                    function,
                    value,
                    candidate.location.span.end_byte,
                    records,
                    &summaries,
                    functions,
                    import_bindings,
                    parameters,
                    maximum_depth.saturating_add(2),
                )
            });
            let Some(mut bindings) = trusted else {
                continue;
            };
            if matches!(
                mode,
                AuthorizationSummaryMode::FilteredPrincipal | AuthorizationSummaryMode::Enforced
            ) {
                let Some(returned_bindings) = accepted.iter().find_map(|value| {
                    trusted_principal_bindings(
                        function,
                        value,
                        candidate.location.span.end_byte,
                        records,
                        &summaries,
                        functions,
                        import_bindings,
                        parameters,
                        maximum_depth.saturating_add(2),
                    )
                }) else {
                    continue;
                };
                bindings.extend(returned_bindings);
            }
            if mode == AuthorizationSummaryMode::Principal {
                bindings.extend(parameter_bindings_for_values(
                    function, &checked, parameters,
                ));
            }
            summaries.insert(AuthorizationSummary {
                function: function.to_owned(),
                policy: candidate.name.clone().unwrap_or_default(),
                mode,
                parameter_bindings: bindings,
            });
        }
        if summaries == before {
            break;
        }
    }
    summaries.into_iter().collect()
}

fn summary_mode(candidate: &ProgramRecord) -> Option<AuthorizationSummaryMode> {
    if candidate
        .inputs
        .iter()
        .any(|input| input == "@summary:principal")
    {
        Some(AuthorizationSummaryMode::Principal)
    } else if candidate
        .inputs
        .iter()
        .any(|input| input == "@summary:filtered")
    {
        Some(AuthorizationSummaryMode::FilteredPrincipal)
    } else if candidate
        .inputs
        .iter()
        .any(|input| input == "@summary:boolean")
    {
        Some(AuthorizationSummaryMode::Boolean)
    } else if candidate
        .inputs
        .iter()
        .any(|input| input == "@summary:enforced")
    {
        Some(AuthorizationSummaryMode::Enforced)
    } else {
        None
    }
}

fn candidate_segment(inputs: &[String], after: Option<&str>, before: Option<&str>) -> Vec<String> {
    let mut selected = after.is_none();
    let mut values = Vec::new();
    for input in inputs {
        if after == Some(input.as_str()) {
            selected = true;
            continue;
        }
        if before == Some(input.as_str()) {
            break;
        }
        if selected && (!input.starts_with('@') || input.starts_with("@call:")) {
            values.push(input.clone());
        }
    }
    values
}

#[allow(clippy::too_many_arguments)]
fn trusted_principal_bindings(
    function: &str,
    value: &str,
    before: u64,
    records: &[&ProgramRecord],
    summaries: &BTreeSet<AuthorizationSummary>,
    functions: &BTreeMap<String, Vec<String>>,
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
    depth: usize,
) -> Option<BTreeSet<usize>> {
    if depth == 0 || value.starts_with("@argument:") || value.starts_with("@property:") {
        return None;
    }
    let lookup = if value.starts_with("@call:") && !value.contains('.') {
        value
    } else {
        value.split(['.', '[']).next().unwrap_or(value)
    };
    let origin = records
        .iter()
        .filter(|record| {
            record.function.as_deref() == Some(function)
                && (record.location.span.end_byte <= before || lookup.starts_with("@call:"))
                && record.output.as_deref() == Some(lookup)
                && !matches!(
                    record.kind.as_str(),
                    "argument" | "source" | "authorization-candidate" | "control-gate"
                )
        })
        .max_by_key(|record| record.location.span.start_byte)?;
    if let Some(callee) = origin.callee.as_deref() {
        if let Some(target) = unique_function(callee, origin, functions, import_bindings) {
            if let Some(summary) = summaries.iter().find(|summary| {
                summary.function.as_str() == target
                    && matches!(
                        summary.mode,
                        AuthorizationSummaryMode::Principal
                            | AuthorizationSummaryMode::FilteredPrincipal
                            | AuthorizationSummaryMode::Enforced
                    )
            }) {
                return map_summary_bindings(summary, origin, function, records, parameters);
            }
            return None;
        }
        if trusted_external_principal_resolver(callee, origin, import_bindings) {
            return Some(parameter_bindings_for_values(
                function,
                &origin.inputs,
                parameters,
            ));
        }
    }
    origin.inputs.iter().find_map(|input| {
        trusted_principal_bindings(
            function,
            input,
            origin.location.span.start_byte,
            records,
            summaries,
            functions,
            import_bindings,
            parameters,
            depth.saturating_sub(1),
        )
    })
}

fn trusted_external_principal_resolver(
    callee: &str,
    record: &ProgramRecord,
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
) -> bool {
    let normalized = callee.to_ascii_lowercase().replace("::", ".");
    let recognized = matches!(
        normalized.as_str(),
        "identity.current" | "auth.api.getsession" | "auth.session.current" | "session.current"
    ) || normalized.ends_with(".auth.api.getsession");
    if !recognized {
        return false;
    }
    let leaf = terminal_identifier(&normalized);
    !import_bindings
        .get(&record.location.path)
        .into_iter()
        .flatten()
        .any(|binding| {
            binding.module.starts_with('.')
                && (binding.local.eq_ignore_ascii_case(leaf)
                    || binding.imported.eq_ignore_ascii_case(leaf))
        })
}

fn parameter_bindings_for_values(
    function: &str,
    values: &[String],
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
) -> BTreeSet<usize> {
    let Some(function_parameters) = parameters.get(function) else {
        return BTreeSet::new();
    };
    function_parameters
        .iter()
        .filter_map(|parameter| {
            let output = parameter.output.as_deref()?;
            values
                .iter()
                .any(|value| {
                    value == output
                        || value
                            .strip_prefix(output)
                            .is_some_and(|suffix| suffix == ".headers" || suffix == "[headers]")
                })
                .then(|| parameter_index(parameter))
                .flatten()
        })
        .collect()
}

fn parameter_index(record: &ProgramRecord) -> Option<usize> {
    record
        .inputs
        .iter()
        .find_map(|input| input.strip_prefix("@parameter:"))
        .and_then(|index| index.parse().ok())
}

fn map_summary_bindings(
    summary: &AuthorizationSummary,
    origin: &ProgramRecord,
    function: &str,
    records: &[&ProgramRecord],
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
) -> Option<BTreeSet<usize>> {
    if summary.parameter_bindings.is_empty() {
        return Some(BTreeSet::new());
    }
    let call = matching_call_record(origin, records).unwrap_or(origin);
    let slots = argument_slots(&call.inputs);
    let mut mapped = BTreeSet::new();
    for binding in &summary.parameter_bindings {
        let values = slots
            .get(*binding)
            .map_or_else(Vec::new, |slot| slot_values(slot));
        let current = parameter_bindings_for_values(function, &values, parameters);
        if current.is_empty() {
            return None;
        }
        mapped.extend(current);
    }
    Some(mapped)
}

fn matching_call_record<'a>(
    origin: &ProgramRecord,
    records: &'a [&ProgramRecord],
) -> Option<&'a ProgramRecord> {
    records
        .iter()
        .copied()
        .filter(|record| {
            record.function == origin.function
                && record.callee == origin.callee
                && matches!(record.kind.as_str(), "call" | "guard")
                && record.location.span.start_byte >= origin.location.span.start_byte
                && record.location.span.end_byte <= origin.location.span.end_byte
        })
        .max_by_key(|record| record.location.span.start_byte)
}

fn summary_authorization_guards(
    records: &[&ProgramRecord],
    summaries: &[AuthorizationSummary],
    functions: &BTreeMap<String, Vec<String>>,
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
) -> Vec<ProgramRecord> {
    let summary_set = summaries.iter().cloned().collect::<BTreeSet<_>>();
    let mut guards = direct_structural_authorization_guards(
        records,
        &summary_set,
        functions,
        import_bindings,
        parameters,
    );
    guards.extend(summarized_call_authorization_guards(
        records,
        summaries,
        functions,
        import_bindings,
        parameters,
    ));
    guards.sort();
    guards.dedup_by(|left, right| {
        left.record_id == right.record_id
            && left.name == right.name
            && left.function == right.function
    });
    guards
}

fn direct_structural_authorization_guards(
    records: &[&ProgramRecord],
    summaries: &BTreeSet<AuthorizationSummary>,
    functions: &BTreeMap<String, Vec<String>>,
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
) -> Vec<ProgramRecord> {
    let mut guards = Vec::new();
    for candidate in records
        .iter()
        .filter(|record| record.kind == "authorization-candidate")
    {
        if candidate
            .inputs
            .iter()
            .any(|input| input == "@summary:identity-gate")
        {
            if identity_candidate_is_trusted(
                candidate,
                records,
                summaries,
                functions,
                import_bindings,
                parameters,
            ) {
                guards.push(synthetic_guard(candidate));
            }
        } else if candidate
            .inputs
            .iter()
            .any(|input| input == "@summary:gate")
            && candidate
                .name
                .as_deref()
                .is_some_and(crate::semantics::is_operation_authorization)
            && candidate_segment(&candidate.inputs, None, None)
                .iter()
                .any(|value| {
                    candidate.function.as_deref().is_some_and(|function| {
                        trusted_principal_bindings(
                            function,
                            value,
                            candidate.location.span.end_byte,
                            records,
                            summaries,
                            functions,
                            import_bindings,
                            parameters,
                            10,
                        )
                        .is_some()
                    })
                })
        {
            guards.push(synthetic_guard(candidate));
        }
    }
    guards
}

fn summarized_call_authorization_guards(
    records: &[&ProgramRecord],
    summaries: &[AuthorizationSummary],
    functions: &BTreeMap<String, Vec<String>>,
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
) -> Vec<ProgramRecord> {
    let mut guards = Vec::new();
    for call in records
        .iter()
        .filter(|record| matches!(record.kind.as_str(), "call" | "guard"))
    {
        let Some(callee) = call.callee.as_deref() else {
            continue;
        };
        let Some(target) = unique_function(callee, call, functions, import_bindings) else {
            continue;
        };
        for summary in summaries.iter().filter(|summary| {
            summary.function.as_str() == target
                && crate::semantics::is_operation_authorization(&summary.policy)
        }) {
            if !call_satisfies_summary_bindings(call, summary, parameters, records) {
                continue;
            }
            if summary.mode == AuthorizationSummaryMode::Enforced
                && call.dominance_start.is_some()
                && call.dominance_end.is_some()
            {
                let mut guard = synthetic_guard(call);
                guard.name = Some(summary.policy.clone());
                guards.push(guard);
                continue;
            }
            if !matches!(
                summary.mode,
                AuthorizationSummaryMode::Boolean | AuthorizationSummaryMode::FilteredPrincipal
            ) {
                continue;
            }
            for gate in records.iter().filter(|record| {
                record.kind == "control-gate"
                    && record.function == call.function
                    && record.location.span.start_byte >= call.location.span.end_byte
                    && record.dominance_start.is_some()
                    && record.dominance_end.is_some()
            }) {
                if gate.inputs.iter().any(|value| {
                    value_originates_from_call(
                        call,
                        value,
                        gate.location.span.start_byte,
                        records,
                        10,
                    )
                }) {
                    let mut guard = synthetic_guard(gate);
                    guard.name = Some(summary.policy.clone());
                    guards.push(guard);
                }
            }
        }
    }
    guards
}

fn synthetic_guard(record: &ProgramRecord) -> ProgramRecord {
    let mut guard = record.clone();
    guard.kind = "guard".into();
    guard.callee = Some("@structural-authorization-proof".into());
    guard
}

fn call_satisfies_summary_bindings(
    call: &ProgramRecord,
    summary: &AuthorizationSummary,
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
    records: &[&ProgramRecord],
) -> bool {
    if summary.parameter_bindings.is_empty() {
        return true;
    }
    let Some(function) = call.function.as_deref() else {
        return false;
    };
    let slots = argument_slots(&call.inputs);
    summary.parameter_bindings.iter().all(|binding| {
        slots.get(*binding).is_some_and(|slot| {
            let values = slot_values(slot);
            !parameter_bindings_for_values(function, &values, parameters).is_empty()
                || values.iter().any(|value| {
                    trusted_request_context(
                        function,
                        value,
                        call.location.span.start_byte,
                        records,
                        8,
                    )
                })
        })
    })
}

fn trusted_request_context(
    function: &str,
    value: &str,
    before: u64,
    records: &[&ProgramRecord],
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let lookup = if value.starts_with("@call:") && !value.contains('.') {
        value
    } else {
        value.split(['.', '[']).next().unwrap_or(value)
    };
    let Some(origin) = records
        .iter()
        .filter(|record| {
            record.function.as_deref() == Some(function)
                && record.location.span.end_byte <= before
                && record.output.as_deref() == Some(lookup)
        })
        .max_by_key(|record| record.location.span.start_byte)
    else {
        return false;
    };
    if origin
        .callee
        .as_deref()
        .is_some_and(|callee| terminal_identifier(&callee.to_ascii_lowercase()) == "headers")
    {
        return true;
    }
    origin.inputs.iter().any(|input| {
        trusted_request_context(
            function,
            input,
            origin.location.span.start_byte,
            records,
            depth.saturating_sub(1),
        )
    })
}

fn value_originates_from_call(
    call: &ProgramRecord,
    value: &str,
    before: u64,
    records: &[&ProgramRecord],
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    if call.output.as_deref() == Some(value) {
        return true;
    }
    let lookup = if value.starts_with("@call:") {
        value
    } else {
        value.split(['.', '[']).next().unwrap_or(value)
    };
    let Some(origin) = records
        .iter()
        .filter(|record| {
            record.function == call.function
                && record.location.span.end_byte <= before
                && record.output.as_deref() == Some(lookup)
                && !matches!(record.kind.as_str(), "argument" | "source")
        })
        .max_by_key(|record| record.location.span.start_byte)
    else {
        return false;
    };
    if origin.record_id == call.record_id {
        return true;
    }
    origin.inputs.iter().any(|input| {
        value_originates_from_call(
            call,
            input,
            origin.location.span.start_byte,
            records,
            depth.saturating_sub(1),
        )
    })
}

fn identity_candidate_is_trusted(
    candidate: &ProgramRecord,
    records: &[&ProgramRecord],
    summaries: &BTreeSet<AuthorizationSummary>,
    functions: &BTreeMap<String, Vec<String>>,
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
) -> bool {
    let Some(function) = candidate.function.as_deref() else {
        return false;
    };
    let left = candidate_segment(&candidate.inputs, Some("@left"), Some("@right"));
    let right = candidate_segment(&candidate.inputs, Some("@right"), None);
    let left_principal = left.iter().any(|value| {
        trusted_principal_bindings(
            function,
            value,
            candidate.location.span.end_byte,
            records,
            summaries,
            functions,
            import_bindings,
            parameters,
            10,
        )
        .is_some()
    });
    let right_principal = right.iter().any(|value| {
        trusted_principal_bindings(
            function,
            value,
            candidate.location.span.end_byte,
            records,
            summaries,
            functions,
            import_bindings,
            parameters,
            10,
        )
        .is_some()
    });
    (left_principal
        && right.iter().any(|value| {
            trusted_server_identity(
                function,
                value,
                candidate.location.span.end_byte,
                records,
                parameters,
                8,
            )
        }))
        || (right_principal
            && left.iter().any(|value| {
                trusted_server_identity(
                    function,
                    value,
                    candidate.location.span.end_byte,
                    records,
                    parameters,
                    8,
                )
            }))
}

fn trusted_server_identity(
    function: &str,
    value: &str,
    before: u64,
    records: &[&ProgramRecord],
    parameters: &BTreeMap<String, Vec<&ProgramRecord>>,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let lookup = value.split(['.', '[']).next().unwrap_or(value);
    let Some(origin) = records
        .iter()
        .filter(|record| {
            record.function.as_deref() == Some(function)
                && record.location.span.end_byte <= before
                && record.output.as_deref() == Some(lookup)
                && !matches!(record.kind.as_str(), "argument" | "source")
        })
        .max_by_key(|record| record.location.span.start_byte)
    else {
        return false;
    };
    if origin
        .callee
        .as_deref()
        .is_some_and(is_trusted_identity_selection)
        && parameter_bindings_for_values(function, &origin.inputs, parameters).is_empty()
    {
        return true;
    }
    origin.inputs.iter().any(|input| {
        trusted_server_identity(
            function,
            input,
            origin.location.span.start_byte,
            records,
            parameters,
            depth.saturating_sub(1),
        )
    })
}

fn is_trusted_identity_selection(callee: &str) -> bool {
    matches!(
        terminal_identifier(&callee.to_ascii_lowercase()),
        "findfirst" | "first" | "findone"
    )
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
    records: &[&ProgramRecord],
    taints: &BTreeMap<(String, String), Trace>,
    sink: &ProgramRecord,
) -> bool {
    let Some(policy) = required_sanitizer_policy(rule_id) else {
        return false;
    };
    if trace.sanitizers.contains(policy)
        || trace
            .sanitizers
            .contains(crate::semantics::POLICY_EXACT_ALLOWLIST)
    {
        return true;
    }
    guards.iter().any(|guard| {
        guard
            .name
            .as_deref()
            .is_some_and(|name| name == policy || name == crate::semantics::POLICY_EXACT_ALLOWLIST)
            && guard_applies_to_trace(guard, trace, taints)
            && (rule_id != "SE1003"
                || filesystem_guard_proves_values(
                    guard,
                    &sensitive_sink_inputs(sink),
                    sink,
                    trace,
                    records,
                    taints,
                ))
    })
}

fn guard_is_authorization(guard: &ProgramRecord, records: &[&ProgramRecord]) -> bool {
    if guard
        .inputs
        .iter()
        .any(|input| input == "@conditional-conjunction")
    {
        return false;
    }
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

fn filesystem_guard_proves_values(
    guard: &ProgramRecord,
    target_values: &[String],
    target: &ProgramRecord,
    trace: &Trace,
    records: &[&ProgramRecord],
    taints: &BTreeMap<(String, String), Trace>,
) -> bool {
    let candidate = guard
        .inputs
        .iter()
        .find_map(|input| input.strip_prefix("@filesystem-candidate:"));
    let has_structural_proof = guard
        .inputs
        .iter()
        .any(|input| input.starts_with("@filesystem-proof:"));
    let (Some(candidate), true) = (candidate, has_structural_proof) else {
        return false;
    };
    if guard.function != target.function
        || !guard_applies_to_trace(guard, trace, taints)
        || value_reassigned_between(
            candidate,
            guard.location.span.end_byte,
            target.location.span.start_byte,
            guard.function.as_deref(),
            records,
        )
    {
        return false;
    }
    target_values.iter().any(|value| {
        current_value_derives_from(
            value,
            candidate,
            target.location.span.start_byte,
            guard.function.as_deref(),
            records,
            8,
        )
    })
}

fn current_value_derives_from(
    value: &str,
    expected: &str,
    before: u64,
    function: Option<&str>,
    records: &[&ProgramRecord],
    depth: usize,
) -> bool {
    if value == expected {
        return true;
    }
    if depth == 0 || value.starts_with('@') {
        return false;
    }
    records
        .iter()
        .copied()
        .filter(|record| {
            record.function.as_deref() == function
                && record.location.span.end_byte <= before
                && record.output.as_deref() == Some(value)
                && matches!(record.kind.as_str(), "assignment" | "alias")
                && record.callee.is_none()
        })
        .max_by_key(|record| record.location.span.end_byte)
        .and_then(|record| {
            let inputs = record
                .inputs
                .iter()
                .filter(|input| !input.starts_with('@'))
                .collect::<Vec<_>>();
            (inputs.len() == 1).then(|| inputs[0])
        })
        .is_some_and(|input| {
            current_value_derives_from(
                input,
                expected,
                before,
                function,
                records,
                depth.saturating_sub(1),
            )
        })
}

fn value_reassigned_between(
    value: &str,
    after: u64,
    before: u64,
    function: Option<&str>,
    records: &[&ProgramRecord],
) -> bool {
    records.iter().any(|record| {
        record.function.as_deref() == function
            && record.output.as_deref() == Some(value)
            && record.location.span.start_byte >= after
            && record.location.span.end_byte <= before
            && matches!(
                record.kind.as_str(),
                "assignment" | "alias" | "transformation" | "sanitizer"
            )
    })
}

fn guard_applies_to_trace(
    guard: &ProgramRecord,
    trace: &Trace,
    taints: &BTreeMap<(String, String), Trace>,
) -> bool {
    let function = guard.function.as_deref().unwrap_or_default();
    guard.inputs.iter().any(|input| {
        trace_for_inputs(taints, function, std::slice::from_ref(input)).is_some_and(|guard_trace| {
            guard_trace.source_node == trace.source_node
                && guard_trace.value_identity == trace.value_identity
        })
    })
}

fn authorization_applies_to_trace(
    guard: &ProgramRecord,
    trace: &Trace,
    taints: &BTreeMap<(String, String), Trace>,
) -> bool {
    guard.name.as_deref().is_some_and(|policy| {
        crate::semantics::authorization_kind(policy) == Some(crate::AuthorizationKind::Role)
            || policy == IDENTITY_POLICY
    }) || guard_applies_to_trace(guard, trace, taints)
}

fn resource_authorization_applies_to_sink(
    guard: &ProgramRecord,
    sink: &ProgramRecord,
    records: &[&ProgramRecord],
) -> bool {
    if sink.name.as_deref() != Some("sensitive-mutation")
        || guard
            .inputs
            .iter()
            .any(|input| input == "@conditional-conjunction")
        || !guard
            .name
            .as_deref()
            .is_some_and(crate::semantics::is_operation_authorization)
    {
        return false;
    }
    let sink_values = sensitive_sink_inputs(sink);
    if sink_values.is_empty() {
        return false;
    }
    records.iter().copied().any(|call| {
        call.function == guard.function
            && call.callee.is_some()
            && call.location.path == guard.location.path
            && call.location.span.start_byte >= guard.location.span.start_byte
            && call.location.span.end_byte <= guard.location.span.end_byte
            && resource_authorization_call_binds_sink(call, sink, &sink_values, records)
    })
}

fn resource_authorization_call_binds_sink(
    call: &ProgramRecord,
    sink: &ProgramRecord,
    sink_values: &[String],
    records: &[&ProgramRecord],
) -> bool {
    let slots = argument_slots(&call.inputs);
    if slots.len() < 3 || !slots.iter().any(Vec::is_empty) {
        return false;
    }
    let meaningful = slots
        .iter()
        .map(|slot| slot_values(slot))
        .collect::<Vec<_>>();
    let resource_slots = meaningful
        .iter()
        .enumerate()
        .filter(|(_, slot)| {
            slot.iter().any(|candidate| {
                sink_values.iter().any(|sink_value| {
                    local_values_share_identity(
                        candidate,
                        sink_value,
                        sink.location.span.start_byte,
                        records,
                    )
                })
            })
        })
        .map(|(index, _)| index)
        .collect::<BTreeSet<_>>();
    !resource_slots.is_empty()
        && meaningful.iter().enumerate().any(|(index, slot)| {
            !resource_slots.contains(&index)
                && slot.iter().any(|value| {
                    !value.starts_with('@')
                        && !call.callee.as_deref().is_some_and(|callee| {
                            values_correspond(value, callee)
                                || values_correspond(value, terminal_identifier(callee))
                        })
                })
        })
}

fn local_values_share_identity(
    left: &str,
    right: &str,
    before: u64,
    records: &[&ProgramRecord],
) -> bool {
    if left == right {
        return true;
    }
    let aliases = |start: &str| {
        let mut values = BTreeSet::from([start.to_owned()]);
        for _ in 0..8 {
            let previous = values.clone();
            for record in records.iter().copied().filter(|record| {
                record.location.span.end_byte <= before
                    && matches!(record.kind.as_str(), "assignment" | "alias")
                    && record.callee.is_none()
            }) {
                let Some(output) = record.output.as_deref() else {
                    continue;
                };
                let inputs = record
                    .inputs
                    .iter()
                    .filter(|input| !input.starts_with('@'))
                    .collect::<Vec<_>>();
                if inputs.len() != 1 {
                    continue;
                }
                let input = inputs[0];
                if previous.contains(output) {
                    values.insert(input.clone());
                }
                if previous.contains(input) {
                    values.insert(output.to_owned());
                }
            }
            if values == previous {
                break;
            }
        }
        values
    };
    !aliases(left).is_disjoint(&aliases(right))
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

fn extended_round_candidate_allowed(
    rule_id: &str,
    pass: usize,
    legacy_passes: usize,
    already_present: bool,
) -> bool {
    pass < legacy_passes || already_present || rule_id != "SE1005"
}

fn unique_function<'a>(
    call_target: &str,
    call_record: &ProgramRecord,
    functions: &'a BTreeMap<String, Vec<String>>,
    import_bindings: &BTreeMap<String, Vec<ImportBinding>>,
) -> Option<&'a String> {
    let leaf = call_target
        .rsplit(['.', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(call_target);
    let matches = functions.get(&function_resolution_key(leaf, &call_record.provenance))?;
    let same_file = matches
        .iter()
        .filter(|qualified| qualified_function_path(qualified) == Some(&call_record.location.path))
        .collect::<Vec<_>>();
    if same_file.len() == 1 {
        return Some(same_file[0]);
    }
    if call_record
        .provenance
        .grammar
        .contains("tree-sitter-javascript")
        || call_record
            .provenance
            .grammar
            .contains("tree-sitter-typescript")
    {
        let bindings = import_bindings.get(&call_record.location.path)?;
        let member_object = call_target.rsplit_once('.').map(|(object, _)| object);
        let modules = bindings
            .iter()
            .filter(|binding| {
                (binding.imported == leaf && member_object.is_none())
                    || (binding.imported == "*" && member_object == Some(binding.local.as_str()))
            })
            .map(|binding| binding.module.as_str())
            .collect::<BTreeSet<_>>();
        let imported = matches
            .iter()
            .filter(|qualified| {
                qualified_function_path(qualified).is_some_and(|candidate| {
                    modules.iter().any(|module| {
                        module_resolves_to(&call_record.location.path, module, candidate)
                    })
                })
            })
            .collect::<Vec<_>>();
        return (imported.len() == 1).then(|| imported[0]);
    }
    (matches.len() == 1).then(|| &matches[0])
}

fn qualified_function_path(qualified: &str) -> Option<&str> {
    qualified.rsplit_once("::").map(|(path, _)| path)
}

fn module_resolves_to(caller: &str, module: &str, candidate: &str) -> bool {
    if !module.starts_with('.') {
        return aliased_module_resolves_to(module, candidate);
    }
    let parent = Path::new(caller).parent().unwrap_or_else(|| Path::new(""));
    let Some(normalized) = lexical_path(&parent.join(module)) else {
        return false;
    };
    let candidate = strip_source_extension(candidate);
    let normalized = strip_source_extension(&normalized);
    candidate == normalized || candidate == format!("{normalized}/index")
}

fn aliased_module_resolves_to(module: &str, candidate: &str) -> bool {
    let Some(suffix) = module
        .strip_prefix("@/")
        .or_else(|| module.strip_prefix("~/"))
        .map(strip_source_extension)
    else {
        return false;
    };
    if suffix.is_empty() || suffix.split('/').any(|component| component == "..") {
        return false;
    }
    let candidate = strip_source_extension(candidate);
    candidate == suffix
        || candidate.ends_with(&format!("/{suffix}"))
        || candidate.ends_with(&format!("/{suffix}/index"))
}

fn lexical_path(path: &Path) -> Option<String> {
    let mut components = Vec::<String>::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            Component::ParentDir => {
                components.pop()?;
            }
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(components.join("/"))
}

fn strip_source_extension(path: &str) -> String {
    [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]
        .iter()
        .find_map(|extension| path.strip_suffix(extension).map(str::to_owned))
        .unwrap_or_else(|| path.to_owned())
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
    if leaf == "function" {
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

fn fixed_executable_without_shell(call: Node<'_>, content: &[u8], callee: &str) -> bool {
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
    let fixed = matches!(executable.kind(), "string" | "string_fragment");
    let array = matches!(argument_array.kind(), "array" | "array_expression");
    if !fixed || !array {
        return false;
    }
    let Some(options) = arguments.named_child(2) else {
        // Node's execFile/spawn APIs do not invoke a shell unless explicitly requested.
        return true;
    };
    object_property_is_absent_or_false(options, content, "shell")
}

fn object_property_is_absent_or_false(object: Node<'_>, content: &[u8], property: &str) -> bool {
    if !matches!(object.kind(), "object" | "object_expression") {
        return false;
    }
    (0..object.named_child_count()).all(|index| {
        let Some(pair) = object.named_child(u32::try_from(index).unwrap_or(u32::MAX)) else {
            return false;
        };
        let Some(key) = pair.child_by_field_name("key") else {
            return false;
        };
        let Some(value) = pair.child_by_field_name("value") else {
            return false;
        };
        if !matches!(key.kind(), "property_identifier" | "string") {
            return false;
        }
        let key_text = key
            .utf8_text(content)
            .unwrap_or_default()
            .trim_matches(['\'', '"']);
        if key_text != property {
            return true;
        }
        value.utf8_text(content).unwrap_or_default().trim() == "false"
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
    let membership = condition_has_fixed_allowlist(condition, content);
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
    if !membership || unsafe_shape {
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
    if !unsafe_destination_check
        && (condition_has_fixed_allowlist(condition, content)
            || condition_has_single_literal_allowlist(condition, content))
    {
        return Some(crate::semantics::POLICY_EXACT_ALLOWLIST);
    }
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

const AUTHENTICATION_POLICY: &str = "authentication-before-sensitive-operation";
const ROLE_POLICY: &str = "role-authorization-before-sensitive-operation";
const PERMISSION_POLICY: &str = "permission-authorization-before-sensitive-operation";
const OWNERSHIP_POLICY: &str = "ownership-authorization-before-sensitive-operation";
const TENANT_POLICY: &str = "tenant-authorization-before-sensitive-operation";
const IDENTITY_POLICY: &str = "identity-authorization-before-sensitive-operation";

fn append_authorization_candidates(
    path: &str,
    content: &[u8],
    root: Node<'_>,
    functions: &[FunctionInfo],
    provenance: &ParserProvenance,
    records: &mut Vec<ProgramRecord>,
    maximum: usize,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if records.len() >= maximum {
            return;
        }
        let function = containing_function(node, functions);
        if let Some(function) = function {
            if node.kind() == "return_statement"
                && let Some(value) = node.named_child(0)
            {
                append_return_authorization_candidate(
                    path, content, value, function, provenance, records,
                );
            } else if node.kind() == "if_statement"
                && let Some(condition) = node.child_by_field_name("condition")
                && let Some(dominance) =
                    if_guard_dominance(node, condition, content, Some(function))
                && authorization_guard_survives_try_context(node, function, content)
            {
                if let Some(policy) = structural_policy(condition, content) {
                    let mut inputs = vec!["@summary:gate".into()];
                    inputs.extend(value_names(condition, content));
                    records.push(record_with_dominance(
                        "authorization-candidate",
                        Some(policy),
                        Some(&function.qualified_name),
                        inputs,
                        None,
                        None,
                        location_for_node(path, content, condition),
                        provenance,
                        Some(dominance),
                    ));
                    if let Some(returned) = following_simple_return(node, content, function) {
                        let failure = node.child_by_field_name("consequence");
                        let mode = if failure
                            .is_some_and(|branch| branch_returns_nullish(branch, content))
                        {
                            Some("@summary:filtered")
                        } else if failure.is_some_and(|branch| branch_fails_closed(branch, content))
                        {
                            Some("@summary:enforced")
                        } else {
                            None
                        };
                        if let Some(mode) = mode {
                            let mut inputs = vec![mode.into()];
                            inputs.extend(value_names(condition, content));
                            inputs.push("@accepted".into());
                            inputs.extend(value_names(returned, content));
                            records.push(record(
                                "authorization-candidate",
                                Some(policy),
                                Some(&function.qualified_name),
                                inputs,
                                Some("@return"),
                                None,
                                location_for_node(path, content, node),
                                provenance,
                            ));
                        }
                    }
                }
                if let Some((left, right)) = identity_comparison(condition, content) {
                    let mut inputs = vec!["@summary:identity-gate".into(), "@left".into()];
                    inputs.extend(value_names(left, content));
                    inputs.push("@right".into());
                    inputs.extend(value_names(right, content));
                    records.push(record_with_dominance(
                        "authorization-candidate",
                        Some(IDENTITY_POLICY),
                        Some(&function.qualified_name),
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
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
}

fn append_return_authorization_candidate(
    path: &str,
    content: &[u8],
    value: Node<'_>,
    function: &FunctionInfo,
    provenance: &ParserProvenance,
    records: &mut Vec<ProgramRecord>,
) {
    if !return_survives_try_context(value, function, content) {
        return;
    }
    let value = unwrap_expression(value);
    if matches!(
        value.kind(),
        "identifier" | "member_expression" | "subscript_expression" | "call_expression"
    ) {
        let mut inputs = vec!["@summary:principal".into()];
        inputs.extend(value_names(value, content));
        records.push(record(
            "authorization-candidate",
            Some(AUTHENTICATION_POLICY),
            Some(&function.qualified_name),
            inputs,
            Some("@return"),
            None,
            location_for_node(path, content, value),
            provenance,
        ));
    }
    if let Some(policy) = structural_policy(value, content) {
        let mut inputs = vec!["@summary:boolean".into()];
        inputs.extend(value_names(value, content));
        records.push(record(
            "authorization-candidate",
            Some(policy),
            Some(&function.qualified_name),
            inputs,
            Some("@return"),
            None,
            location_for_node(path, content, value),
            provenance,
        ));
    }
    if matches!(
        value.kind(),
        "ternary_expression" | "conditional_expression"
    ) && let (Some(condition), Some(consequence), Some(alternative)) = (
        value.child_by_field_name("condition"),
        value.child_by_field_name("consequence"),
        value.child_by_field_name("alternative"),
    ) && let Some(policy) = structural_policy(condition, content)
    {
        let accepted = if is_nullish(consequence, content) {
            Some(alternative)
        } else if is_nullish(alternative, content) {
            Some(consequence)
        } else {
            None
        };
        if let Some(accepted) = accepted.filter(|accepted| simple_principal_value(*accepted)) {
            let mut inputs = vec!["@summary:filtered".into()];
            inputs.extend(value_names(condition, content));
            inputs.push("@accepted".into());
            inputs.extend(value_names(accepted, content));
            records.push(record(
                "authorization-candidate",
                Some(policy),
                Some(&function.qualified_name),
                inputs,
                Some("@return"),
                None,
                location_for_node(path, content, value),
                provenance,
            ));
        }
    }
}

fn structural_policy(node: Node<'_>, content: &[u8]) -> Option<&'static str> {
    let node = unwrap_expression(node);
    if matches!(node.kind(), "binary_expression" | "logical_expression") {
        let operator = node
            .child_by_field_name("operator")
            .and_then(|operator| operator.utf8_text(content).ok())
            .unwrap_or_default();
        let left = node.child_by_field_name("left")?;
        let right = node.child_by_field_name("right")?;
        if matches!(operator, "&&" | "||") {
            let left_policy = structural_policy(left, content);
            let right_policy = structural_policy(right, content);
            if left_policy == right_policy {
                return left_policy;
            }
            if left_policy.is_none() && existence_check(left, content) {
                return right_policy;
            }
            if right_policy.is_none() && existence_check(right, content) {
                return left_policy;
            }
            return None;
        }
        if matches!(operator, "==" | "===" | "!=" | "!==") {
            if is_boolean_true(right, content) {
                return structural_policy(left, content);
            }
            if is_boolean_true(left, content) {
                return structural_policy(right, content);
            }
            let dynamic = if is_fixed_policy_literal(left, content) {
                Some(right)
            } else if is_fixed_policy_literal(right, content) {
                Some(left)
            } else {
                None
            };
            if let Some(dynamic) = dynamic {
                return policy_for_expression(dynamic, content);
            }
        }
    }
    if node.kind() == "call_expression"
        && let Some(callee) = node
            .child_by_field_name("function")
            .and_then(|callee| expression_name(callee, content))
        && matches!(
            terminal_identifier(&callee.to_ascii_lowercase()),
            "includes" | "has"
        )
        && node
            .child_by_field_name("arguments")
            .and_then(|arguments| arguments.named_child(0))
            .is_some_and(|argument| is_fixed_policy_literal(argument, content))
    {
        return policy_for_expression(node.child_by_field_name("function")?, content);
    }
    None
}

fn existence_check(node: Node<'_>, content: &[u8]) -> bool {
    let text = node
        .utf8_text(content)
        .unwrap_or_default()
        .replace(char::is_whitespace, "");
    text.starts_with('!')
        || text.ends_with("==null")
        || text.ends_with("===null")
        || text.ends_with("==undefined")
        || text.ends_with("===undefined")
}

fn policy_for_expression(node: Node<'_>, content: &[u8]) -> Option<&'static str> {
    let lower = node.utf8_text(content).ok()?.to_ascii_lowercase();
    if lower.contains("permission") || lower.contains("scope") || lower.contains("capability") {
        Some(PERMISSION_POLICY)
    } else if lower.contains("role") {
        Some(ROLE_POLICY)
    } else if lower.contains("tenant")
        || lower.contains("organization")
        || lower.contains("workspace")
    {
        Some(TENANT_POLICY)
    } else if lower.contains("owner") || lower.contains("membership") || lower.contains("member") {
        Some(OWNERSHIP_POLICY)
    } else {
        None
    }
}

fn identity_comparison<'a>(node: Node<'a>, content: &[u8]) -> Option<(Node<'a>, Node<'a>)> {
    let node = unwrap_expression(node);
    if matches!(node.kind(), "binary_expression" | "logical_expression") {
        let operator = node
            .child_by_field_name("operator")
            .and_then(|operator| operator.utf8_text(content).ok())
            .unwrap_or_default();
        let left = node.child_by_field_name("left")?;
        let right = node.child_by_field_name("right")?;
        if matches!(operator, "==" | "===" | "!=" | "!==")
            && !is_fixed_policy_literal(left, content)
            && !is_fixed_policy_literal(right, content)
            && identity_expression(left, content)
            && identity_expression(right, content)
        {
            return Some((left, right));
        }
        return identity_comparison(left, content).or_else(|| identity_comparison(right, content));
    }
    None
}

fn identity_expression(node: Node<'_>, content: &[u8]) -> bool {
    expression_name(node, content).is_some_and(|name| {
        matches!(
            terminal_identifier(&name.to_ascii_lowercase()),
            "id" | "subject" | "sub" | "principalid" | "accountid" | "userid"
        )
    })
}

fn unwrap_expression(mut node: Node<'_>) -> Node<'_> {
    while matches!(
        node.kind(),
        "parenthesized_expression" | "await_expression" | "as_expression" | "satisfies_expression"
    ) {
        let Some(child) = node.named_child(0) else {
            break;
        };
        node = child;
    }
    node
}

fn is_fixed_policy_literal(node: Node<'_>, content: &[u8]) -> bool {
    is_fixed_string_literal(node, content) || is_boolean_true(node, content)
}

fn is_boolean_true(node: Node<'_>, content: &[u8]) -> bool {
    node.utf8_text(content)
        .is_ok_and(|text| text.trim() == "true")
}

fn is_nullish(node: Node<'_>, content: &[u8]) -> bool {
    node.utf8_text(content)
        .is_ok_and(|text| matches!(text.trim(), "null" | "undefined"))
}

fn simple_principal_value(node: Node<'_>) -> bool {
    matches!(
        unwrap_expression(node).kind(),
        "identifier" | "member_expression" | "subscript_expression"
    )
}

fn authorization_guard_survives_try_context(
    node: Node<'_>,
    function: &FunctionInfo,
    content: &[u8],
) -> bool {
    let root = syntax_root(node);
    let exits = node
        .child_by_field_name("consequence")
        .and_then(|branch| branch_exit_kinds(branch, content, root, &mut Vec::new(), true));
    try_context_preserves_exit(node, function, content, exits)
}

fn return_survives_try_context(node: Node<'_>, function: &FunctionInfo, content: &[u8]) -> bool {
    try_context_preserves_exit(node, function, content, Some(ExitKinds::returning()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExitKinds {
    returns: bool,
    throws: bool,
}

impl ExitKinds {
    const fn returning() -> Self {
        Self {
            returns: true,
            throws: false,
        }
    }

    const fn throwing() -> Self {
        Self {
            returns: false,
            throws: true,
        }
    }

    const fn union(self, other: Self) -> Self {
        Self {
            returns: self.returns || other.returns,
            throws: self.throws || other.throws,
        }
    }
}

fn try_context_preserves_exit(
    node: Node<'_>,
    function: &FunctionInfo,
    content: &[u8],
    exits: Option<ExitKinds>,
) -> bool {
    let Some(mut exits) = exits else {
        return false;
    };
    let root = syntax_root(node);
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.start_byte() <= usize::try_from(function.location.span.start_byte).unwrap_or(0)
            && ancestor.end_byte()
                >= usize::try_from(function.location.span.end_byte).unwrap_or(usize::MAX)
        {
            break;
        }
        if ancestor.kind() == "try_statement" {
            let Some(body) = ancestor.child_by_field_name("body") else {
                return false;
            };
            if !node_within(node, body) {
                return false;
            }
            if exits.throws
                && let Some(handler) = ancestor.child_by_field_name("handler")
            {
                let Some(handler_exits) = catch_handler_exit_kinds(handler, content, root) else {
                    return false;
                };
                exits = ExitKinds {
                    returns: exits.returns,
                    throws: false,
                }
                .union(handler_exits);
            }
            if ancestor
                .child_by_field_name("finalizer")
                .is_some_and(|finalizer| !finally_preserves_pending_exit(finalizer, content))
            {
                return false;
            }
        }
        current = ancestor.parent();
    }
    true
}

fn syntax_root(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
}

fn node_within(node: Node<'_>, container: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && container.end_byte() >= node.end_byte()
}

fn finally_preserves_pending_exit(finalizer: Node<'_>, content: &[u8]) -> bool {
    let mut stack = vec![finalizer];
    while let Some(node) = stack.pop() {
        if node != finalizer && is_function(node) {
            continue;
        }
        if matches!(
            node.kind(),
            "return_statement"
                | "throw_statement"
                | "break_statement"
                | "continue_statement"
                | "assignment_expression"
                | "augmented_assignment_expression"
                | "update_expression"
                | "call_expression"
                | "new_expression"
                | "await_expression"
                | "yield_expression"
                | "delete_expression"
                | "for_statement"
                | "for_in_statement"
                | "while_statement"
                | "do_statement"
        ) {
            return false;
        }
        if node.kind() == "unary_expression"
            && node
                .child_by_field_name("operator")
                .and_then(|operator| operator.utf8_text(content).ok())
                .is_some_and(|operator| operator.trim() == "delete")
        {
            return false;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    true
}

fn catch_handler_exit_kinds(
    handler: Node<'_>,
    content: &[u8],
    root: Node<'_>,
) -> Option<ExitKinds> {
    if contains_sensitive_mutation(handler, content) {
        return None;
    }
    branch_exit_kinds(handler, content, root, &mut Vec::new(), true)
}

fn contains_sensitive_mutation(node: Node<'_>, content: &[u8]) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current != node && is_function(current) {
            continue;
        }
        if current.kind() == "call_expression"
            && current
                .child_by_field_name("function")
                .and_then(|callee| expression_name(callee, content))
                .and_then(|callee| sink_kind(&callee))
                == Some("sensitive-mutation")
        {
            return true;
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    false
}

fn branch_exit_kinds(
    node: Node<'_>,
    content: &[u8],
    root: Node<'_>,
    resolving_helpers: &mut Vec<String>,
    return_exits_scope: bool,
) -> Option<ExitKinds> {
    match node.kind() {
        "return_statement" => return_exits_scope.then_some(ExitKinds::returning()),
        "throw_statement" => Some(ExitKinds::throwing()),
        "catch_clause" | "finally_clause" => node.child_by_field_name("body").and_then(|body| {
            branch_exit_kinds(body, content, root, resolving_helpers, return_exits_scope)
        }),
        "statement_block" => node
            .named_child_count()
            .checked_sub(1)
            .and_then(|index| node.named_child(u32::try_from(index).ok()?))
            .and_then(|last| {
                branch_exit_kinds(last, content, root, resolving_helpers, return_exits_scope)
            }),
        "if_statement" => {
            let consequence = node.child_by_field_name("consequence").and_then(|branch| {
                branch_exit_kinds(branch, content, root, resolving_helpers, return_exits_scope)
            })?;
            let alternative = node.child_by_field_name("alternative").and_then(|branch| {
                branch_exit_kinds(branch, content, root, resolving_helpers, return_exits_scope)
            })?;
            Some(consequence.union(alternative))
        }
        "expression_statement" => {
            let call = node.named_child(0).map(unwrap_expression)?;
            if call.kind() != "call_expression" {
                return None;
            }
            match local_terminating_helper(call, content, root, resolving_helpers) {
                LocalHelperResolution::Terminates => Some(ExitKinds::throwing()),
                LocalHelperResolution::NonTerminating => None,
                LocalHelperResolution::Absent => {
                    named_framework_terminator(call, content).then_some(ExitKinds::throwing())
                }
            }
        }
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalHelperResolution {
    Absent,
    NonTerminating,
    Terminates,
}

fn local_terminating_helper(
    call: Node<'_>,
    content: &[u8],
    root: Node<'_>,
    resolving_helpers: &mut Vec<String>,
) -> LocalHelperResolution {
    let Some(callee) = call
        .child_by_field_name("function")
        .and_then(|callee| expression_name(callee, content))
    else {
        return LocalHelperResolution::Absent;
    };
    if callee.contains('.') {
        return LocalHelperResolution::Absent;
    }

    let bodies = local_function_bodies(root, content, &callee);
    if bodies.is_empty() {
        return LocalHelperResolution::Absent;
    }
    if bodies.len() != 1
        || resolving_helpers.len() >= 8
        || resolving_helpers
            .iter()
            .any(|resolving| resolving == &callee)
    {
        return LocalHelperResolution::NonTerminating;
    }

    resolving_helpers.push(callee);
    let exits = branch_exit_kinds(bodies[0], content, root, resolving_helpers, false);
    resolving_helpers.pop();
    if exits == Some(ExitKinds::throwing()) {
        LocalHelperResolution::Terminates
    } else {
        LocalHelperResolution::NonTerminating
    }
}

fn local_function_bodies<'tree>(root: Node<'tree>, content: &[u8], name: &str) -> Vec<Node<'tree>> {
    let mut bodies = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "function_declaration" | "generator_function_declaration"
        ) && node
            .child_by_field_name("name")
            .and_then(|candidate| expression_name(candidate, content))
            .as_deref()
            == Some(name)
            && let Some(body) = node.child_by_field_name("body")
        {
            bodies.push(body);
        } else if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .and_then(|candidate| expression_name(candidate, content))
                .as_deref()
                == Some(name)
            && let Some(value) = node.child_by_field_name("value")
            && is_function(value)
            && let Some(body) = value.child_by_field_name("body")
        {
            bodies.push(body);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    bodies
}

fn named_framework_terminator(call: Node<'_>, content: &[u8]) -> bool {
    call.child_by_field_name("function")
        .and_then(|callee| expression_name(callee, content))
        .is_some_and(|callee| {
            matches!(
                terminal_identifier(&callee.to_ascii_lowercase()),
                "redirect" | "permanentredirect" | "notfound"
            )
        })
}

fn following_simple_return<'a>(
    statement: Node<'a>,
    content: &[u8],
    function: &FunctionInfo,
) -> Option<Node<'a>> {
    let function_node = function_ancestor(statement)?;
    let mut stack = vec![function_node.child_by_field_name("body")?];
    let mut selected = None;
    while let Some(node) = stack.pop() {
        if node.start_byte() > statement.end_byte()
            && node.end_byte()
                <= usize::try_from(function.location.span.end_byte).unwrap_or(usize::MAX)
            && node.kind() == "return_statement"
            && let Some(value) = node.named_child(0)
            && simple_principal_value(value)
            && !value.utf8_text(content).unwrap_or_default().contains("??")
        {
            selected = Some(value);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    selected
}

fn function_ancestor(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if is_function(parent) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn branch_returns_nullish(node: Node<'_>, content: &[u8]) -> bool {
    if node.kind() == "return_statement" {
        return node
            .named_child(0)
            .is_some_and(|value| is_nullish(value, content));
    }
    if node.kind() == "statement_block" {
        return node
            .named_child_count()
            .checked_sub(1)
            .and_then(|index| node.named_child(u32::try_from(index).ok()?))
            .is_some_and(|last| branch_returns_nullish(last, content));
    }
    false
}

fn branch_fails_closed(node: Node<'_>, content: &[u8]) -> bool {
    if matches!(node.kind(), "return_statement" | "throw_statement") {
        return true;
    }
    if node.kind() == "expression_statement"
        && let Some(call) = node.named_child(0).map(unwrap_expression)
        && call.kind() == "call_expression"
        && let Some(callee) = call
            .child_by_field_name("function")
            .and_then(|callee| expression_name(callee, content))
    {
        return matches!(
            terminal_identifier(&callee.to_ascii_lowercase()),
            "redirect" | "permanentredirect" | "notfound"
        );
    }
    if node.kind() == "statement_block" {
        return node
            .named_child_count()
            .checked_sub(1)
            .and_then(|index| node.named_child(u32::try_from(index).ok()?))
            .is_some_and(|last| branch_fails_closed(last, content));
    }
    if node.kind() == "if_statement" {
        return node
            .child_by_field_name("consequence")
            .is_some_and(|branch| branch_fails_closed(branch, content))
            && node
                .child_by_field_name("alternative")
                .is_some_and(|branch| branch_fails_closed(branch, content));
    }
    false
}

fn condition_has_single_literal_allowlist(condition: Node<'_>, content: &[u8]) -> bool {
    let mut stack = vec![condition];
    while let Some(node) = stack.pop() {
        if node.kind() == "binary_expression"
            && let Some(operator) = node
                .child_by_field_name("operator")
                .and_then(|item| item.utf8_text(content).ok())
            && matches!(operator, "==" | "===" | "!=" | "!==")
            && let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
            && (is_fixed_string_literal(left, content) ^ is_fixed_string_literal(right, content))
        {
            return true;
        }
        for index in 0..node.named_child_count() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    false
}

fn condition_has_fixed_allowlist(condition: Node<'_>, content: &[u8]) -> bool {
    let mut stack = vec![condition];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && matches!(
                function.kind(),
                "member_expression" | "subscript_expression"
            )
            && let Some(method) = function
                .child_by_field_name("property")
                .or_else(|| function.child_by_field_name("index"))
                .and_then(|item| {
                    expression_name(item, content).or_else(|| string_value(item, content))
                })
            && matches!(method.to_ascii_lowercase().as_str(), "has" | "includes")
            && let Some(collection) = function.child_by_field_name("object")
            && fixed_string_collection(collection, node.start_byte(), content)
        {
            return true;
        }
        for index in 0..node.named_child_count() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    false
}

fn fixed_string_collection(collection: Node<'_>, before: usize, content: &[u8]) -> bool {
    if collection_is_fixed_strings(collection, content) {
        return true;
    }
    let Some(name) = expression_name(collection, content) else {
        return false;
    };
    let mut root = collection;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before {
            continue;
        }
        if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .and_then(|item| expression_name(item, content))
                .as_deref()
                == Some(name.as_str())
            && node
                .child_by_field_name("value")
                .is_some_and(|value| collection_is_fixed_strings(value, content))
        {
            return !binding_mutated_between(root, &name, node.end_byte(), before, content);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    false
}

fn binding_mutated_between(
    root: Node<'_>,
    binding: &str,
    after: usize,
    before: usize,
    content: &[u8],
) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() < after || node.start_byte() >= before {
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                    stack.push(child);
                }
            }
            continue;
        }
        if node.kind() == "assignment_expression"
            && node
                .child_by_field_name("left")
                .and_then(|left| expression_name(left, content))
                .is_some_and(|left| values_correspond(&left, binding))
        {
            return true;
        }
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && let Some(object) = function.child_by_field_name("object")
            && expression_name(object, content).as_deref() == Some(binding)
            && function
                .child_by_field_name("property")
                .or_else(|| function.child_by_field_name("index"))
                .and_then(|property| {
                    expression_name(property, content).or_else(|| string_value(property, content))
                })
                .is_some_and(|method| {
                    matches!(
                        method.to_ascii_lowercase().as_str(),
                        "add"
                            | "clear"
                            | "delete"
                            | "pop"
                            | "push"
                            | "set"
                            | "shift"
                            | "splice"
                            | "unshift"
                    )
                })
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

fn collection_is_fixed_strings(node: Node<'_>, content: &[u8]) -> bool {
    let array = if matches!(node.kind(), "array" | "array_expression") {
        Some(node)
    } else if node.kind() == "new_expression"
        && node
            .child_by_field_name("constructor")
            .and_then(|item| expression_name(item, content))
            .is_some_and(|name| name.eq_ignore_ascii_case("set"))
    {
        node.child_by_field_name("arguments")
            .and_then(|arguments| arguments.named_child(0))
    } else {
        None
    };
    let Some(array) = array else {
        return false;
    };
    array.named_child_count() > 0
        && (0..array.named_child_count()).all(|index| {
            array
                .named_child(u32::try_from(index).unwrap_or(u32::MAX))
                .is_some_and(|value| is_fixed_string_literal(value, content))
        })
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
    if condition_rejects_invalid(condition_text) && branch_fails_closed(consequence, content) {
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

fn condition_contains_conjunction(condition: Node<'_>, content: &[u8]) -> bool {
    let mut stack = vec![condition];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "binary_expression" | "logical_expression")
            && node
                .child_by_field_name("operator")
                .and_then(|operator| operator.utf8_text(content).ok())
                == Some("&&")
        {
            return true;
        }
        let count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
        for index in 0..count {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

fn filesystem_confinement_markers(
    statement: Node<'_>,
    condition: Node<'_>,
    content: &[u8],
) -> Vec<String> {
    let Some((candidate, root)) = separator_aware_prefix_rejection(condition, content) else {
        return Vec::new();
    };
    if !trusted_filesystem_root(statement, &root, content) {
        return Vec::new();
    }
    let Some(proof) = composed_path_proof(statement, &candidate, &root, content) else {
        return Vec::new();
    };
    vec![
        format!("@filesystem-candidate:{candidate}"),
        format!("@filesystem-root:{root}"),
        format!("@filesystem-proof:{proof}"),
    ]
}

fn separator_aware_prefix_rejection(
    condition: Node<'_>,
    content: &[u8],
) -> Option<(String, String)> {
    let mut stack = vec![condition];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression"
            && call_is_negated_within(node, condition, content)
            && let Some(callee) = node.child_by_field_name("function")
            && callee.kind() == "member_expression"
            && callee
                .child_by_field_name("property")
                .and_then(|property| expression_name(property, content))
                .as_deref()
                == Some("startsWith")
            && let Some(candidate) = callee
                .child_by_field_name("object")
                .and_then(|object| expression_name(object, content))
            && !candidate.contains('[')
            && let Some(argument) = node
                .child_by_field_name("arguments")
                .and_then(|arguments| arguments.named_child(0))
            && let Some(root) = separator_boundary_root(condition, argument, content)
        {
            return Some((candidate, root));
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    None
}

fn call_is_negated_within(call: Node<'_>, boundary: Node<'_>, content: &[u8]) -> bool {
    let mut current = call.parent();
    while let Some(node) = current {
        if node.kind() == "unary_expression"
            && node
                .child_by_field_name("operator")
                .and_then(|operator| operator.utf8_text(content).ok())
                .is_some_and(|operator| operator.trim() == "!")
        {
            return true;
        }
        if node == boundary {
            break;
        }
        current = node.parent();
    }
    false
}

fn separator_boundary_root(
    anchor: Node<'_>,
    mut expression: Node<'_>,
    content: &[u8],
) -> Option<String> {
    while expression.kind() == "parenthesized_expression" {
        expression = expression.named_child(0)?;
    }
    if let Some(name) = expression_name(expression, content)
        && latest_bound_value(anchor, &name, anchor.start_byte(), content)
            .is_some_and(|value| separator_wrapped_expression(value, content).is_some())
    {
        return Some(name);
    }
    if expression.kind() != "binary_expression"
        || expression
            .child_by_field_name("operator")
            .and_then(|operator| operator.utf8_text(content).ok())
            .is_none_or(|operator| operator.trim() != "+")
    {
        return None;
    }
    let left = expression.child_by_field_name("left")?;
    let right = expression.child_by_field_name("right")?;
    if is_separator_value(right, content) {
        return expression_name(left, content);
    }
    if is_separator_value(left, content) {
        return expression_name(right, content);
    }
    None
}

fn separator_wrapped_expression<'tree>(
    mut expression: Node<'tree>,
    content: &[u8],
) -> Option<Node<'tree>> {
    while matches!(
        expression.kind(),
        "parenthesized_expression" | "await_expression"
    ) {
        expression = expression.named_child(0)?;
    }
    if expression.kind() != "binary_expression"
        || expression
            .child_by_field_name("operator")
            .and_then(|operator| operator.utf8_text(content).ok())
            .is_none_or(|operator| operator.trim() != "+")
    {
        return None;
    }
    let left = expression.child_by_field_name("left")?;
    let right = expression.child_by_field_name("right")?;
    if is_separator_value(right, content) {
        return Some(left);
    }
    is_separator_value(left, content).then_some(right)
}

fn is_separator_value(node: Node<'_>, content: &[u8]) -> bool {
    expression_name(node, content).is_some_and(|name| {
        let lower = name.to_ascii_lowercase();
        if lower == "path.sep" {
            return true;
        }
        lower == "sep" && imported_path_operation(node, &name, "sep", content)
    })
}

fn trusted_filesystem_root(anchor: Node<'_>, root: &str, content: &[u8]) -> bool {
    trusted_root_name(
        anchor,
        root,
        anchor.start_byte(),
        content,
        &mut BTreeSet::new(),
        8,
    )
}

fn trusted_root_name(
    anchor: Node<'_>,
    name: &str,
    before: usize,
    content: &[u8],
    visited: &mut BTreeSet<String>,
    depth: usize,
) -> bool {
    if depth == 0 || !visited.insert(name.to_owned()) {
        return false;
    }
    let result = latest_bound_value(anchor, name, before, content).is_some_and(|value| {
        trusted_root_expression(
            anchor,
            value,
            value.start_byte(),
            content,
            visited,
            depth.saturating_sub(1),
        )
    });
    visited.remove(name);
    result
}

fn trusted_root_expression(
    anchor: Node<'_>,
    mut expression: Node<'_>,
    before: usize,
    content: &[u8],
    visited: &mut BTreeSet<String>,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    while matches!(
        expression.kind(),
        "parenthesized_expression" | "await_expression"
    ) {
        let Some(child) = expression.named_child(0) else {
            return false;
        };
        expression = child;
    }
    if fixed_string(expression, content) {
        return true;
    }
    if let Some(base) = separator_wrapped_expression(expression, content) {
        return trusted_root_expression(
            anchor,
            base,
            before,
            content,
            visited,
            depth.saturating_sub(1),
        );
    }
    if expression.kind() == "identifier" {
        return expression_name(expression, content).is_some_and(|name| {
            trusted_root_name(
                anchor,
                &name,
                before,
                content,
                visited,
                depth.saturating_sub(1),
            )
        });
    }
    if matches!(expression.kind(), "member_expression")
        && expression_name(expression, content).is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            !is_untrusted_source(&lower)
                && ![
                    ".body",
                    ".query",
                    ".params",
                    ".headers",
                    ".cookies",
                    ".formdata",
                ]
                .iter()
                .any(|marker| lower.contains(marker))
        })
    {
        return true;
    }
    if expression.kind() != "call_expression"
        || known_path_operation(expression, content).is_none_or(|operation| {
            !matches!(
                operation,
                "realpath" | "canonicalize" | "resolve" | "normalize"
            )
        })
    {
        return false;
    }
    expression
        .child_by_field_name("arguments")
        .filter(|arguments| arguments.named_child_count() == 1)
        .and_then(|arguments| arguments.named_child(0))
        .is_some_and(|argument| {
            trusted_root_expression(
                anchor,
                argument,
                expression.start_byte(),
                content,
                visited,
                depth.saturating_sub(1),
            )
        })
}

fn composed_path_proof(
    anchor: Node<'_>,
    candidate: &str,
    root: &str,
    content: &[u8],
) -> Option<&'static str> {
    let mut value = latest_bound_value(anchor, candidate, anchor.start_byte(), content)?;
    while matches!(
        value.kind(),
        "parenthesized_expression" | "await_expression"
    ) {
        value = value.named_child(0)?;
    }
    known_path_operation(value, content)?;
    let mut stack = vec![value];
    let mut supported = false;
    let mut canonical = false;
    let mut root_present = false;
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited > 256 {
            return None;
        }
        if node.kind() == "call_expression"
            && let Some(operation) = known_path_operation(node, content)
        {
            supported = true;
            canonical |= matches!(operation, "realpath" | "canonicalize");
        }
        root_present |= expression_name(node, content).as_deref() == Some(root);
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    (supported && root_present).then_some(if canonical { "canonical" } else { "lexical" })
}

fn known_path_operation(call: Node<'_>, content: &[u8]) -> Option<&'static str> {
    let callee = call
        .child_by_field_name("function")
        .and_then(|function| expression_name(function, content))?;
    let lower = callee.to_ascii_lowercase();
    let leaf = terminal_identifier(&lower);
    let operation = match leaf {
        "join" => "join",
        "resolve" => "resolve",
        "normalize" => "normalize",
        "realpath" => "realpath",
        "canonicalize" => "canonicalize",
        _ => return None,
    };
    if let Some((object, _)) = lower.rsplit_once('.') {
        let expected_object = match operation {
            "join" | "resolve" | "normalize" => "path",
            "realpath" | "canonicalize" => "fs",
            _ => return None,
        };
        return (object == expected_object
            && conventional_module_object_is_unshadowed(call, expected_object, content))
        .then_some(operation);
    }
    imported_path_operation(call, &callee, operation, content).then_some(operation)
}

fn conventional_module_object_is_unshadowed(call: Node<'_>, object: &str, content: &[u8]) -> bool {
    if module_object_imported(call, object, content) {
        return true;
    }
    if non_variable_binding_shadows_name(call, object, content) {
        return false;
    }
    let call_scope = enclosing_function_span(call);
    let Some(root) = program_root(call) else {
        return false;
    };
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let scope = binding_scope(node);
        if (scope.is_none() || scope == call_scope)
            && node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .is_some_and(|binding| pattern_binds_name(binding, object, content))
        {
            return false;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    true
}

fn module_object_imported(call: Node<'_>, object: &str, content: &[u8]) -> bool {
    let Some(root) = program_root(call) else {
        return false;
    };
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let expected_module = node
            .child_by_field_name("source")
            .and_then(|source| string_value(source, content))
            .is_some_and(|module| {
                if object == "path" {
                    matches!(module.as_str(), "path" | "node:path")
                } else {
                    matches!(module.as_str(), "fs" | "node:fs" | "node:fs/promises")
                }
            });
        if node.kind() == "import_statement"
            && expected_module
            && (0..node.named_child_count()).any(|index| {
                node.named_child(u32::try_from(index).unwrap_or(u32::MAX))
                    .is_some_and(|child| pattern_binds_name(child, object, content))
            })
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

fn imported_path_operation(anchor: Node<'_>, local: &str, operation: &str, content: &[u8]) -> bool {
    let Some(root) = program_root(anchor) else {
        return false;
    };
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "import_statement"
            && node
                .child_by_field_name("source")
                .and_then(|source| string_value(source, content))
                .is_some_and(|module| match operation {
                    "join" | "resolve" | "normalize" | "sep" => {
                        matches!(module.as_str(), "path" | "node:path")
                    }
                    "realpath" | "canonicalize" => {
                        matches!(module.as_str(), "fs" | "node:fs" | "node:fs/promises")
                    }
                    _ => false,
                })
        {
            let mut imports = vec![node];
            while let Some(item) = imports.pop() {
                if item.kind() == "import_specifier" {
                    let imported = item
                        .child_by_field_name("name")
                        .and_then(|name| expression_name(name, content));
                    let bound = item
                        .child_by_field_name("alias")
                        .and_then(|alias| expression_name(alias, content))
                        .or_else(|| imported.clone());
                    if imported.as_deref() == Some(operation) && bound.as_deref() == Some(local) {
                        return true;
                    }
                }
                for index in (0..item.named_child_count()).rev() {
                    if let Some(child) = item.named_child(u32::try_from(index).unwrap_or(u32::MAX))
                    {
                        imports.push(child);
                    }
                }
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    false
}

fn latest_bound_value<'tree>(
    anchor: Node<'tree>,
    name: &str,
    before: usize,
    content: &[u8],
) -> Option<Node<'tree>> {
    let root = program_root(anchor)?;
    let context_scope = enclosing_function_span(anchor);
    let mut local = Vec::<(usize, Node<'tree>)>::new();
    let mut global = Vec::<(usize, Node<'tree>)>::new();
    let mut stack = vec![root];
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited > 4096 {
            return None;
        }
        let value = if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .and_then(|binding| expression_name(binding, content))
                .as_deref()
                == Some(name)
        {
            node.child_by_field_name("value")
        } else if matches!(
            node.kind(),
            "assignment_expression" | "augmented_assignment_expression"
        ) && node
            .child_by_field_name("left")
            .and_then(|binding| expression_name(binding, content))
            .as_deref()
            == Some(name)
        {
            node.child_by_field_name("right")
        } else {
            None
        };
        if let Some(value) = value
            && node.end_byte() <= before
        {
            match binding_scope(node) {
                scope if scope == context_scope => local.push((node.end_byte(), value)),
                None => global.push((node.end_byte(), value)),
                _ => {}
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    let candidates = if local.is_empty() {
        &mut global
    } else {
        &mut local
    };
    candidates.sort_by_key(|(end, _)| *end);
    candidates.last().map(|(_, value)| *value)
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

fn framework_member_source(
    function: Option<&FunctionInfo>,
    name: &str,
) -> Option<crate::framework_sources::FrameworkSourceKind> {
    let function = function?;
    let parameters = function
        .parameters
        .iter()
        .map(|parameter| parameter.name.clone())
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
        .map(|parameter| parameter.name.clone())
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

fn parameter_names(path: &str, content: &[u8], parameters: Node<'_>) -> Vec<ParameterInfo> {
    let mut result = Vec::new();
    let count = u32::try_from(parameters.named_child_count()).unwrap_or(u32::MAX);
    for argument_index in 0..count {
        let Some(parameter) = parameters.named_child(argument_index) else {
            continue;
        };
        collect_parameter_bindings(
            path,
            content,
            parameter,
            usize::try_from(argument_index).unwrap_or(usize::MAX),
            None,
            &mut result,
        );
    }
    result
}

fn collect_parameter_bindings(
    path: &str,
    content: &[u8],
    node: Node<'_>,
    argument_index: usize,
    property_path: Option<String>,
    result: &mut Vec<ParameterInfo>,
) {
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier_pattern"
    ) {
        if let Some(name) = expression_name(node, content) {
            let property_path = property_path.or_else(|| {
                (node.kind() == "shorthand_property_identifier_pattern").then(|| name.clone())
            });
            result.push(ParameterInfo {
                name,
                location: location_for_node(path, content, node),
                argument_index,
                property_path,
            });
        }
        return;
    }
    if matches!(node.kind(), "pair_pattern" | "pair") {
        let key = node
            .child_by_field_name("key")
            .and_then(|key| expression_name(key, content).or_else(|| string_value(key, content)));
        let value = node
            .child_by_field_name("value")
            .or_else(|| node.named_child(1));
        if let Some(value) = value {
            let nested = key.map(|key| append_property_path(property_path.as_deref(), &key));
            collect_parameter_bindings(
                path,
                content,
                value,
                argument_index,
                nested.or(property_path),
                result,
            );
        }
        return;
    }
    if matches!(
        node.kind(),
        "assignment_pattern" | "required_parameter" | "optional_parameter"
    ) && let Some(binding) = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("pattern"))
        .or_else(|| node.named_child(0))
    {
        collect_parameter_bindings(
            path,
            content,
            binding,
            argument_index,
            property_path,
            result,
        );
        return;
    }
    let count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
    for index in 0..count {
        let Some(child) = node.named_child(index) else {
            continue;
        };
        if child.kind().contains("type") {
            continue;
        }
        let nested_path = if matches!(node.kind(), "array_pattern" | "array") {
            Some(append_property_path(
                property_path.as_deref(),
                &index.to_string(),
            ))
        } else {
            property_path.clone()
        };
        collect_parameter_bindings(path, content, child, argument_index, nested_path, result);
    }
}

fn append_property_path(prefix: Option<&str>, property: &str) -> String {
    prefix.map_or_else(
        || property.to_owned(),
        |prefix| format!("{prefix}.{property}"),
    )
}

fn parameter_markers(parameter: &ParameterInfo) -> Vec<String> {
    let mut markers = vec![format!("@parameter:{}", parameter.argument_index)];
    if let Some(path) = &parameter.property_path {
        markers.push(format!("@property:{path}"));
    }
    markers
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
    let mut values = Vec::new();
    for index in 0..count {
        let Some(argument) = arguments.named_child(index) else {
            continue;
        };
        let object_argument = matches!(argument.kind(), "object" | "object_expression");
        if count > 1 || object_argument {
            values.push(format!("@argument:{}:{index}", call.start_byte()));
        }
        if object_argument {
            values.extend(object_argument_values(argument, content, None));
        } else if argument.kind() == "call_expression" {
            values.push(call_output_key(argument));
        } else if let Some(name) = expression_name(argument, content) {
            values.push(name);
        } else {
            values.extend(value_names(argument, content));
        }
    }
    values
}

fn object_argument_values(object: Node<'_>, content: &[u8], prefix: Option<&str>) -> Vec<String> {
    let mut values = Vec::new();
    let count = u32::try_from(object.named_child_count()).unwrap_or(u32::MAX);
    for index in 0..count {
        let Some(property) = object.named_child(index) else {
            continue;
        };
        if matches!(property.kind(), "spread_element" | "spread_property") {
            values.push("@ambiguous-property".into());
            continue;
        }
        if matches!(
            property.kind(),
            "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
        ) && let Some(name) = expression_name(property, content)
        {
            let path = append_property_path(prefix, &name);
            values.push(format!("@property:{path}"));
            values.push(name);
            continue;
        }
        let Some(key) = property
            .child_by_field_name("key")
            .and_then(|key| expression_name(key, content).or_else(|| string_value(key, content)))
        else {
            continue;
        };
        let Some(value) = property
            .child_by_field_name("value")
            .or_else(|| property.named_child(1))
        else {
            continue;
        };
        let path = append_property_path(prefix, &key);
        if matches!(value.kind(), "object" | "object_expression") {
            values.extend(object_argument_values(value, content, Some(&path)));
            continue;
        }
        values.push(format!("@property:{path}"));
        if value.kind() == "call_expression" {
            values.push(call_output_key(value));
        } else if let Some(name) = expression_name(value, content) {
            values.push(name);
        } else {
            values.extend(value_names(value, content));
        }
    }
    values
}

fn argument_slots(inputs: &[String]) -> Vec<Vec<String>> {
    if !inputs.iter().any(|input| input.starts_with("@argument:")) {
        return if inputs.is_empty() {
            Vec::new()
        } else {
            vec![inputs.to_vec()]
        };
    }
    let mut slots = Vec::<Vec<String>>::new();
    for input in inputs {
        if input.starts_with("@argument:") {
            slots.push(Vec::new());
        } else if let Some(slot) = slots.last_mut() {
            slot.push(input.clone());
        }
    }
    slots
}

fn slot_values(slot: &[String]) -> Vec<String> {
    slot.iter()
        .filter(|input| !input.starts_with('@'))
        .cloned()
        .collect()
}

fn property_values(slot: &[String], requested: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut selected = false;
    for input in slot {
        if let Some(path) = input.strip_prefix("@property:") {
            selected = path == requested;
            continue;
        }
        if input.starts_with('@') {
            selected = false;
            continue;
        }
        if selected {
            values.push(input.clone());
        }
    }
    values
}

fn sensitive_sink_inputs(record: &ProgramRecord) -> Vec<String> {
    let mut slots = argument_slots(&record.inputs);
    let leaf = record
        .callee
        .as_deref()
        .map(|callee| terminal_identifier(&callee.to_ascii_lowercase()).to_owned())
        .unwrap_or_default();
    let all_arguments_are_sensitive = (record.name.as_deref() == Some("dynamic-code-execution")
        && leaf == "function")
        || (record.name.as_deref() == Some("filesystem-operation") && leaf == "rename");
    if all_arguments_are_sensitive {
        return slots.into_iter().flatten().collect();
    }
    let mut slots = slots.drain(..);
    let mut sensitive = slots.next().unwrap_or_default();
    let shell_array_api = record.name.as_deref() == Some("process-execution")
        && matches!(
            leaf.as_str(),
            "spawn" | "spawnsync" | "execfile" | "execfilesync"
        );
    if shell_array_api && let Some(arguments) = slots.next() {
        sensitive.extend(arguments);
    }
    sensitive
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

fn unshadowed_dynamic_code_callee(
    call: Node<'_>,
    content: &[u8],
    function: Option<&FunctionInfo>,
    aliases: &AliasMap,
) -> Option<&'static str> {
    let callee = call.child_by_field_name("function")?;
    let final_value = final_sequence_value(callee)?;
    let raw = expression_name(final_value, content)?;
    if raw.contains('.') || raw.contains('[') {
        return None;
    }
    let resolved = resolve_alias(&raw, function, aliases);
    if resolved != "eval" || !alias_chain_originates_from_builtin_eval(call, &raw, content, 8) {
        return None;
    }
    Some("eval")
}

fn final_sequence_value(mut node: Node<'_>) -> Option<Node<'_>> {
    for _ in 0..8 {
        match node.kind() {
            "parenthesized_expression" => node = node.named_child(0)?,
            "sequence_expression" => {
                let count = u32::try_from(node.named_child_count()).ok()?;
                node = count
                    .checked_sub(1)
                    .and_then(|index| node.named_child(index))?;
            }
            _ => return Some(node),
        }
    }
    None
}

fn alias_chain_originates_from_builtin_eval(
    call: Node<'_>,
    name: &str,
    content: &[u8],
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    if name == "eval" {
        return !binding_shadows_builtin_eval(call, content);
    }
    if non_variable_binding_shadows_name(call, name, content) {
        return false;
    }
    unique_alias_initializer(call, name, content).is_some_and(|initializer| {
        final_sequence_value(initializer)
            .and_then(|value| expression_name(value, content))
            .is_some_and(|target| {
                !target.contains('.')
                    && !target.contains('[')
                    && alias_chain_originates_from_builtin_eval(
                        call,
                        &target,
                        content,
                        depth.saturating_sub(1),
                    )
            })
    })
}

fn binding_shadows_builtin_eval(call: Node<'_>, content: &[u8]) -> bool {
    if non_variable_binding_shadows_name(call, "eval", content) {
        return true;
    }
    let call_scope = enclosing_function_span(call);
    let Some(root) = program_root(call) else {
        return true;
    };
    let mut stack = vec![root];
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited > 4096 {
            return true;
        }
        let declaration_scope = binding_scope(node);
        let visible_scope = declaration_scope.is_none() || declaration_scope == call_scope;
        let declares_eval = node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .is_some_and(|pattern| pattern_binds_name(pattern, "eval", content));
        let assigns_eval_before_call = node.end_byte() <= call.start_byte()
            && (matches!(
                node.kind(),
                "assignment_expression" | "augmented_assignment_expression"
            ) && node
                .child_by_field_name("left")
                .and_then(|left| expression_name(left, content))
                .as_deref()
                == Some("eval"));
        if visible_scope && (declares_eval || assigns_eval_before_call) {
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

fn non_variable_binding_shadows_name(call: Node<'_>, name: &str, content: &[u8]) -> bool {
    let call_scope = enclosing_function_span(call);
    if let Some(function) = enclosing_function_node(call)
        && (function
            .child_by_field_name("name")
            .and_then(|node| expression_name(node, content))
            .as_deref()
            == Some(name)
            || function
                .child_by_field_name("parameters")
                .is_some_and(|parameters| pattern_binds_name(parameters, name, content)))
    {
        return true;
    }
    let Some(root) = program_root(call) else {
        return true;
    };
    let mut stack = vec![root];
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited > 4096 {
            return true;
        }
        let declaration_scope = binding_scope(node);
        let visible_scope = declaration_scope.is_none() || declaration_scope == call_scope;
        if visible_scope
            && match node.kind() {
                "function_declaration" | "generator_function_declaration" | "class_declaration" => {
                    node.child_by_field_name("name")
                        .and_then(|binding| expression_name(binding, content))
                        .as_deref()
                        == Some(name)
                }
                "import_specifier" | "namespace_import" => {
                    import_local_name(node, content).as_deref() == Some(name)
                }
                "catch_clause" => node
                    .child_by_field_name("parameter")
                    .is_some_and(|binding| pattern_binds_name(binding, name, content)),
                _ => false,
            }
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

fn unique_alias_initializer<'tree>(
    call: Node<'tree>,
    name: &str,
    content: &[u8],
) -> Option<Node<'tree>> {
    let root = program_root(call)?;
    let call_scope = enclosing_function_span(call);
    let mut local = Vec::new();
    let mut global = Vec::new();
    let mut stack = vec![root];
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited > 4096 {
            return None;
        }
        if node.kind() == "variable_declarator"
            && node.end_byte() <= call.start_byte()
            && node
                .child_by_field_name("name")
                .and_then(|binding| expression_name(binding, content))
                .as_deref()
                == Some(name)
            && let Some(value) = node.child_by_field_name("value")
        {
            match binding_scope(node) {
                scope if scope == call_scope => local.push(value),
                None => global.push(value),
                _ => {}
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    let candidates = if local.is_empty() { global } else { local };
    (candidates.len() == 1).then(|| candidates[0])
}

fn pattern_binds_name(node: Node<'_>, name: &str, content: &[u8]) -> bool {
    if node.kind().contains("type") {
        return false;
    }
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier_pattern" | "shorthand_property_identifier"
    ) && expression_name(node, content).as_deref() == Some(name)
    {
        return true;
    }
    (0..node.named_child_count()).any(|index| {
        node.named_child(u32::try_from(index).unwrap_or(u32::MAX))
            .is_some_and(|child| pattern_binds_name(child, name, content))
    })
}

fn import_local_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    node.child_by_field_name("alias")
        .or_else(|| node.child_by_field_name("name"))
        .and_then(|binding| expression_name(binding, content))
        .or_else(|| {
            (0..node.named_child_count()).find_map(|index| {
                node.named_child(u32::try_from(index).ok()?)
                    .and_then(|binding| expression_name(binding, content))
            })
        })
}

fn program_root(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    (node.kind() == "program").then_some(node)
}

fn enclosing_function_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if is_function(parent) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn enclosing_function_span(node: Node<'_>) -> Option<(usize, usize)> {
    enclosing_function_node(node).map(|function| (function.start_byte(), function.end_byte()))
}

fn binding_scope(node: Node<'_>) -> Option<(usize, usize)> {
    let start = if is_function(node) {
        node.parent()
    } else {
        Some(node)
    }?;
    enclosing_function_node(start).map(|function| (function.start_byte(), function.end_byte()))
}

fn expression_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier"
        | "property_identifier"
        | "private_property_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern"
        | "this" => normalize(node.utf8_text(content).ok()?),
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
