use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tree_sitter::Node;

use crate::{
    AnalysisSummary, CancellationToken, EvidenceEdge, EvidenceGraph, EvidenceNode,
    EvidencePathStep, Finding, NormalizedFact, ParserProvenance, RuleMetadata, ScanConfiguration,
    ScanError, SourceLocation, SourceSpan, SuppressionDiagnostic,
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
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct Trace {
    nodes: Vec<String>,
    edges: Vec<String>,
    source_function: Option<String>,
}

#[derive(Clone)]
struct Candidate {
    rule_id: &'static str,
    trace: Trace,
    sink_node: String,
    guards: Vec<String>,
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
                && record(
                    &item.kind,
                    item.name.as_deref(),
                    item.function.as_deref(),
                    item.inputs.clone(),
                    item.output.as_deref(),
                    item.callee.as_deref(),
                    item.location.clone(),
                    &item.provenance,
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
        let node = builder.node(
            graph_kind_for_record(&record.kind, record.name.as_deref()),
            record
                .name
                .as_deref()
                .or(record.output.as_deref())
                .or(record.callee.as_deref()),
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
                .entry(raw.clone())
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
    let guards = all_records
        .iter()
        .filter(|record| record.kind == "guard")
        .filter_map(|record| {
            record
                .function
                .as_ref()
                .map(|function| (function.clone(), *record))
        })
        .fold(
            BTreeMap::<String, Vec<&ProgramRecord>>::new(),
            |mut map, (function, record)| {
                map.entry(function).or_default().push(record);
                map
            },
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
                            },
                        );
                    }
                }
                "assignment" | "transformation" => {
                    if let (Some(output), Some(trace)) = (
                        &record.output,
                        trace_for_inputs(&snapshot, &function, &record.inputs),
                    ) {
                        let edge_kind = if record.kind == "assignment" {
                            "assignment"
                        } else {
                            "source-to-sink-propagation"
                        };
                        let trace = extend_trace(
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
                        insert_trace(&mut taints, (function.clone(), output.clone()), trace);
                    }
                }
                "sanitizer" => {
                    if let Some(trace) = trace_for_inputs(&snapshot, &function, &record.inputs) {
                        let _edge = builder.edge(
                            "sanitization",
                            trace.nodes.last().map_or(record_node, String::as_str),
                            record_node,
                            &record.location,
                            &record.provenance,
                        );
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
                        let trace = extend_trace(
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
                        insert_trace(&mut taints, (function.clone(), "@return".into()), trace);
                    }
                }
                "sink" => {
                    if let Some(trace) = trace_for_inputs(&snapshot, &function, &record.inputs)
                        && let Some(rule_id) = rule_for_sink(record)
                    {
                        let guard_nodes = dominating_guards(record, &guards, &record_nodes);
                        add_candidate(
                            rule_id,
                            trace,
                            record_node,
                            guard_nodes,
                            record,
                            &mut builder,
                            &mut candidates,
                        );
                    }
                    if handlers.contains(&function)
                        && dominating_guards(record, &guards, &record_nodes).is_empty()
                    {
                        let Some(handler_node) = function_nodes.get(&function) else {
                            continue;
                        };
                        add_candidate(
                            "SE1007",
                            &Trace {
                                nodes: vec![handler_node.clone()],
                                edges: Vec::new(),
                                source_function: Some(function.clone()),
                            },
                            record_node,
                            Vec::new(),
                            record,
                            &mut builder,
                            &mut candidates,
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
    let (mut findings, suppression_diagnostics, suppressed) =
        findings_from_candidates(candidates.into_values().collect(), &graph, configuration);
    let findings_were_truncated = findings.len() > configuration.max_findings;
    findings.truncate(configuration.max_findings);
    let truncated = builder.truncated || findings_were_truncated;
    let limitations = analysis_limitations(configuration, truncated);
    Ok(AnalysisResult {
        summary: AnalysisSummary {
            nodes: graph.nodes.len(),
            edges: graph.edges.len(),
            candidate_paths: findings.len().saturating_add(suppressed),
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
            let server_action = global_use_server && is_exported(node);
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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn extract_record_for_node(
    path: &str,
    content: &[u8],
    node: Node<'_>,
    function: Option<&FunctionInfo>,
    provenance: &ParserProvenance,
    records: &mut Vec<ProgramRecord>,
) {
    let function_name = function.map(|item| item.qualified_name.as_str());
    match node.kind() {
        "member_expression" | "subscript_expression" => {
            if let Some(name) = expression_name(node, content)
                && is_untrusted_source(&name)
            {
                records.push(record(
                    "source",
                    Some(source_kind(&name)),
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
                let inputs = value_names(value, content);
                let callee = call_callee(value, content);
                let kind = if callee.as_deref().is_some_and(is_sanitizer_name) {
                    "sanitizer"
                } else if is_transformation(value) {
                    "transformation"
                } else {
                    "assignment"
                };
                records.push(record(
                    kind,
                    callee.as_deref(),
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
            let Some(callee) = node
                .child_by_field_name("function")
                .and_then(|item| expression_name(item, content))
            else {
                return;
            };
            let inputs = argument_values(node, content);
            let sink = sink_kind(&callee);
            let kind = if sink.is_some() {
                "sink"
            } else if is_guard_name(&callee) {
                "guard"
            } else if is_sanitizer_name(&callee) {
                "sanitizer"
            } else if is_request_call(&callee) {
                "source"
            } else {
                "call"
            };
            let name = if sink == Some("database-access")
                && is_parameterized_database_call(node, content)
            {
                Some("database-parameterized")
            } else {
                sink.or(Some(callee.as_str()))
            };
            let output = (kind == "source").then_some(callee.as_str());
            records.push(record(
                kind,
                name,
                function_name,
                inputs,
                output,
                Some(&callee),
                location_for_node(path, content, node),
                provenance,
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
                if inputs.iter().any(|name| is_guard_name(name)) {
                    records.push(record(
                        "guard",
                        Some("authorization-condition"),
                        function_name,
                        inputs,
                        None,
                        None,
                        location_for_node(path, content, condition),
                        provenance,
                    ));
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    kind: &str,
    name: Option<&str>,
    function: Option<&str>,
    mut inputs: Vec<String>,
    output: Option<&str>,
    callee: Option<&str>,
    location: SourceLocation,
    provenance: &ParserProvenance,
) -> ProgramRecord {
    inputs.sort();
    inputs.dedup();
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
                .and_then(|name| unique_function(name, raw_functions))
            && let Some(target) = function_nodes.get(callee)
        {
            let _edge = builder.edge("calls", node, target, &record.location, &record.provenance);
        }
    }
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
        .and_then(|name| unique_function(name, functions))
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
        let parameter_trace = extend_trace(&via_call, parameter_node, parameter_edge);
        if let Some(output) = &parameter.output {
            insert_trace(
                updates,
                (callee_function.clone(), output.clone()),
                parameter_trace,
            );
        }
    }
}

fn add_candidate(
    rule_id: &'static str,
    trace: &Trace,
    sink_node: &str,
    guards: Vec<String>,
    sink: &ProgramRecord,
    builder: &mut GraphBuilder,
    candidates: &mut BTreeMap<String, Candidate>,
) {
    let edge = builder.edge(
        "source-to-sink-propagation",
        trace.nodes.last().map_or(sink_node, String::as_str),
        sink_node,
        &sink.location,
        &sink.provenance,
    );
    let extended = extend_trace(trace, sink_node, edge);
    let key = format!("{rule_id}:{sink_node}:{}", extended.nodes.join(":"));
    candidates.entry(key).or_insert(Candidate {
        rule_id,
        trace: extended,
        sink_node: sink_node.into(),
        guards,
    });
}

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
                    "assignment" | "transformation" | "argument" | "return"
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
        });
    }
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    findings.dedup_by(|left, right| left.fingerprint == right.fingerprint);
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
) -> Vec<crate::Limitation> {
    let mut limitations = vec![
        crate::Limitation { code: "bounded-interprocedural-analysis".into(), message: format!("Local inter-procedural propagation is bounded to {} traversal levels", configuration.max_interprocedural_depth) },
        crate::Limitation { code: "dynamic-resolution-limited".into(), message: "Dynamic imports, non-unique aliases, callbacks, recursion, and unresolved calls are not followed".into() },
        crate::Limitation { code: "framework-middleware-not-modeled".into(), message: "Authentication supplied only by external framework middleware is not proven by this phase".into() },
    ];
    if truncated {
        limitations.push(crate::Limitation {
            code: "analysis-limit-reached".into(),
            message: "A configured graph or finding bound truncated Phase 3 analysis".into(),
        });
    }
    limitations
}

fn trace_for_inputs<'a>(
    taints: &'a BTreeMap<(String, String), Trace>,
    function: &str,
    inputs: &[String],
) -> Option<&'a Trace> {
    inputs.iter().find_map(|input| {
        let mut candidate = input.as_str();
        loop {
            if let Some(trace) = taints.get(&(function.to_owned(), candidate.to_owned())) {
                return Some(trace);
            }
            let Some((prefix, _)) = candidate.rsplit_once('.') else {
                break;
            };
            candidate = prefix;
        }
        None
    })
}

fn insert_trace(
    taints: &mut BTreeMap<(String, String), Trace>,
    key: (String, String),
    trace: Trace,
) {
    if taints.get(&key).is_none_or(|existing| trace < *existing) {
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

fn dominating_guards(
    record: &ProgramRecord,
    guards: &BTreeMap<String, Vec<&ProgramRecord>>,
    record_nodes: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut nodes = record
        .function
        .as_ref()
        .and_then(|function| guards.get(function))
        .into_iter()
        .flatten()
        .filter(|guard| guard.location.span.start_byte < record.location.span.start_byte)
        .filter_map(|guard| record_nodes.get(&guard.record_id).cloned())
        .collect::<Vec<_>>();
    nodes.sort();
    nodes.dedup();
    nodes
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
) -> Option<&'a String> {
    let leaf = callee.rsplit('.').next().unwrap_or(callee);
    let matches = functions.get(leaf)?;
    (matches.len() == 1).then(|| &matches[0])
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
        "transformation" => "transformation",
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
    None
}

fn is_raw_database_call(callee: &str) -> bool {
    matches!(
        callee.to_ascii_lowercase().rsplit('.').next(),
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
    ]
    .iter()
    .any(|token| lower.contains(token))
}
fn is_request_call(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.starts_with("req.") || lower.starts_with("request."))
        && ["get", "header", "cookie", "json", "formdata"]
            .iter()
            .any(|leaf| lower.ends_with(leaf))
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
fn source_kind(name: &str) -> &str {
    let lower = name.to_ascii_lowercase();
    if lower.contains("header") {
        "request-header"
    } else if lower.contains("cookie") {
        "request-cookie"
    } else if lower.contains("body") || lower.contains("formdata") {
        "request-body"
    } else if lower.contains("url") || lower.contains("searchparam") {
        "request-url"
    } else {
        "request-parameter"
    }
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
            expression_name(argument, content)
                .map_or_else(|| value_names(argument, content), |name| vec![name])
        })
        .collect()
}

fn call_callee(node: Node<'_>, content: &[u8]) -> Option<String> {
    (node.kind() == "call_expression")
        .then(|| node.child_by_field_name("function"))
        .flatten()
        .and_then(|item| expression_name(item, content))
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
