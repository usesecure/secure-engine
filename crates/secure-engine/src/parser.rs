use std::ops::ControlFlow;

use serde::{Deserialize, Serialize};
use tree_sitter::{Node, ParseOptions, Parser};

use crate::graph::{ProgramUnit, empty_program, extract_program, validate_program};
use crate::{
    CancellationToken, FactRelationship, NormalizedFact, ParserDiagnostic, ParserProvenance,
    ScanConfiguration, ScanError, SourceLocation, SourceSpan,
};

pub(crate) const PARSER_ADAPTER_VERSION: &str = "secure-tree-sitter-adapter-v1";
pub(crate) const EXTRACTOR_VERSION: &str = "normalized-js-facts-v1";
pub(crate) const TREE_SITTER_VERSION: &str = "0.26.11";
const JAVASCRIPT_GRAMMAR_VERSION: &str = "0.25.0";
const TYPESCRIPT_GRAMMAR_VERSION: &str = "0.23.2";
const MAX_NORMALIZED_NAME_BYTES: usize = 512;
const MAX_DIAGNOSTICS_PER_FILE: usize = 256;
const MAX_VISITED_NODES: usize = 5_000_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ParserMode {
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
}

impl ParserMode {
    pub(crate) fn for_path(path: &str) -> Option<Self> {
        let extension = path.rsplit_once('.')?.1.to_ascii_lowercase();
        match extension.as_str() {
            "js" | "mjs" | "cjs" => Some(Self::JavaScript),
            "jsx" => Some(Self::Jsx),
            "ts" | "mts" | "cts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            _ => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::Jsx => "jsx",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
        }
    }

    fn grammar(self) -> tree_sitter::Language {
        match self {
            Self::JavaScript | Self::Jsx => tree_sitter_javascript::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        }
    }

    fn grammar_version(self) -> &'static str {
        match self {
            Self::JavaScript | Self::Jsx => JAVASCRIPT_GRAMMAR_VERSION,
            Self::TypeScript | Self::Tsx => TYPESCRIPT_GRAMMAR_VERSION,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ParseOutput {
    pub(crate) parser_mode: String,
    pub(crate) parsed: bool,
    pub(crate) facts: Vec<NormalizedFact>,
    pub(crate) diagnostics: Vec<ParserDiagnostic>,
    pub(crate) program: ProgramUnit,
}

pub(crate) fn provenance(mode: ParserMode) -> ParserProvenance {
    let grammar_crate = match mode {
        ParserMode::JavaScript | ParserMode::Jsx => "tree-sitter-javascript",
        ParserMode::TypeScript | ParserMode::Tsx => "tree-sitter-typescript",
    };
    ParserProvenance {
        parser: PARSER_ADAPTER_VERSION.into(),
        parser_version: TREE_SITTER_VERSION.into(),
        grammar: format!(
            "{grammar_crate}@{}:{}",
            mode.grammar_version(),
            mode.as_str()
        ),
        extractor_version: EXTRACTOR_VERSION.into(),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_source(
    path: &str,
    content: &[u8],
    mode: ParserMode,
    configuration: &ScanConfiguration,
    cancellation: &CancellationToken,
) -> Result<ParseOutput, ScanError> {
    check_cancelled(cancellation)?;
    let parser_provenance = provenance(mode);
    if std::str::from_utf8(content).is_err() {
        return Ok(ParseOutput {
            parser_mode: mode.as_str().into(),
            parsed: false,
            facts: Vec::new(),
            diagnostics: vec![diagnostic(
                "invalid-utf8",
                "Supported source must be valid UTF-8",
                start_location(path),
                false,
                &parser_provenance,
            )],
            program: empty_program(path, &parser_provenance),
        });
    }

    let mut parser = Parser::new();
    parser
        .set_language(&mode.grammar())
        .map_err(|_| ScanError::Internal("supported parser grammar could not be loaded".into()))?;
    let mut reader = |offset: usize, _position| content.get(offset..).unwrap_or_default();
    let mut cancellation_callback = |_state: &tree_sitter::ParseState| {
        if cancellation.is_cancelled() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let options = ParseOptions::new().progress_callback(&mut cancellation_callback);
    let tree = parser.parse_with_options(&mut reader, None, Some(options));
    let Some(tree) = tree else {
        check_cancelled(cancellation)?;
        return Ok(ParseOutput {
            parser_mode: mode.as_str().into(),
            parsed: false,
            facts: Vec::new(),
            diagnostics: vec![diagnostic(
                "parser-aborted",
                "The parser did not produce a syntax tree",
                start_location(path),
                false,
                &parser_provenance,
            )],
            program: empty_program(path, &parser_provenance),
        });
    };

    let root = tree.root_node();
    let global_use_server = contains_directive(root, content, "use server");
    let mut facts = Vec::new();
    let mut diagnostics = Vec::new();
    let mut stack = vec![root];
    let mut visited = 0_usize;
    let diagnostic_limit = configuration
        .max_parser_diagnostics
        .min(MAX_DIAGNOSTICS_PER_FILE);
    while let Some(node) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited.is_multiple_of(256) {
            check_cancelled(cancellation)?;
        }
        if visited > MAX_VISITED_NODES {
            push_diagnostic(
                &mut diagnostics,
                diagnostic_limit,
                diagnostic(
                    "syntax-node-limit",
                    "Additional syntax nodes were not traversed",
                    location_for_node(path, content, node),
                    true,
                    &parser_provenance,
                ),
            );
            break;
        }
        if node.is_error() {
            push_diagnostic(
                &mut diagnostics,
                diagnostic_limit,
                diagnostic(
                    "syntax-error",
                    "Tree-sitter recovered from malformed syntax",
                    location_for_node(path, content, node),
                    true,
                    &parser_provenance,
                ),
            );
        } else if node.is_missing() {
            push_diagnostic(
                &mut diagnostics,
                diagnostic_limit,
                diagnostic(
                    "missing-syntax",
                    "Tree-sitter inserted missing syntax during recovery",
                    location_for_node(path, content, node),
                    true,
                    &parser_provenance,
                ),
            );
        }

        extract_node_facts(
            path,
            content,
            node,
            global_use_server,
            &parser_provenance,
            configuration.max_facts_per_file,
            &mut facts,
        );
        if facts.len() >= configuration.max_facts_per_file {
            push_diagnostic(
                &mut diagnostics,
                diagnostic_limit,
                diagnostic(
                    "fact-limit-reached",
                    "Additional normalized facts were omitted for this file",
                    location_for_node(path, content, node),
                    true,
                    &parser_provenance,
                ),
            );
            break;
        }
        let child_count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
        for index in (0..child_count).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    if root.has_error() && diagnostics.is_empty() {
        push_diagnostic(
            &mut diagnostics,
            diagnostic_limit,
            diagnostic(
                "syntax-error",
                "Tree-sitter recovered from malformed syntax",
                location_for_node(path, content, root),
                true,
                &parser_provenance,
            ),
        );
    }
    check_cancelled(cancellation)?;
    let program = extract_program(
        path,
        content,
        root,
        &parser_provenance,
        global_use_server,
        configuration.max_graph_nodes,
        cancellation,
    )?;
    facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
    facts.dedup_by(|left, right| left.fact_id == right.fact_id);
    diagnostics.sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
    diagnostics.dedup_by(|left, right| left.diagnostic_id == right.diagnostic_id);
    Ok(ParseOutput {
        parser_mode: mode.as_str().into(),
        parsed: true,
        facts,
        diagnostics,
        program,
    })
}

pub(crate) fn validate_cached_output(
    output: &ParseOutput,
    expected_path: &str,
    expected_mode: ParserMode,
    configuration: &ScanConfiguration,
) -> bool {
    if output.parser_mode != expected_mode.as_str()
        || output.facts.len() > configuration.max_facts_per_file
        || output.diagnostics.len()
            > configuration
                .max_parser_diagnostics
                .min(MAX_DIAGNOSTICS_PER_FILE)
    {
        return false;
    }
    let expected_provenance = provenance(expected_mode);
    let facts_are_valid = output.facts.iter().all(|fact| {
        fact.location.path == expected_path
            && location_is_valid(&fact.location)
            && normalized_value_is_valid(&fact.kind)
            && fact.provenance == expected_provenance
            && fact.name.as_deref().is_none_or(normalized_value_is_valid)
            && fact.relationships.iter().all(|relationship| {
                normalized_value_is_valid(&relationship.kind)
                    && normalized_value_is_valid(&relationship.target)
            })
            && fact.fingerprint
                == fact_fingerprint(
                    &fact.kind,
                    &fact.location,
                    fact.name.as_deref(),
                    &fact.relationships,
                    &fact.provenance,
                )
            && fact.fact_id == format!("sf_{}", &fact.fingerprint[..24])
    });
    let diagnostics_are_valid = output.diagnostics.iter().all(|item| {
        item.location.path == expected_path
            && location_is_valid(&item.location)
            && item.provenance == expected_provenance
            && diagnostic_message(&item.code) == Some(item.message.as_str())
            && diagnostic_recoverable(&item.code) == Some(item.recoverable)
            && diagnostic(
                &item.code,
                &item.message,
                item.location.clone(),
                item.recoverable,
                &item.provenance,
            )
            .diagnostic_id
                == item.diagnostic_id
    });
    facts_are_valid
        && diagnostics_are_valid
        && validate_program(
            &output.program,
            expected_path,
            configuration.max_graph_nodes,
        )
}

fn diagnostic_recoverable(code: &str) -> Option<bool> {
    match code {
        "invalid-utf8" | "parser-aborted" => Some(false),
        "syntax-error" | "missing-syntax" | "syntax-node-limit" | "fact-limit-reached" => {
            Some(true)
        }
        _ => None,
    }
}

fn diagnostic_message(code: &str) -> Option<&'static str> {
    match code {
        "invalid-utf8" => Some("Supported source must be valid UTF-8"),
        "parser-aborted" => Some("The parser did not produce a syntax tree"),
        "syntax-error" => Some("Tree-sitter recovered from malformed syntax"),
        "missing-syntax" => Some("Tree-sitter inserted missing syntax during recovery"),
        "syntax-node-limit" => Some("Additional syntax nodes were not traversed"),
        "fact-limit-reached" => Some("Additional normalized facts were omitted for this file"),
        _ => None,
    }
}

fn location_is_valid(location: &SourceLocation) -> bool {
    !location.path.is_empty()
        && location.span.start_byte <= location.span.end_byte
        && location.span.start_line >= 1
        && location.span.start_column >= 1
        && location.span.end_line >= location.span.start_line
        && location.span.end_column >= 1
}

fn normalized_value_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NORMALIZED_NAME_BYTES
        && !value.chars().any(char::is_control)
}

#[allow(clippy::too_many_lines)]
fn extract_node_facts(
    path: &str,
    content: &[u8],
    node: Node<'_>,
    global_use_server: bool,
    parser_provenance: &ParserProvenance,
    maximum: usize,
    facts: &mut Vec<NormalizedFact>,
) {
    if facts.len() >= maximum {
        return;
    }
    match node.kind() {
        "function_declaration"
        | "generator_function_declaration"
        | "function_expression"
        | "arrow_function" => {
            let name = function_name(node, content);
            push_fact(
                facts,
                maximum,
                make_fact(
                    "function",
                    path,
                    content,
                    node,
                    name.clone(),
                    Vec::new(),
                    parser_provenance,
                ),
            );
            if (global_use_server || function_has_use_server(node, content)) && is_exported(node) {
                let relationships = name
                    .as_ref()
                    .map(|name| relationship("exports-server-action", name))
                    .into_iter()
                    .collect();
                push_fact(
                    facts,
                    maximum,
                    make_fact(
                        "server-action-handler",
                        path,
                        content,
                        node,
                        name,
                        relationships,
                        parser_provenance,
                    ),
                );
            }
        }
        "method_definition" => push_fact(
            facts,
            maximum,
            make_fact(
                "method",
                path,
                content,
                node,
                node.child_by_field_name("name")
                    .and_then(|name| expression_name(name, content)),
                Vec::new(),
                parser_provenance,
            ),
        ),
        "import_statement" => {
            let module = node
                .child_by_field_name("source")
                .and_then(|source| string_value(source, content));
            let relationships = module
                .as_ref()
                .map(|module| relationship("imports", module))
                .into_iter()
                .collect();
            push_fact(
                facts,
                maximum,
                make_fact(
                    "module-import",
                    path,
                    content,
                    node,
                    module,
                    relationships,
                    parser_provenance,
                ),
            );
        }
        "export_statement" => {
            extract_export_fact(path, content, node, parser_provenance, maximum, facts);
        }
        "call_expression" => {
            extract_call_facts(path, content, node, parser_provenance, maximum, facts);
        }
        "new_expression" => {
            if node
                .child_by_field_name("constructor")
                .and_then(|constructor| expression_name(constructor, content))
                .is_some_and(|name| name == "Function")
            {
                push_fact(
                    facts,
                    maximum,
                    make_fact(
                        "dynamic-code-execution",
                        path,
                        content,
                        node,
                        Some("Function".into()),
                        vec![relationship("constructs", "Function")],
                        parser_provenance,
                    ),
                );
            }
        }
        "member_expression" | "subscript_expression" => {
            if let Some(name) = expression_name(node, content)
                && environment_name(&name).is_some()
            {
                push_fact(
                    facts,
                    maximum,
                    make_fact(
                        "environment-access",
                        path,
                        content,
                        node,
                        environment_name(&name),
                        vec![relationship("reads-environment", &name)],
                        parser_provenance,
                    ),
                );
            }
        }
        "if_statement" => {
            if let Some(condition) = node.child_by_field_name("condition") {
                let names = identifier_names(condition, content);
                if names.iter().any(|name| is_guard_name(name)) {
                    let normalized = names.join(".");
                    push_fact(
                        facts,
                        maximum,
                        make_fact(
                            "guard-candidate",
                            path,
                            content,
                            condition,
                            normalize_name(&normalized),
                            vec![relationship("guards-branch", &normalized)],
                            parser_provenance,
                        ),
                    );
                }
            }
        }
        _ => {}
    }
}

fn extract_export_fact(
    path: &str,
    content: &[u8],
    node: Node<'_>,
    parser_provenance: &ParserProvenance,
    maximum: usize,
    facts: &mut Vec<NormalizedFact>,
) {
    let module = node
        .child_by_field_name("source")
        .and_then(|source| string_value(source, content));
    let declaration = node.child_by_field_name("declaration");
    let name = declaration
        .and_then(|item| declared_name(item, content))
        .or_else(|| exported_clause_name(node, content))
        .or_else(|| module.clone());
    let mut relationships = Vec::new();
    if let Some(module) = &module {
        relationships.push(relationship("re-exports", module));
    }
    if let Some(name) = &name {
        relationships.push(relationship("exports", name));
    }
    push_fact(
        facts,
        maximum,
        make_fact(
            "module-export",
            path,
            content,
            node,
            name.clone(),
            relationships,
            parser_provenance,
        ),
    );

    if let Some(name) = name
        && is_http_method(&name)
        && file_name(path).starts_with("route.")
    {
        let route = next_route_from_path(path);
        push_fact(
            facts,
            maximum,
            make_fact(
                "http-route-handler",
                path,
                content,
                declaration.unwrap_or(node),
                Some(name.clone()),
                vec![relationship(
                    "handles",
                    &format!("{} {route}", name.to_ascii_uppercase()),
                )],
                parser_provenance,
            ),
        );
    }
}

fn extract_call_facts(
    path: &str,
    content: &[u8],
    node: Node<'_>,
    parser_provenance: &ParserProvenance,
    maximum: usize,
    facts: &mut Vec<NormalizedFact>,
) {
    let Some(callee_node) = node.child_by_field_name("function") else {
        return;
    };
    let Some(callee) = expression_name(callee_node, content) else {
        return;
    };
    push_fact(
        facts,
        maximum,
        make_fact(
            "call",
            path,
            content,
            node,
            Some(callee.clone()),
            vec![relationship("calls", &callee)],
            parser_provenance,
        ),
    );

    if let Some((method, route, handler)) = conventional_route(node, content, &callee) {
        let mut relationships = vec![relationship("handles", &format!("{method} {route}"))];
        if let Some(handler) = handler {
            relationships.push(relationship("handler", &handler));
        }
        push_fact(
            facts,
            maximum,
            make_fact(
                "http-route",
                path,
                content,
                node,
                Some(callee.clone()),
                relationships,
                parser_provenance,
            ),
        );
    }

    for kind in operation_kinds(&callee) {
        push_fact(
            facts,
            maximum,
            make_fact(
                kind,
                path,
                content,
                node,
                Some(callee.clone()),
                vec![relationship("invokes", &callee)],
                parser_provenance,
            ),
        );
    }
    if callee == "Deno.env.get" || callee == "Bun.env.get" {
        let variable =
            first_argument(node, content).and_then(|argument| string_value(argument, content));
        push_fact(
            facts,
            maximum,
            make_fact(
                "environment-access",
                path,
                content,
                node,
                variable,
                vec![relationship("reads-environment", &callee)],
                parser_provenance,
            ),
        );
    }
}

fn operation_kinds(callee: &str) -> Vec<&'static str> {
    let lower = callee.to_ascii_lowercase();
    let leaf = lower.rsplit('.').next().unwrap_or(lower.as_str());
    let mut kinds = Vec::new();
    if matches!(
        leaf,
        "exec" | "execsync" | "execfile" | "execfilesync" | "spawn" | "spawnsync" | "fork"
    ) || lower.starts_with("child_process.")
    {
        kinds.push("process-execution");
    }
    if matches!(
        leaf,
        "query" | "execute" | "raw" | "$queryraw" | "$executeraw" | "findmany" | "findunique"
    ) || lower.starts_with("prisma.")
    {
        kinds.push("database-access");
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
        kinds.push("filesystem-operation");
    }
    if leaf == "fetch"
        || lower.starts_with("axios.")
        || matches!(
            lower.as_str(),
            "axios" | "http.get" | "http.request" | "https.get" | "https.request"
        )
    {
        kinds.push("network-request");
    }
    if leaf == "redirect" {
        kinds.push("redirect");
    }
    if matches!(leaf, "render" | "renderfile" | "rendertostring") {
        kinds.push("template-render");
    }
    if matches!(
        lower.as_str(),
        "json.parse" | "yaml.load" | "yaml.parsesafe"
    ) || matches!(leaf, "deserialize" | "deserializeunchecked")
    {
        kinds.push("deserialization");
    }
    if matches!(leaf, "eval") {
        kinds.push("dynamic-code-execution");
    }
    kinds
}

fn conventional_route(
    call: Node<'_>,
    content: &[u8],
    callee: &str,
) -> Option<(String, String, Option<String>)> {
    let (object, method) = callee.rsplit_once('.')?;
    if !is_http_method(method)
        || !object
            .rsplit('.')
            .next()
            .is_some_and(|name| matches!(name, "app" | "router" | "server"))
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let route = arguments
        .named_child(0)
        .and_then(|argument| string_value(argument, content))?;
    let argument_count = u32::try_from(arguments.named_child_count()).unwrap_or(u32::MAX);
    let handler = argument_count
        .checked_sub(1)
        .and_then(|index| arguments.named_child(index))
        .and_then(|argument| {
            function_name(argument, content).or_else(|| expression_name(argument, content))
        });
    Some((method.to_ascii_uppercase(), route, handler))
}

fn first_argument<'tree>(call: Node<'tree>, _content: &[u8]) -> Option<Node<'tree>> {
    call.child_by_field_name("arguments")?.named_child(0)
}

fn function_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    node.child_by_field_name("name")
        .and_then(|name| expression_name(name, content))
        .or_else(|| {
            let parent = node.parent()?;
            (parent.kind() == "variable_declarator")
                .then(|| parent.child_by_field_name("name"))
                .flatten()
                .and_then(|name| expression_name(name, content))
        })
}

fn declared_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    function_name(node, content)
        .or_else(|| {
            let child_count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
            (0..child_count).find_map(|index| {
                let child = node.named_child(index)?;
                (child.kind() == "variable_declarator")
                    .then(|| child.child_by_field_name("name"))
                    .flatten()
                    .and_then(|name| expression_name(name, content))
            })
        })
        .or_else(|| {
            node.child_by_field_name("name")
                .and_then(|name| expression_name(name, content))
        })
}

fn exported_clause_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    let child_count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
    (0..child_count).find_map(|index| {
        let child = node.named_child(index)?;
        (child.kind() == "export_clause")
            .then(|| identifier_names(child, content).into_iter().next())
            .flatten()
    })
}

fn expression_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" | "private_property_identifier" | "this" => {
            normalize_name(node.utf8_text(content).ok()?)
        }
        "member_expression" => {
            let object = node
                .child_by_field_name("object")
                .and_then(|item| expression_name(item, content))?;
            let property = node
                .child_by_field_name("property")
                .and_then(|item| expression_name(item, content))?;
            normalize_name(&format!("{object}.{property}"))
        }
        "subscript_expression" => {
            let object = node
                .child_by_field_name("object")
                .and_then(|item| expression_name(item, content))?;
            let index = node.child_by_field_name("index").and_then(|item| {
                string_value(item, content).or_else(|| expression_name(item, content))
            })?;
            normalize_name(&format!("{object}.{index}"))
        }
        "parenthesized_expression" => node
            .named_child(0)
            .and_then(|child| expression_name(child, content)),
        _ => None,
    }
}

fn identifier_names(node: Node<'_>, content: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut stack = vec![node];
    while let Some(item) = stack.pop() {
        if matches!(item.kind(), "identifier" | "property_identifier")
            && let Some(name) = expression_name(item, content)
        {
            names.push(name);
            if names.len() >= 16 {
                break;
            }
        }
        let child_count = u32::try_from(item.named_child_count()).unwrap_or(u32::MAX);
        for index in (0..child_count).rev() {
            if let Some(child) = item.named_child(index) {
                stack.push(child);
            }
        }
    }
    names
}

fn is_guard_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "auth",
        "authoriz",
        "permission",
        "role",
        "session",
        "user",
        "tenant",
        "owner",
        "policy",
        "guard",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn environment_name(name: &str) -> Option<String> {
    ["process.env.", "import.meta.env.", "Bun.env."]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix))
        .and_then(normalize_name)
}

fn contains_directive(node: Node<'_>, content: &[u8], directive: &str) -> bool {
    let child_count = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
    (0..child_count).any(|index| {
        node.named_child(index).is_some_and(|child| {
            child.kind() == "expression_statement"
                && child
                    .named_child(0)
                    .and_then(|literal| string_value(literal, content))
                    .is_some_and(|value| value == directive)
        })
    })
}

fn function_has_use_server(node: Node<'_>, content: &[u8]) -> bool {
    node.child_by_field_name("body")
        .is_some_and(|body| contains_directive(body, content, "use server"))
}

fn is_exported(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    for _ in 0..4 {
        let Some(parent) = ancestor else {
            return false;
        };
        if parent.kind() == "export_statement" {
            return true;
        }
        ancestor = parent.parent();
    }
    false
}

fn is_http_method(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "USE" | "ALL"
    )
}

fn next_route_from_path(path: &str) -> String {
    let mut components = path.split('/').collect::<Vec<_>>();
    if components
        .last()
        .is_some_and(|name| name.starts_with("route."))
    {
        components.pop();
    }
    if let Some(app_index) = components.iter().position(|part| *part == "app") {
        components.drain(..=app_index);
    }
    components.retain(|component| !(component.starts_with('(') && component.ends_with(')')));
    if components.is_empty() {
        "/".into()
    } else {
        format!("/{}", components.join("/"))
    }
}

fn string_value(node: Node<'_>, content: &[u8]) -> Option<String> {
    let text = node.utf8_text(content).ok()?.trim();
    let unquoted = if text.len() >= 2 {
        let first = text.as_bytes()[0];
        let last = *text.as_bytes().last()?;
        if matches!((first, last), (b'\'', b'\'') | (b'"', b'"') | (b'`', b'`')) {
            &text[1..text.len() - 1]
        } else {
            text
        }
    } else {
        text
    };
    normalize_name(unquoted)
}

fn normalize_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return None;
    }
    let mut normalized = String::new();
    for character in trimmed.chars() {
        if normalized.len().saturating_add(character.len_utf8()) > MAX_NORMALIZED_NAME_BYTES {
            break;
        }
        normalized.push(character);
    }
    (!normalized.is_empty()).then_some(normalized)
}

fn make_fact(
    kind: &str,
    path: &str,
    content: &[u8],
    node: Node<'_>,
    name: Option<String>,
    mut relationships: Vec<FactRelationship>,
    parser_provenance: &ParserProvenance,
) -> NormalizedFact {
    relationships.sort();
    relationships.dedup();
    let location = location_for_node(path, content, node);
    let fingerprint = fact_fingerprint(
        kind,
        &location,
        name.as_deref(),
        &relationships,
        parser_provenance,
    );
    let fact_id = format!("sf_{}", &fingerprint[..24]);
    NormalizedFact {
        fact_id,
        kind: kind.into(),
        location,
        name,
        relationships,
        provenance: parser_provenance.clone(),
        fingerprint,
    }
}

fn fact_fingerprint(
    kind: &str,
    location: &SourceLocation,
    name: Option<&str>,
    relationships: &[FactRelationship],
    parser_provenance: &ParserProvenance,
) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [
        kind,
        &location.path,
        name.unwrap_or(""),
        &parser_provenance.parser,
        &parser_provenance.parser_version,
        &parser_provenance.grammar,
        &parser_provenance.extractor_version,
    ] {
        hash_value(&mut hasher, value.as_bytes());
    }
    for coordinate in [
        location.span.start_byte,
        location.span.end_byte,
        u64::from(location.span.start_line),
        u64::from(location.span.start_column),
        u64::from(location.span.end_line),
        u64::from(location.span.end_column),
    ] {
        hash_value(&mut hasher, &coordinate.to_le_bytes());
    }
    for relationship in relationships {
        hash_value(&mut hasher, relationship.kind.as_bytes());
        hash_value(&mut hasher, relationship.target.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn diagnostic(
    code: &str,
    message: &str,
    location: SourceLocation,
    recoverable: bool,
    parser_provenance: &ParserProvenance,
) -> ParserDiagnostic {
    let mut hasher = blake3::Hasher::new();
    for value in [
        code,
        &location.path,
        &location.span.start_byte.to_string(),
        &location.span.end_byte.to_string(),
        &parser_provenance.grammar,
    ] {
        hash_value(&mut hasher, value.as_bytes());
    }
    let fingerprint = hasher.finalize().to_hex().to_string();
    ParserDiagnostic {
        diagnostic_id: format!("pd_{}", &fingerprint[..24]),
        code: code.into(),
        message: message.into(),
        location,
        recoverable,
        provenance: parser_provenance.clone(),
    }
}

fn push_fact(facts: &mut Vec<NormalizedFact>, maximum: usize, fact: NormalizedFact) {
    if facts.len() < maximum {
        facts.push(fact);
    }
}

fn push_diagnostic(
    diagnostics: &mut Vec<ParserDiagnostic>,
    maximum: usize,
    diagnostic: ParserDiagnostic,
) {
    if diagnostics.len() < maximum {
        diagnostics.push(diagnostic);
    }
}

fn relationship(kind: &str, target: &str) -> FactRelationship {
    FactRelationship {
        kind: kind.into(),
        target: normalize_name(target).unwrap_or_else(|| "unknown".into()),
    }
}

fn location_for_node(path: &str, content: &[u8], node: Node<'_>) -> SourceLocation {
    location_for_range(path, content, node.start_byte(), node.end_byte())
}

fn location_for_range(path: &str, content: &[u8], start: usize, end: usize) -> SourceLocation {
    let bounded_start = start.min(content.len());
    let bounded_end = end.min(content.len()).max(bounded_start);
    let (start_line, start_column) = line_column(content, bounded_start);
    let (end_line, end_column) = line_column(content, bounded_end);
    SourceLocation {
        path: path.into(),
        span: SourceSpan {
            start_byte: u64::try_from(bounded_start).unwrap_or(u64::MAX),
            end_byte: u64::try_from(bounded_end).unwrap_or(u64::MAX),
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
        .map_or(0, |position| position.saturating_add(1));
    let column = std::str::from_utf8(&before[line_start..])
        .map_or(1, |text| text.chars().count().saturating_add(1));
    (line, u32::try_from(column).unwrap_or(u32::MAX))
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

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn hash_value(hasher: &mut blake3::Hasher, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(&length.to_le_bytes());
    hasher.update(value);
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), ScanError> {
    if cancellation.is_cancelled() {
        Err(ScanError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_modes_are_extension_specific() {
        assert_eq!(ParserMode::for_path("app.js"), Some(ParserMode::JavaScript));
        assert_eq!(ParserMode::for_path("view.jsx"), Some(ParserMode::Jsx));
        assert_eq!(
            ParserMode::for_path("model.ts"),
            Some(ParserMode::TypeScript)
        );
        assert_eq!(ParserMode::for_path("page.tsx"), Some(ParserMode::Tsx));
        assert_eq!(ParserMode::for_path("main.rs"), None);
    }

    #[test]
    fn unicode_columns_and_recoverable_facts_are_precise() -> Result<(), ScanError> {
        let source = "const café = '☕';\nexport function GET() { return fetch('/api'); }\n";
        let output = parse_source(
            "app/route.ts",
            source.as_bytes(),
            ParserMode::TypeScript,
            &ScanConfiguration::default(),
            &CancellationToken::new(),
        )?;
        assert!(output.parsed);
        let function = output
            .facts
            .iter()
            .find(|fact| fact.kind == "function" && fact.name.as_deref() == Some("GET"))
            .ok_or_else(|| ScanError::Internal("expected function fact".into()))?;
        assert_eq!(function.location.span.start_line, 2);
        assert_eq!(function.location.span.start_column, 8);
        assert!(
            output
                .facts
                .iter()
                .any(|fact| fact.kind == "network-request")
        );
        assert!(
            output
                .facts
                .iter()
                .any(|fact| fact.kind == "http-route-handler")
        );
        Ok(())
    }

    #[test]
    fn malformed_source_retains_facts_and_diagnostics() -> Result<(), ScanError> {
        let output = parse_source(
            "broken.js",
            b"import x from 'x'; function broken( { fetch('/still-useful')",
            ParserMode::JavaScript,
            &ScanConfiguration::default(),
            &CancellationToken::new(),
        )?;
        assert!(output.parsed);
        assert!(!output.diagnostics.is_empty());
        assert!(output.facts.iter().any(|fact| fact.kind == "module-import"));
        Ok(())
    }

    #[test]
    fn exported_arrow_handlers_support_next_routes_and_server_actions() -> Result<(), ScanError> {
        let output = parse_source(
            "app/api/route.ts",
            b"'use server'; export const POST = async () => { return fetch('/api'); };",
            ParserMode::TypeScript,
            &ScanConfiguration::default(),
            &CancellationToken::new(),
        )?;
        assert!(output.facts.iter().any(|fact| {
            fact.kind == "server-action-handler" && fact.name.as_deref() == Some("POST")
        }));
        assert!(output.facts.iter().any(|fact| {
            fact.kind == "http-route-handler"
                && fact.relationships.iter().any(|relationship| {
                    relationship.kind == "handles" && relationship.target == "POST /api"
                })
        }));
        Ok(())
    }

    #[test]
    fn large_parse_observes_concurrent_cancellation() -> Result<(), Box<dyn std::error::Error>> {
        let source = "export function work() { return fetch('/api'); }\n".repeat(500_000);
        let cancellation = CancellationToken::new();
        let cancelling_token = cancellation.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            cancelling_token.cancel();
        });
        let result = parse_source(
            "large.ts",
            source.as_bytes(),
            ParserMode::TypeScript,
            &ScanConfiguration::default(),
            &cancellation,
        );
        canceller
            .join()
            .map_err(|_| "cancellation thread panicked")?;
        assert!(matches!(result, Err(ScanError::Cancelled)));
        Ok(())
    }
}
