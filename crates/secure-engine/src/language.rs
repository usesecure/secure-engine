use std::collections::BTreeSet;

use tree_sitter::Node;

use crate::graph::{GRAPH_EXTRACTOR_VERSION, ProgramUnit, record};
use crate::parser::{ParserMode, location_for_node, make_fact, relationship};
use crate::{CancellationToken, NormalizedFact, ParserProvenance, ScanError, SourceLocation};

const MAX_NAME_BYTES: usize = 512;

#[derive(Clone)]
struct FunctionInfo {
    name: String,
    qualified: String,
    location: SourceLocation,
    parameters: Vec<(String, SourceLocation)>,
    handler: bool,
    guarded: bool,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn extract_node_facts(
    path: &str,
    content: &[u8],
    node: Node<'_>,
    mode: ParserMode,
    provenance: &ParserProvenance,
    maximum: usize,
    facts: &mut Vec<NormalizedFact>,
) {
    if facts.len() >= maximum {
        return;
    }
    if is_function_node(node, mode) {
        let name = function_name(node, content, mode);
        push_fact(
            facts,
            maximum,
            make_fact(
                "function",
                path,
                content,
                node,
                name,
                Vec::new(),
                provenance,
            ),
        );
        return;
    }
    if is_import_node(node, mode) {
        let name = normalized_text(node, content);
        let relationships = name
            .as_ref()
            .map(|value| relationship("imports", value))
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
                name,
                relationships,
                provenance,
            ),
        );
        return;
    }
    if is_if_node(node) {
        let condition = condition_node(node).unwrap_or(node);
        let inputs = value_names(condition, content);
        if inputs.iter().any(|name| is_guard_name(name)) {
            let name = normalize(&inputs.join("."));
            push_fact(
                facts,
                maximum,
                make_fact(
                    "guard-candidate",
                    path,
                    content,
                    condition,
                    name.clone(),
                    name.as_ref()
                        .map(|value| relationship("guards-branch", value))
                        .into_iter()
                        .collect(),
                    provenance,
                ),
            );
        }
        return;
    }
    if !is_call_node(node) {
        return;
    }
    let Some(callee) = call_callee(node, content) else {
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
            provenance,
        ),
    );
    if let Some((method, route, handler)) = route_call(node, content, &callee, mode) {
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
                provenance,
            ),
        );
    }
    if let Some(kind) = operation_kind(&callee, mode) {
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
                provenance,
            ),
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn extract_program(
    path: &str,
    content: &[u8],
    root: Node<'_>,
    mode: ParserMode,
    parser_provenance: &ParserProvenance,
    maximum: usize,
    cancellation: &CancellationToken,
) -> Result<ProgramUnit, ScanError> {
    let mut provenance = parser_provenance.clone();
    provenance.extractor_version = GRAPH_EXTRACTOR_VERSION.into();
    let route_handlers = collect_route_handlers(root, content, mode, maximum);
    let functions = collect_functions(path, content, root, mode, &route_handlers, maximum);
    let mut records = Vec::new();
    let mut truncated = false;
    for function in &functions {
        if records.len() >= maximum {
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
            Some(&function.qualified),
            Vec::new(),
            None,
            None,
            function.location.clone(),
            &provenance,
        ));
        for (parameter, location) in &function.parameters {
            if records.len() >= maximum {
                truncated = true;
                break;
            }
            records.push(record(
                if function.handler {
                    "source"
                } else {
                    "argument"
                },
                Some(if function.handler {
                    "request-parameter"
                } else {
                    parameter
                }),
                Some(&function.qualified),
                Vec::new(),
                Some(parameter),
                None,
                location.clone(),
                &provenance,
            ));
        }
        if function.guarded && records.len() < maximum {
            records.push(record(
                "guard",
                Some("framework-authorization"),
                Some(&function.qualified),
                Vec::new(),
                None,
                None,
                function.location.clone(),
                &provenance,
            ));
        }
    }

    let mut stack = vec![root];
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        if records.len() >= maximum {
            truncated = true;
            break;
        }
        visited = visited.saturating_add(1);
        if visited.is_multiple_of(256) && cancellation.is_cancelled() {
            return Err(ScanError::Cancelled);
        }
        let function = containing_function(node, &functions);
        extract_record(
            path,
            content,
            node,
            mode,
            function,
            &provenance,
            &mut records,
        );
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    records.sort();
    records.dedup();
    Ok(ProgramUnit {
        path: path.into(),
        provenance,
        records,
        truncated,
    })
}

fn collect_functions(
    path: &str,
    content: &[u8],
    root: Node<'_>,
    mode: ParserMode,
    route_handlers: &BTreeSet<String>,
    maximum: usize,
) -> Vec<FunctionInfo> {
    let mut functions = Vec::new();
    let mut stack = vec![root];
    let repository_middleware_guard = std::str::from_utf8(content)
        .ok()
        .is_some_and(has_authorization_middleware);
    while let Some(node) = stack.pop() {
        if functions.len() >= maximum {
            break;
        }
        if is_function_node(node, mode)
            && let Some(name) = function_name(node, content, mode)
        {
            let decorated = decorated_text(node, content);
            let handler = route_handlers.contains(&name)
                || decorated
                    .as_deref()
                    .is_some_and(|text| is_route_marker(text, mode));
            let guarded = decorated.as_deref().is_some_and(is_guard_name)
                || (handler && repository_middleware_guard);
            functions.push(FunctionInfo {
                qualified: format!("{path}:{name}"),
                name,
                location: location_for_node(path, content, node),
                parameters: function_parameters(path, content, node, mode),
                handler,
                guarded,
            });
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    functions.sort_by_key(|item| item.location.span.start_byte);
    functions
}

fn collect_route_handlers(
    root: Node<'_>,
    content: &[u8],
    mode: ParserMode,
    maximum: usize,
) -> BTreeSet<String> {
    let mut handlers = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if handlers.len() >= maximum {
            break;
        }
        if is_call_node(node)
            && let Some(callee) = call_callee(node, content)
            && let Some((_method, _route, handler)) = route_call(node, content, &callee, mode)
            && let Some(handler) = handler
        {
            handlers.insert(handler);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    handlers
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn extract_record(
    path: &str,
    content: &[u8],
    node: Node<'_>,
    mode: ParserMode,
    function: Option<&FunctionInfo>,
    provenance: &ParserProvenance,
    records: &mut Vec<crate::graph::ProgramRecord>,
) {
    let function_name = function.map(|item| item.qualified.as_str());
    if is_member_node(node, mode)
        && let Some(name) = expression_name(node, content)
        && is_untrusted_source(&name, mode)
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
        return;
    }
    if is_assignment_node(node, mode) {
        let left = assignment_side(node, mode, true);
        let right = assignment_side(node, mode, false);
        if let (Some(left), Some(right)) = (left, right)
            && let Some(output) = first_value_name(left, content)
        {
            let callee = call_callee_deep(right, content);
            let kind = if callee.as_deref().is_some_and(is_sanitizer_name) {
                "sanitizer"
            } else if is_transformation(right, content) {
                "transformation"
            } else {
                "assignment"
            };
            records.push(record(
                kind,
                callee.as_deref(),
                function_name,
                value_names(right, content),
                Some(&output),
                callee.as_deref(),
                location_for_node(path, content, node),
                provenance,
            ));
        }
        return;
    }
    if is_call_node(node) {
        let Some(callee) = call_callee(node, content) else {
            return;
        };
        let inputs = argument_values(node, content);
        let source = is_request_call(&callee, mode);
        let sink = (!source).then(|| sink_kind(&callee, mode)).flatten();
        let kind = if source {
            "source"
        } else if sink.is_some() {
            "sink"
        } else if is_guard_name(&callee) {
            "guard"
        } else if is_sanitizer_name(&callee) {
            "sanitizer"
        } else {
            "call"
        };
        let name = if sink == Some("database-access")
            && is_parameterized_database_call(node, content, mode)
        {
            Some("database-parameterized")
        } else {
            sink.or(Some(callee.as_str()))
        };
        records.push(record(
            kind,
            name,
            function_name,
            inputs,
            (kind == "source").then_some(callee.as_str()),
            Some(&callee),
            location_for_node(path, content, node),
            provenance,
        ));
        return;
    }
    if is_return_node(node, mode) {
        if let Some(value) = return_value(node) {
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
        return;
    }
    if is_import_node(node, mode) {
        let name = normalized_text(node, content);
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
        return;
    }
    if is_if_node(node)
        && let Some(condition) = condition_node(node)
    {
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

fn is_function_node(node: Node<'_>, mode: ParserMode) -> bool {
    match mode {
        ParserMode::Rust => node.kind() == "function_item",
        ParserMode::Python => node.kind() == "function_definition",
        ParserMode::Go => matches!(node.kind(), "function_declaration" | "method_declaration"),
        _ => false,
    }
}

fn function_name(node: Node<'_>, content: &[u8], mode: ParserMode) -> Option<String> {
    node.child_by_field_name("name")
        .and_then(|item| normalized_text(item, content))
        .or_else(|| {
            (mode == ParserMode::Go)
                .then(|| node.named_child(0))
                .flatten()
                .and_then(|item| normalized_text(item, content))
        })
}

fn function_parameters(
    path: &str,
    content: &[u8],
    node: Node<'_>,
    mode: ParserMode,
) -> Vec<(String, SourceLocation)> {
    let parameters = node.child_by_field_name("parameters").or_else(|| {
        (mode == ParserMode::Rust)
            .then(|| node.child_by_field_name("parameters"))
            .flatten()
    });
    let Some(parameters) = parameters else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut stack = vec![parameters];
    while let Some(item) = stack.pop() {
        if is_parameter_identifier(item, mode)
            && let Some(name) = normalized_text(item, content)
            && !result.iter().any(|(existing, _)| existing == &name)
        {
            result.push((name, location_for_node(path, content, item)));
        }
        for index in (0..item.named_child_count()).rev() {
            if let Some(child) = item.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    result
}

fn is_parameter_identifier(node: Node<'_>, mode: ParserMode) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    match mode {
        ParserMode::Rust => node.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "parameter" | "self_parameter" | "reference_pattern"
            )
        }),
        ParserMode::Python => node.parent().is_none_or(|parent| parent.kind() != "type"),
        ParserMode::Go => node.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "parameter_declaration" | "variadic_parameter_declaration"
            )
        }),
        _ => false,
    }
}

fn decorated_text(node: Node<'_>, content: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() == "decorated_definition" {
        let mut decorators = String::new();
        for index in 0..parent.named_child_count() {
            let child = parent.named_child(u32::try_from(index).ok()?)?;
            if child.kind() != "decorator" {
                continue;
            }
            decorators.push_str(child.utf8_text(content).ok()?);
            decorators.push('\n');
        }
        return (!decorators.is_empty()).then_some(decorators);
    }
    let start = node.start_byte().saturating_sub(256);
    let prefix = std::str::from_utf8(content.get(start..node.start_byte())?).ok()?;
    let mut attributes = prefix
        .lines()
        .rev()
        .skip_while(|line| line.trim().is_empty())
        .take_while(|line| line.trim_start().starts_with("#["))
        .collect::<Vec<_>>();
    attributes.reverse();
    (!attributes.is_empty()).then(|| attributes.join("\n"))
}

fn has_authorization_middleware(text: &str) -> bool {
    let lower = text.to_ascii_lowercase().replace(char::is_whitespace, "");
    [
        "auth",
        "authoriz",
        "permission",
        "session",
        "role",
        "policy",
        "guard",
    ]
    .iter()
    .any(|guard| {
        [".use(", ".layer(", "middleware(", "dependencies=["]
            .iter()
            .any(|marker| {
                lower.contains(&format!("{marker}{guard}"))
                    || lower.contains(&format!("{marker}depends({guard}"))
            })
    })
}

fn is_route_marker(text: &str, mode: ParserMode) -> bool {
    let lower = text.to_ascii_lowercase();
    match mode {
        ParserMode::Rust => ["#[get", "#[post", "#[put", "#[delete", "#[patch"]
            .iter()
            .any(|marker| lower.contains(marker)),
        ParserMode::Python => [
            ".get(",
            ".post(",
            ".route(",
            "api_view",
            "require_http_methods",
        ]
        .iter()
        .any(|marker| lower.contains(marker)),
        _ => false,
    }
}

fn is_import_node(node: Node<'_>, mode: ParserMode) -> bool {
    match mode {
        ParserMode::Rust => matches!(node.kind(), "use_declaration" | "extern_crate_declaration"),
        ParserMode::Python => matches!(node.kind(), "import_statement" | "import_from_statement"),
        ParserMode::Go => matches!(node.kind(), "import_declaration" | "import_spec"),
        _ => false,
    }
}

fn is_assignment_node(node: Node<'_>, mode: ParserMode) -> bool {
    match mode {
        ParserMode::Rust => matches!(node.kind(), "let_declaration" | "assignment_expression"),
        ParserMode::Python => matches!(node.kind(), "assignment" | "augmented_assignment"),
        ParserMode::Go => matches!(
            node.kind(),
            "short_var_declaration" | "assignment_statement"
        ),
        _ => false,
    }
}

fn assignment_side(node: Node<'_>, mode: ParserMode, left: bool) -> Option<Node<'_>> {
    let fields: &[&str] = if left {
        &["left", "pattern", "name"]
    } else {
        &["right", "value"]
    };
    fields
        .iter()
        .find_map(|field| node.child_by_field_name(field))
        .or_else(|| {
            let count = node.named_child_count();
            if left {
                node.named_child(0)
            } else {
                count
                    .checked_sub(1)
                    .and_then(|index| node.named_child(u32::try_from(index).unwrap_or(u32::MAX)))
            }
        })
        .filter(|_| {
            !matches!(
                mode,
                ParserMode::JavaScript | ParserMode::Jsx | ParserMode::TypeScript | ParserMode::Tsx
            )
        })
}

fn is_call_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "call_expression" | "call")
}

fn is_member_node(node: Node<'_>, mode: ParserMode) -> bool {
    match mode {
        ParserMode::Rust => matches!(node.kind(), "field_expression" | "index_expression"),
        ParserMode::Python => matches!(node.kind(), "attribute" | "subscript"),
        ParserMode::Go => matches!(node.kind(), "selector_expression" | "index_expression"),
        _ => false,
    }
}

fn is_return_node(node: Node<'_>, mode: ParserMode) -> bool {
    match mode {
        ParserMode::Rust => node.kind() == "return_expression",
        ParserMode::Python | ParserMode::Go => node.kind() == "return_statement",
        _ => false,
    }
}

fn return_value(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("value")
        .or_else(|| node.named_child(0))
}

fn is_if_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "if_expression" | "if_statement")
}

fn condition_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("condition")
        .or_else(|| node.named_child(0))
}

fn call_callee(node: Node<'_>, content: &[u8]) -> Option<String> {
    node.child_by_field_name("function")
        .or_else(|| node.named_child(0))
        .and_then(|item| expression_name(item, content))
}

fn call_callee_deep(node: Node<'_>, content: &[u8]) -> Option<String> {
    if is_call_node(node) {
        return call_callee(node, content);
    }
    let mut stack = vec![node];
    while let Some(item) = stack.pop() {
        if is_call_node(item)
            && let Some(name) = call_callee(item, content)
        {
            return Some(name);
        }
        for index in (0..item.named_child_count()).rev() {
            if let Some(child) = item.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    None
}

fn expression_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    if matches!(
        node.kind(),
        "identifier"
            | "field_identifier"
            | "property_identifier"
            | "type_identifier"
            | "scoped_identifier"
            | "self"
    ) {
        return normalized_text(node, content);
    }
    if matches!(
        node.kind(),
        "parenthesized_expression" | "pointer_expression"
    ) {
        return node
            .named_child(0)
            .and_then(|item| expression_name(item, content));
    }
    if is_call_node(node) {
        return call_callee(node, content);
    }
    let object = ["object", "value", "operand", "scope"]
        .iter()
        .find_map(|field| node.child_by_field_name(field))
        .and_then(|item| expression_name(item, content));
    let property = ["property", "attribute", "field", "name"]
        .iter()
        .find_map(|field| node.child_by_field_name(field))
        .and_then(|item| expression_name(item, content));
    match (object, property) {
        (Some(object), Some(property)) => normalize(&format!("{object}.{property}")),
        (Some(object), None) => Some(object),
        (None, Some(property)) => Some(property),
        (None, None) => normalized_text(node, content).filter(|text| {
            text.len() <= MAX_NAME_BYTES
                && !text.contains(char::is_whitespace)
                && !text.contains(['(', ')', '{', '}', '[', ']', ',', ';'])
        }),
    }
}

fn argument_values(call: Node<'_>, content: &[u8]) -> Vec<String> {
    let arguments = call.child_by_field_name("arguments").or_else(|| {
        (0..call.named_child_count()).find_map(|index| {
            let child = call.named_child(u32::try_from(index).ok()?)?;
            matches!(child.kind(), "arguments" | "argument_list").then_some(child)
        })
    });
    let mut values = arguments.map_or_else(Vec::new, |items| value_names(items, content));
    if let Some(function) = call.child_by_field_name("function")
        && !matches!(
            function.kind(),
            "identifier" | "scoped_identifier" | "scoped_type_identifier"
        )
    {
        values.extend(value_names(function, content));
    }
    values.sort();
    values.dedup();
    values
}

fn value_names(node: Node<'_>, content: &[u8]) -> Vec<String> {
    let mut names = BTreeSet::new();
    let mut stack = vec![node];
    while let Some(item) = stack.pop() {
        if (is_call_node(item) || is_generic_value_node(item))
            && let Some(name) = expression_name(item, content)
        {
            names.insert(name);
        }
        if names.len() >= 64 {
            break;
        }
        for index in (0..item.named_child_count()).rev() {
            if let Some(child) = item.named_child(u32::try_from(index).unwrap_or(u32::MAX)) {
                stack.push(child);
            }
        }
    }
    names.into_iter().collect()
}

fn first_value_name(node: Node<'_>, content: &[u8]) -> Option<String> {
    expression_name(node, content).or_else(|| value_names(node, content).into_iter().next())
}

fn is_generic_value_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier"
            | "field_identifier"
            | "attribute"
            | "subscript"
            | "field_expression"
            | "selector_expression"
            | "index_expression"
    )
}

fn is_transformation(node: Node<'_>, content: &[u8]) -> bool {
    matches!(
        node.kind(),
        "binary_expression" | "interpolation" | "concatenated_string" | "list_comprehension"
    ) || normalized_text(node, content).is_some_and(|text| {
        text.contains("format!(") || text.contains("f\"") || text.contains("fmt.Sprintf(")
    })
}

fn route_call(
    call: Node<'_>,
    content: &[u8],
    callee: &str,
    mode: ParserMode,
) -> Option<(String, String, Option<String>)> {
    let lower = callee.to_ascii_lowercase();
    let leaf = lower.rsplit('.').next()?;
    let is_route = match mode {
        ParserMode::Rust => matches!(leaf, "route" | "service") || is_http_method(leaf),
        ParserMode::Python => {
            matches!(leaf, "route" | "add_url_rule" | "path")
                || (is_http_method(leaf)
                    && lower.rsplit_once('.').is_some_and(|(object, _)| {
                        object.rsplit('.').next().is_some_and(|name| {
                            matches!(name, "app" | "router" | "blueprint" | "api")
                        })
                    }))
        }
        ParserMode::Go => is_http_method(leaf) || matches!(leaf, "handle" | "handlefunc" | "any"),
        _ => false,
    };
    if !is_route {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let route = arguments
        .named_child(0)
        .and_then(|item| string_literal(item, content))?;
    let count = arguments.named_child_count();
    let handler = count.checked_sub(1).and_then(|index| {
        let item = arguments.named_child(u32::try_from(index).ok()?)?;
        let candidate = if mode == ParserMode::Rust && is_call_node(item) {
            item.child_by_field_name("arguments")
                .and_then(|nested| nested.named_child(0))
                .unwrap_or(item)
        } else {
            item
        };
        expression_name(candidate, content)
            .map(|name| name.rsplit('.').next().unwrap_or(&name).to_owned())
    });
    let method = if is_http_method(leaf) {
        leaf.to_ascii_uppercase()
    } else {
        "ANY".into()
    };
    Some((method, route, handler))
}

fn sink_kind(callee: &str, mode: ParserMode) -> Option<&'static str> {
    let lower = callee.to_ascii_lowercase().replace("::", ".");
    let leaf = lower.rsplit('.').next().unwrap_or(lower.as_str());
    match mode {
        ParserMode::Rust => {
            if (lower.contains("command")
                && matches!(leaf, "arg" | "args" | "spawn" | "status" | "output"))
                || lower.contains("std.process.command")
            {
                Some("process-execution")
            } else if lower.starts_with("std.fs.")
                || lower.contains("tokio.fs.")
                || (lower.starts_with("file.") && matches!(leaf, "open" | "create" | "options"))
            {
                Some("filesystem-operation")
            } else if lower.contains("sqlx.query") || lower.contains("query_as") {
                Some("database-access")
            } else if (lower.contains("reqwest") || lower.contains("client."))
                && matches!(leaf, "get" | "post" | "request" | "send")
            {
                Some("network-request")
            } else if leaf == "redirect" || lower.contains("redirect.") {
                Some("redirect")
            } else {
                None
            }
        }
        ParserMode::Python => {
            if lower.starts_with("subprocess.")
                || matches!(lower.as_str(), "os.system" | "os.popen")
            {
                Some("process-execution")
            } else if matches!(leaf, "execute" | "executemany" | "raw") {
                Some("database-access")
            } else if matches!(
                leaf,
                "open"
                    | "unlink"
                    | "remove"
                    | "rename"
                    | "mkdir"
                    | "rmdir"
                    | "read_text"
                    | "write_text"
                    | "read_bytes"
                    | "write_bytes"
            ) {
                Some("filesystem-operation")
            } else if lower.starts_with("requests.")
                || lower.starts_with("httpx.")
                || (lower.contains("client.")
                    && matches!(leaf, "get" | "post" | "request" | "send"))
            {
                Some("network-request")
            } else if leaf.contains("redirect") {
                Some("redirect")
            } else if matches!(leaf, "eval" | "exec" | "__import__" | "import_module")
                || lower == "pickle.loads"
                || lower == "pickle.load"
            {
                Some("dynamic-code-execution")
            } else {
                None
            }
        }
        ParserMode::Go => {
            if lower.contains("exec.command") || lower.contains("os.exec") {
                Some("process-execution")
            } else if matches!(leaf, "query" | "querycontext" | "exec" | "execcontext")
                && (lower.starts_with("db.") || lower.contains("sql"))
            {
                Some("database-access")
            } else if lower.starts_with("os.")
                && matches!(
                    leaf,
                    "open"
                        | "openfile"
                        | "readfile"
                        | "writefile"
                        | "remove"
                        | "removeall"
                        | "rename"
                        | "mkdir"
                        | "mkdirall"
                )
            {
                Some("filesystem-operation")
            } else if lower.starts_with("http.") && matches!(leaf, "get" | "post" | "newrequest")
                || lower.contains("client.") && leaf == "do"
            {
                Some("network-request")
            } else if matches!(leaf, "redirect") {
                Some("redirect")
            } else {
                None
            }
        }
        _ => None,
    }
}

fn operation_kind(callee: &str, mode: ParserMode) -> Option<&'static str> {
    if let Some(kind) = sink_kind(callee, mode) {
        if mode == ParserMode::Python
            && matches!(
                callee.to_ascii_lowercase().as_str(),
                "pickle.load" | "pickle.loads"
            )
        {
            return Some("deserialization");
        }
        return Some(kind);
    }
    let lower = callee.to_ascii_lowercase().replace("::", ".");
    let leaf = lower.rsplit('.').next().unwrap_or(lower.as_str());
    match mode {
        ParserMode::Rust if lower.contains("serde") || lower.contains("bincode") => {
            matches!(leaf, "from_str" | "from_slice" | "deserialize").then_some("deserialization")
        }
        ParserMode::Python
            if matches!(
                leaf,
                "render" | "render_template" | "render_template_string"
            ) =>
        {
            Some("template-render")
        }
        ParserMode::Python if lower.starts_with("pickle.") => Some("deserialization"),
        ParserMode::Go if lower.contains("template.") => Some("template-render"),
        ParserMode::Go
            if (lower.contains("json.") || lower.contains("gob."))
                && matches!(leaf, "decode" | "unmarshal") =>
        {
            Some("deserialization")
        }
        _ => None,
    }
}

fn is_parameterized_database_call(call: Node<'_>, content: &[u8], mode: ParserMode) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    if arguments.named_child_count() < 2 {
        return false;
    }
    let Some(first) = arguments.named_child(0) else {
        return false;
    };
    let constant_query = string_literal(first, content).is_some();
    constant_query
        && matches!(mode, ParserMode::Python | ParserMode::Go)
        && value_names(first, content).is_empty()
}

fn is_request_call(name: &str, mode: ParserMode) -> bool {
    let lower = name.to_ascii_lowercase();
    match mode {
        ParserMode::Rust => {
            (lower.starts_with("req.")
                || lower.starts_with("request.")
                || lower.contains("extract"))
                && ["query", "path", "json", "form", "headers", "cookie"]
                    .iter()
                    .any(|token| lower.contains(token))
        }
        ParserMode::Python => {
            (lower.starts_with("request.") || lower.contains("request."))
                && ["get", "json", "data", "form", "args", "headers", "cookies"]
                    .iter()
                    .any(|token| lower.contains(token))
        }
        ParserMode::Go => {
            ["c.", "ctx.", "context.", "r.", "req.", "request."]
                .iter()
                .any(|prefix| lower.starts_with(prefix))
                && [
                    ".param",
                    ".query",
                    ".formvalue",
                    ".bind",
                    ".decode",
                    ".header.get",
                    ".cookie",
                    ".url",
                ]
                .iter()
                .any(|token| lower.contains(token))
        }
        _ => false,
    }
}

fn is_untrusted_source(name: &str, mode: ParserMode) -> bool {
    let lower = name.to_ascii_lowercase();
    match mode {
        ParserMode::Rust => [
            "request", "req.", "query", "path", "header", "cookie", "form", "json",
        ]
        .iter()
        .any(|token| lower.contains(token)),
        ParserMode::Python => {
            lower.starts_with("request.")
                && [
                    "args", "form", "json", "data", "headers", "cookies", "path", "values",
                ]
                .iter()
                .any(|token| lower.contains(token))
        }
        ParserMode::Go => [
            ".url.query",
            ".form",
            ".header",
            ".cookie",
            ".param",
            ".query",
        ]
        .iter()
        .any(|token| lower.contains(token)),
        _ => false,
    }
}

fn source_kind(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.contains("header") {
        "request-header"
    } else if lower.contains("cookie") {
        "request-cookie"
    } else if lower.contains("body") || lower.contains("form") || lower.contains("json") {
        "request-body"
    } else if lower.contains("url") || lower.contains("query") {
        "request-url"
    } else {
        "request-parameter"
    }
}

fn is_guard_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "auth",
        "login_required",
        "permission",
        "requireuser",
        "session",
        "role",
        "policy",
        "guard",
        "current_user",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn is_sanitizer_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "sanitize",
        "escape",
        "validate",
        "allowlist",
        "safe_join",
        "canonicalize",
        "is_relative_to",
        "strip_prefix",
        "parameterize",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn is_http_method(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "any"
    )
}

fn string_literal(node: Node<'_>, content: &[u8]) -> Option<String> {
    let text = node.utf8_text(content).ok()?.trim();
    let quoted = text
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            text.strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .or_else(|| {
            text.strip_prefix('`')
                .and_then(|value| value.strip_suffix('`'))
        })?;
    normalize(quoted)
}

fn normalized_text(node: Node<'_>, content: &[u8]) -> Option<String> {
    normalize(node.utf8_text(content).ok()?)
}

fn normalize(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return None;
    }
    let mut normalized = String::new();
    for character in trimmed.chars() {
        if normalized.len().saturating_add(character.len_utf8()) > MAX_NAME_BYTES {
            break;
        }
        normalized.push(character);
    }
    (!normalized.is_empty()).then_some(normalized)
}

fn push_fact(facts: &mut Vec<NormalizedFact>, maximum: usize, fact: NormalizedFact) {
    if facts.len() < maximum {
        facts.push(fact);
    }
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
