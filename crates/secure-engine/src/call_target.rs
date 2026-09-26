//! Small, conservative call-target refinements shared by facts and the graph.

use tree_sitter::Node;

const LOCAL_NODE_BUDGET: usize = 4096;
const MODULE_NODE_BUDGET: usize = 16384;

/// Recognize only a function-local const `RegExp` literal whose object never
/// escapes or mutates. An unknown receiver remains an ordinary sink candidate.
/// This models standard JavaScript built-ins, not cross-module monkey-patching.
pub(crate) fn local_regexp_exec(call: Node<'_>, content: &[u8]) -> bool {
    let Some(member) = call.child_by_field_name("function") else {
        return false;
    };
    if member.kind() != "member_expression"
        || member
            .child_by_field_name("property")
            .and_then(|node| node.utf8_text(content).ok())
            != Some("exec")
    {
        return false;
    }
    let Some(receiver) = member
        .child_by_field_name("object")
        .filter(|node| node.kind() == "identifier")
    else {
        return false;
    };
    let Ok(name) = receiver.utf8_text(content) else {
        return false;
    };
    let Some(function) = enclosing_function(call) else {
        return false;
    };
    let Some(body) = function
        .child_by_field_name("body")
        .filter(|node| node.kind() == "statement_block")
    else {
        return false;
    };
    let Some(binding) = direct_const_literal(body, name, call.start_byte(), content) else {
        return false;
    };
    if !all_nodes(function, LOCAL_NODE_BUDGET, |node| {
        if node.has_error() {
            return false;
        }
        if !matches!(
            node.kind(),
            "identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        ) || node.utf8_text(content).ok() != Some(name)
            || node == binding
        {
            return true;
        }
        let Some(member) = node
            .parent()
            .filter(|parent| parent.kind() == "member_expression")
        else {
            return false;
        };
        let Some(usage) = member
            .parent()
            .filter(|parent| parent.kind() == "call_expression")
        else {
            return false;
        };
        member.child_by_field_name("object") == Some(node)
            && member
                .child_by_field_name("property")
                .and_then(|property| property.utf8_text(content).ok())
                == Some("exec")
            && usage.child_by_field_name("function") == Some(member)
            && enclosing_function(usage) == Some(function)
    }) {
        return false;
    }
    let mut root = call;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    // Visible prototype manipulation or dynamic evaluation invalidates the
    // built-in assumption. Budget exhaustion always preserves the candidate.
    all_nodes(root, MODULE_NODE_BUDGET, |node| {
        if node.has_error() || node.kind() == "with_statement" {
            return false;
        }
        if node.utf8_text(content).ok() == Some("RegExp")
            && node.parent().is_some_and(|parent| {
                parent.kind() == "new_expression"
                    && parent.child_by_field_name("constructor") == Some(node)
            })
        {
            return true;
        }
        !matches!(
            node.utf8_text(content).ok(),
            Some(
                "RegExp"
                    | "prototype"
                    | "__proto__"
                    | "eval"
                    | "Function"
                    | "getPrototypeOf"
                    | "setPrototypeOf"
                    | "defineProperty"
                    | "defineProperties"
            )
        )
    })
}

fn direct_const_literal<'tree>(
    body: Node<'tree>,
    name: &str,
    before: usize,
    content: &[u8],
) -> Option<Node<'tree>> {
    let mut cursor = body.walk();
    for declaration in body.named_children(&mut cursor) {
        if declaration.kind() != "lexical_declaration"
            || declaration.end_byte() > before
            || declaration
                .child_by_field_name("kind")
                .and_then(|node| node.utf8_text(content).ok())
                != Some("const")
        {
            continue;
        }
        let mut inner = declaration.walk();
        for variable in declaration.named_children(&mut inner) {
            let Some(binding) = variable
                .child_by_field_name("name")
                .filter(|node| node.kind() == "identifier")
            else {
                continue;
            };
            if binding.utf8_text(content).ok() == Some(name)
                && variable
                    .child_by_field_name("value")
                    .is_some_and(|value| value.kind() == "regex")
            {
                return Some(binding);
            }
        }
    }
    None
}

fn enclosing_function(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "function_declaration"
                | "generator_function_declaration"
                | "generator_function"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn all_nodes(root: Node<'_>, budget: usize, predicate: impl Fn(Node<'_>) -> bool) -> bool {
    let mut cursor = root.walk();
    for _ in 0..budget {
        if !predicate(cursor.node()) {
            return false;
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return true;
            }
        }
    }
    false
}
