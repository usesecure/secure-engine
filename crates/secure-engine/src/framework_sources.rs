/// Framework-neutral classification of one externally controlled JavaScript/TypeScript value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameworkSourceKind {
    FormDataValue,
    HttpBodyField,
    HttpQueryValue,
    HttpHeaderValue,
    HttpCookieValue,
}

impl FrameworkSourceKind {
    pub(crate) const fn record_name(self) -> &'static str {
        match self {
            Self::FormDataValue => "form-data-value",
            Self::HttpBodyField => "http-body-field",
            Self::HttpQueryValue => "http-query-value",
            Self::HttpHeaderValue => "http-header-value",
            Self::HttpCookieValue => "http-cookie-value",
        }
    }
}

/// Classifies a collection/member access only when its root is an exposed handler parameter.
pub(crate) fn classify_member_access(
    name: &str,
    parameters: &[String],
    exposed: bool,
) -> Option<FrameworkSourceKind> {
    if !exposed || !root_is_parameter(name, parameters) {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if contains_segment(&lower, "headers") || contains_segment(&lower, "header") {
        Some(FrameworkSourceKind::HttpHeaderValue)
    } else if contains_segment(&lower, "cookies") || contains_segment(&lower, "cookie") {
        Some(FrameworkSourceKind::HttpCookieValue)
    } else if contains_segment(&lower, "body") {
        Some(FrameworkSourceKind::HttpBodyField)
    } else if contains_segment(&lower, "query")
        || contains_segment(&lower, "params")
        || contains_segment(&lower, "searchparams")
        || contains_segment(&lower, "url")
    {
        Some(FrameworkSourceKind::HttpQueryValue)
    } else {
        None
    }
}

/// Classifies request accessors, including `FormData` and `URLSearchParams`, independently of names.
pub(crate) fn classify_call(
    callee: &str,
    expression: &str,
    inputs: &[String],
    parameters: &[String],
    exposed: bool,
    server_action: bool,
) -> Option<FrameworkSourceKind> {
    if !exposed {
        return None;
    }
    let lower_callee = callee.to_ascii_lowercase();
    let lower_expression = expression
        .to_ascii_lowercase()
        .replace(char::is_whitespace, "");
    let rooted = inputs
        .iter()
        .any(|input| root_is_parameter(input, parameters))
        || root_is_parameter(callee, parameters);
    if !rooted {
        return None;
    }
    if (server_action && terminal_segment(&lower_callee) == "get")
        || lower_callee.contains("formdata")
        || lower_expression.contains(".formdata(")
    {
        return Some(FrameworkSourceKind::FormDataValue);
    }
    if lower_expression.contains(".searchparams.get(") || lower_callee.contains("searchparams.get")
    {
        return Some(FrameworkSourceKind::HttpQueryValue);
    }
    if terminal_segment(&lower_callee) == "json" {
        return Some(FrameworkSourceKind::HttpBodyField);
    }
    if matches!(terminal_segment(&lower_callee), "header" | "get") {
        return Some(FrameworkSourceKind::HttpHeaderValue);
    }
    if terminal_segment(&lower_callee) == "cookie" {
        return Some(FrameworkSourceKind::HttpCookieValue);
    }
    None
}

fn terminal_segment(value: &str) -> &str {
    value.rsplit('.').next().unwrap_or(value)
}

fn root_is_parameter(name: &str, parameters: &[String]) -> bool {
    let root = name
        .split(['.', '[', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(name);
    parameters.iter().any(|parameter| parameter == root)
}

fn contains_segment(value: &str, segment: &str) -> bool {
    value
        .split(['.', '[', ']'])
        .any(|part| part.trim_matches(['\'', '"']) == segment)
}
