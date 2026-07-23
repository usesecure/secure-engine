use crate::{AuthorizationKind, EvidenceSemantic, EvidenceSemanticRole};

pub(crate) const POLICY_COMMAND: &str = "command-control-data-separation";
pub(crate) const POLICY_SQL: &str = "sql-control-data-separation";
pub(crate) const POLICY_FILESYSTEM: &str = "filesystem-path-confinement";
pub(crate) const POLICY_OUTBOUND: &str = "outbound-destination-policy";
pub(crate) const POLICY_REDIRECT: &str = "redirect-destination-policy";
pub(crate) const POLICY_CODE: &str = "dynamic-code-control-data-separation";
pub(crate) const POLICY_EXACT_ALLOWLIST: &str = "exact-value-allowlist";

pub(crate) fn for_record(
    kind: &str,
    name: Option<&str>,
    callee: Option<&str>,
) -> Option<EvidenceSemantic> {
    let normalized = name.or(callee).unwrap_or_default();
    match kind {
        "source" | "handler" => Some(semantic(
            EvidenceSemanticRole::UntrustedSource,
            if kind == "handler" {
                "untrusted.handler-entry"
            } else {
                source_identity(normalized)
            },
            None,
            None,
            "proven",
        )),
        "assignment" | "alias" | "transformation" | "argument" | "return" | "call" => {
            Some(semantic(
                EvidenceSemanticRole::Transformation,
                transformation_identity(kind, normalized),
                None,
                None,
                "proven",
            ))
        }
        "guard" => {
            let authorization = authorization_kind(normalized);
            Some(semantic(
                if authorization.is_some() {
                    EvidenceSemanticRole::AuthorizationCheck
                } else {
                    EvidenceSemanticRole::Guard
                },
                guard_identity(normalized),
                guard_policy(normalized),
                authorization,
                "proven",
            ))
        }
        "sanitizer" => Some(semantic(
            EvidenceSemanticRole::Sanitizer,
            sanitizer_identity(normalized),
            sanitizer_policy(normalized),
            None,
            "proven",
        )),
        "sink" => Some(semantic(
            EvidenceSemanticRole::SensitiveSink,
            sink_identity(normalized),
            None,
            None,
            "proven",
        )),
        _ => None,
    }
}

pub(crate) fn authorization_kind(value: &str) -> Option<AuthorizationKind> {
    let lower = compact(value);
    if lower.contains("tenant") || lower.contains("organization") || lower.contains("workspace") {
        return Some(AuthorizationKind::Tenant);
    }
    if lower.contains("owner") || lower.contains("membership") || lower.contains("member") {
        return Some(AuthorizationKind::Ownership);
    }
    if lower.contains("role")
        || lower.contains("permission")
        || lower.contains("scope")
        || lower.contains("capability")
    {
        return Some(AuthorizationKind::Role);
    }
    if lower.contains("authoriz")
        || lower.contains("policy")
        || lower.contains("canaccess")
        || lower.contains("allowed")
        || lower.contains("enforce")
    {
        return Some(AuthorizationKind::General);
    }
    if lower.contains("authentic")
        || lower.contains("session")
        || lower.contains("login")
        || lower.contains("requireuser")
        || lower == "auth"
    {
        return Some(AuthorizationKind::Authentication);
    }
    None
}

pub(crate) fn is_operation_authorization(value: &str) -> bool {
    authorization_kind(value).is_some_and(|kind| kind != AuthorizationKind::Authentication)
}

pub(crate) fn sanitizer_policy(value: &str) -> Option<&'static str> {
    let lower = compact(value);
    if lower.contains("command") || lower.contains("shell") {
        return Some(POLICY_COMMAND);
    }
    if lower.contains("sql") || lower.contains("query") || lower.contains("parameter") {
        return Some(POLICY_SQL);
    }
    if lower.contains("path") || lower.contains("file") || lower.contains("relative") {
        return Some(POLICY_FILESYSTEM);
    }
    if lower.contains("redirect") || lower.contains("returnurl") || lower.contains("callback") {
        return Some(POLICY_REDIRECT);
    }
    if lower.contains("url") || lower.contains("host") || lower.contains("origin") {
        return Some(POLICY_OUTBOUND);
    }
    if lower.contains("code") || lower.contains("expression") {
        return Some(POLICY_CODE);
    }
    None
}

fn semantic(
    role: EvidenceSemanticRole,
    identity: &str,
    policy: Option<&str>,
    authorization: Option<AuthorizationKind>,
    certainty: &str,
) -> EvidenceSemantic {
    EvidenceSemantic {
        semantics_version: Some(crate::EVIDENCE_SEMANTICS_VERSION.into()),
        role,
        identity: identity.into(),
        policy: policy.map(str::to_owned),
        authorization,
        certainty: certainty.into(),
    }
}

fn source_identity(value: &str) -> &'static str {
    let lower = compact(value);
    if lower.contains("formdata") {
        "untrusted.form-data-value"
    } else if lower.contains("httpbody") || lower.contains("requestbody") {
        "untrusted.http-body-field"
    } else if lower.contains("header") {
        "untrusted.http-header-value"
    } else if lower.contains("cookie") {
        "untrusted.http-cookie-value"
    } else if lower.contains("query") || lower.contains("requesturl") {
        "untrusted.http-query-value"
    } else if lower.contains("serveraction") {
        "untrusted.server-action-parameter"
    } else if lower.contains("environment") {
        "untrusted.environment-value"
    } else {
        "untrusted.request-value"
    }
}

fn transformation_identity(kind: &str, value: &str) -> &'static str {
    let lower = compact(value);
    if kind == "alias" {
        "transformation.alias"
    } else if lower.ends_with("join") {
        "transformation.path-base-join"
    } else if lower.ends_with("resolve") || lower.ends_with("normalize") {
        "transformation.path-lexical-normalization"
    } else if lower.ends_with("realpath") || lower.ends_with("canonicalize") {
        "transformation.path-canonicalization"
    } else if lower.ends_with("relative") {
        "transformation.path-relative"
    } else if lower.contains("decode") {
        "transformation.decoding"
    } else if kind == "argument" {
        "transformation.argument"
    } else if kind == "return" {
        "transformation.return"
    } else if kind == "call" {
        "transformation.local-call"
    } else {
        "transformation.value"
    }
}

fn guard_identity(value: &str) -> &'static str {
    if let Some(kind) = authorization_kind(value) {
        return match kind {
            AuthorizationKind::Authentication => "guard.authentication",
            AuthorizationKind::Role => "guard.authorization.role",
            AuthorizationKind::Ownership => "guard.authorization.ownership",
            AuthorizationKind::Tenant => "guard.authorization.tenant",
            AuthorizationKind::General => "guard.authorization.general",
        };
    }
    match guard_policy(value) {
        Some(POLICY_EXACT_ALLOWLIST) => "guard.exact-value-allowlist",
        Some(POLICY_FILESYSTEM) => "guard.filesystem-confinement",
        Some(POLICY_OUTBOUND) => "guard.outbound-destination",
        Some(POLICY_REDIRECT) => "guard.redirect-destination",
        _ => "guard.ambiguous",
    }
}

fn guard_policy(value: &str) -> Option<&'static str> {
    match value {
        POLICY_FILESYSTEM => Some(POLICY_FILESYSTEM),
        POLICY_OUTBOUND => Some(POLICY_OUTBOUND),
        POLICY_REDIRECT => Some(POLICY_REDIRECT),
        POLICY_COMMAND => Some(POLICY_COMMAND),
        POLICY_SQL => Some(POLICY_SQL),
        POLICY_CODE => Some(POLICY_CODE),
        POLICY_EXACT_ALLOWLIST => Some(POLICY_EXACT_ALLOWLIST),
        _ => None,
    }
}

fn sanitizer_identity(value: &str) -> &'static str {
    match sanitizer_policy(value) {
        Some(POLICY_COMMAND) => "sanitizer.command",
        Some(POLICY_SQL) => "sanitizer.sql",
        Some(POLICY_FILESYSTEM) => "sanitizer.filesystem",
        Some(POLICY_OUTBOUND) => "sanitizer.outbound-destination",
        Some(POLICY_REDIRECT) => "sanitizer.redirect-destination",
        Some(POLICY_CODE) => "sanitizer.dynamic-code",
        _ => "sanitizer.unresolved",
    }
}

fn sink_identity(value: &str) -> &'static str {
    match value {
        "process-execution" | "process-argument-execution" => "sink.process-execution",
        "database-access" | "database-parameterized" => "sink.database-query",
        "filesystem-operation" => "sink.filesystem-operation",
        "network-request" => "sink.outbound-request",
        "redirect" => "sink.redirect",
        "dynamic-code-execution" => "sink.dynamic-code-execution",
        "sensitive-mutation" => "sink.sensitive-mutation",
        "cli-option-injection" => "sink.cli-option-parser",
        "prototype-mutation" => "sink.prototype-mutation",
        _ => "sink.sensitive-operation",
    }
}

fn compact(value: &str) -> String {
    value.to_ascii_lowercase().replace(['-', '_', '.', ':'], "")
}
