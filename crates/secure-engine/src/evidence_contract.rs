use serde::{Deserialize, Serialize};

use crate::{
    EvidenceContractPathStepV2, EvidenceContractRoleV2, EvidenceContractV2, EvidenceEffectV2,
    EvidencePathStep, EvidenceSemanticRole, EvidenceSinkKindV2, EvidenceSourceKindV2,
    TaxonomyCoordinates,
};

/// Frozen public evidence-contract version implemented by Secure Engine.
pub const EVIDENCE_CONTRACT_VERSION: &str = "2.0.0";
/// Explicit version of Secure Engine's contract-v2 semantic projection.
pub const EVIDENCE_SEMANTICS_VERSION: &str = "secure-evidence-semantics-v2";

/// Result of comparing one finding with one public contract-v2 expectation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceContractOutcome {
    /// Taxonomy, endpoints, path and barrier semantics match exactly.
    Exact,
    /// Required semantics match but declared uncertainty prevents detection credit.
    Partial,
    /// One or more required semantic fields do not match.
    NoMatch,
}

/// One synthetic public conformance-test document.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct EvidenceContractTestDocument {
    pub schema_version: String,
    pub contract_version: String,
    pub synthetic_reports_only: bool,
    pub tests: Vec<EvidenceContractTest>,
}

/// One canonical or near-miss contract test.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct EvidenceContractTest {
    pub test_id: String,
    pub expectation: ContractExpectation,
    pub finding: ContractFinding,
    pub expected: EvidenceContractOutcome,
}

/// Tool-neutral expected evidence path.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct ContractExpectation {
    pub expectation_id: String,
    pub taxonomy_version: String,
    pub category_id: String,
    pub invariant_id: String,
    pub primary_cwe: String,
    pub path: Vec<ContractPathStep>,
}

/// Tool-neutral finding used by the public synthetic conformance vectors.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct ContractFinding {
    pub taxonomy_version: String,
    pub category_id: String,
    pub invariant_id: String,
    pub path: Vec<ContractPathStep>,
    pub connected_edges: Vec<bool>,
    pub effective_barriers: Vec<String>,
    pub unresolved_call: bool,
    pub uncertain: bool,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub tool_identity: String,
    #[serde(default)]
    pub prose: String,
}

/// One public contract path step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct ContractPathStep {
    pub role: String,
    pub effect: String,
    pub source_kind: Option<String>,
    pub sink_kind: Option<String>,
    pub span: ContractSpan,
    pub summarizable: bool,
}

/// One-based source span used by the public contract vectors.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct ContractSpan {
    pub file: String,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

/// Applies every normative public contract-v2 matching rule to one synthetic vector.
#[must_use]
pub fn evaluate_contract_v2(
    expectation: &ContractExpectation,
    finding: &ContractFinding,
) -> EvidenceContractOutcome {
    if expectation.taxonomy_version != finding.taxonomy_version
        || expectation.category_id != finding.category_id
        || expectation.invariant_id != finding.invariant_id
        || finding.path.len() < 2
        || finding.connected_edges.len().saturating_add(1) != finding.path.len()
        || finding.connected_edges.iter().any(|connected| !connected)
        || !finding.effective_barriers.is_empty()
        || finding.path.first().map(|step| step.role.as_str()) != Some("source")
        || finding.path.last().map(|step| step.role.as_str()) != Some("sink")
        || !paths_match(&expectation.path, &finding.path)
    {
        return EvidenceContractOutcome::NoMatch;
    }
    if finding.unresolved_call || finding.uncertain {
        EvidenceContractOutcome::Partial
    } else {
        EvidenceContractOutcome::Exact
    }
}

fn paths_match(expected: &[ContractPathStep], observed: &[ContractPathStep]) -> bool {
    let mut expected_index = 0_usize;
    let mut observed_index = 0_usize;
    while expected_index < expected.len() && observed_index < observed.len() {
        let expected_step = &expected[expected_index];
        let observed_step = &observed[observed_index];
        if steps_match(expected_step, observed_step) {
            expected_index = expected_index.saturating_add(1);
            observed_index = observed_index.saturating_add(1);
        } else if expected_step.summarizable {
            expected_index = expected_index.saturating_add(1);
        } else if observed_step.summarizable {
            observed_index = observed_index.saturating_add(1);
        } else {
            return false;
        }
    }
    expected[expected_index..]
        .iter()
        .all(|step| step.summarizable)
        && observed[observed_index..]
            .iter()
            .all(|step| step.summarizable)
}

fn steps_match(expected: &ContractPathStep, observed: &ContractPathStep) -> bool {
    expected.role == observed.role
        && expected.effect == observed.effect
        && expected.source_kind == observed.source_kind
        && expected.sink_kind == observed.sink_kind
        && spans_equivalent(&expected.span, &observed.span)
}

fn spans_equivalent(expected: &ContractSpan, observed: &ContractSpan) -> bool {
    let Some(expected_file) = normalize_contract_path(&expected.file) else {
        return false;
    };
    let Some(observed_file) = normalize_contract_path(&observed.file) else {
        return false;
    };
    if expected_file != observed_file {
        return false;
    }
    if expected == observed {
        return true;
    }
    (span_contains(expected, observed) || span_contains(observed, expected))
        && expected
            .end_line
            .max(observed.end_line)
            .saturating_sub(expected.start_line.min(observed.start_line))
            .saturating_add(1)
            <= 3
}

fn span_contains(outer: &ContractSpan, inner: &ContractSpan) -> bool {
    (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column)
        && (outer.end_line, outer.end_column) >= (inner.end_line, inner.end_column)
}

fn normalize_contract_path(path: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    if path.is_empty() || path.starts_with('/') || path.contains('\0') {
        return None;
    }
    let mut normalized = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return None,
            value => normalized.push(value),
        }
    }
    (!normalized.is_empty()).then(|| normalized.join("/"))
}

pub(crate) fn finding_contract_v2(
    taxonomy: Option<&TaxonomyCoordinates>,
    rule_id: &str,
    steps: &[EvidencePathStep],
) -> Option<EvidenceContractV2> {
    let taxonomy = taxonomy?;
    let mut path = steps
        .iter()
        .filter_map(|step| contract_step(rule_id, step))
        .collect::<Vec<_>>();
    if path.first().map(|step| &step.role) != Some(&EvidenceContractRoleV2::Source)
        || path.last().map(|step| &step.role) != Some(&EvidenceContractRoleV2::Sink)
    {
        return None;
    }
    compress_redundant_propagation(&mut path);
    let connected_edges = vec![true; path.len().saturating_sub(1)];
    let uncertain = path
        .iter()
        .any(|step| step.effect == EvidenceEffectV2::Uncertain);
    let fingerprint = semantic_fingerprint(taxonomy, &path, uncertain);
    let duplicate_fingerprint = duplicate_fingerprint(taxonomy, &path, uncertain);
    Some(EvidenceContractV2 {
        contract_version: EVIDENCE_CONTRACT_VERSION.into(),
        semantics_version: EVIDENCE_SEMANTICS_VERSION.into(),
        path,
        connected_edges,
        effective_barriers: Vec::new(),
        unresolved_call: false,
        uncertain,
        fingerprint,
        duplicate_fingerprint,
    })
}

fn contract_step(rule_id: &str, step: &EvidencePathStep) -> Option<EvidenceContractPathStepV2> {
    let semantic = step.semantic.as_ref()?;
    let (role, effect, summarizable) = match semantic.role {
        EvidenceSemanticRole::UntrustedSource => (
            EvidenceContractRoleV2::Source,
            EvidenceEffectV2::PreservesInfluence,
            false,
        ),
        EvidenceSemanticRole::Transformation => (
            EvidenceContractRoleV2::Propagation,
            if semantic.certainty == "proven" {
                EvidenceEffectV2::PreservesInfluence
            } else {
                EvidenceEffectV2::Uncertain
            },
            true,
        ),
        EvidenceSemanticRole::Guard => (
            EvidenceContractRoleV2::Guard,
            EvidenceEffectV2::BlocksInfluence,
            false,
        ),
        EvidenceSemanticRole::Sanitizer => (
            EvidenceContractRoleV2::Sanitizer,
            EvidenceEffectV2::RestrictsValue,
            false,
        ),
        EvidenceSemanticRole::AuthorizationCheck => (
            EvidenceContractRoleV2::Authorization,
            EvidenceEffectV2::AuthorizesOperation,
            false,
        ),
        EvidenceSemanticRole::SensitiveSink => (
            EvidenceContractRoleV2::Sink,
            EvidenceEffectV2::PreservesInfluence,
            false,
        ),
    };
    let source_kind =
        (role == EvidenceContractRoleV2::Source).then(|| source_kind(rule_id, &semantic.identity));
    let sink_kind = (role == EvidenceContractRoleV2::Sink).then(|| sink_kind(&semantic.identity));
    Some(EvidenceContractPathStepV2 {
        role,
        effect,
        source_kind,
        sink_kind,
        span: step.location.clone(),
        summarizable,
    })
}

fn source_kind(rule_id: &str, identity: &str) -> EvidenceSourceKindV2 {
    if rule_id == "SE1007" {
        EvidenceSourceKindV2::ProtectedResourceId
    } else if identity.contains("form-data") || identity.contains("server-action") {
        EvidenceSourceKindV2::FormDataValue
    } else if identity.contains("body")
        || identity.contains("header")
        || identity.contains("cookie")
    {
        EvidenceSourceKindV2::HttpBodyField
    } else {
        EvidenceSourceKindV2::HttpQueryValue
    }
}

fn sink_kind(identity: &str) -> EvidenceSinkKindV2 {
    match identity {
        "sink.process-execution" => EvidenceSinkKindV2::OsCommandExecution,
        "sink.database-query" => EvidenceSinkKindV2::SqlQueryExecution,
        "sink.filesystem-operation" => EvidenceSinkKindV2::FilesystemRead,
        "sink.outbound-request" => EvidenceSinkKindV2::OutboundRequest,
        "sink.redirect" => EvidenceSinkKindV2::RedirectResponse,
        "sink.dynamic-code-execution" => EvidenceSinkKindV2::DynamicCodeEvaluation,
        _ => EvidenceSinkKindV2::ProtectedRecordMutation,
    }
}

fn compress_redundant_propagation(path: &mut Vec<EvidenceContractPathStepV2>) {
    let mut previous: Option<(EvidenceContractRoleV2, crate::SourceLocation)> = None;
    path.retain(|step| {
        let duplicate = step.summarizable
            && previous
                .as_ref()
                .is_some_and(|(role, span)| *role == step.role && *span == step.span);
        previous = Some((step.role.clone(), step.span.clone()));
        !duplicate
    });
}

fn semantic_fingerprint(
    taxonomy: &TaxonomyCoordinates,
    path: &[EvidenceContractPathStepV2],
    uncertain: bool,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hash(&mut hasher, b"secure-contract-v2-semantic-fingerprint-v1");
    hash(&mut hasher, taxonomy.taxonomy_version.as_bytes());
    hash(&mut hasher, taxonomy.category_id.as_bytes());
    hash(&mut hasher, taxonomy.invariant_id.as_bytes());
    hash(&mut hasher, &[u8::from(uncertain)]);
    for step in path {
        hash(&mut hasher, format!("{:?}", step.role).as_bytes());
        hash(&mut hasher, format!("{:?}", step.effect).as_bytes());
        hash(&mut hasher, format!("{:?}", step.source_kind).as_bytes());
        hash(&mut hasher, format!("{:?}", step.sink_kind).as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn duplicate_fingerprint(
    taxonomy: &TaxonomyCoordinates,
    path: &[EvidenceContractPathStepV2],
    uncertain: bool,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hash(&mut hasher, b"secure-contract-v2-duplicate-fingerprint-v1");
    hash(
        &mut hasher,
        semantic_fingerprint(taxonomy, path, uncertain).as_bytes(),
    );
    for step in path {
        hash(&mut hasher, step.span.path.as_bytes());
        for value in [
            step.span.span.start_byte,
            step.span.span.end_byte,
            u64::from(step.span.span.start_line),
            u64::from(step.span.span.start_column),
            u64::from(step.span.span.end_line),
            u64::from(step.span.span.end_column),
        ] {
            hash(&mut hasher, &value.to_le_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn hash(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}
