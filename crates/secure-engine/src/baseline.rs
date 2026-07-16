use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Finding, RepositoryIdentity, SCHEMA_VERSION, ScanReport, SourceLocation};

/// Version identifier for deterministic local finding baselines.
pub const BASELINE_FORMAT: &str = "secure-baseline-v1";
/// Version identifier for deterministic comparison documents.
pub const BASELINE_COMPARISON_FORMAT: &str = "secure-baseline-comparison-v1";

/// Failure while validating or comparing a baseline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaselineError {
    /// The report or baseline is incomplete, malformed, or incompatible.
    Invalid(String),
}

impl fmt::Display for BaselineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid baseline input: {message}"),
        }
    }
}

impl std::error::Error for BaselineError {}

/// Timestamp-independent baseline of deterministic finding fingerprints.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Baseline {
    /// Baseline format identifier.
    pub format: String,
    /// Secure report schema used to create the baseline.
    pub report_schema: String,
    /// Safe repository identity at baseline creation.
    pub repository: RepositoryIdentity,
    /// Stable source report fingerprint.
    pub report_fingerprint: String,
    /// Sorted deterministic finding records.
    pub findings: Vec<BaselineFinding>,
}

/// One finding identity retained in a baseline.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BaselineFinding {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Stable finding fingerprint.
    pub fingerprint: String,
    /// Stable related key derived from rule and sink.
    pub related_key: String,
    /// Exact repository-relative sink.
    pub sink: SourceLocation,
}

/// Deterministic classification of current findings relative to a baseline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BaselineComparison {
    /// Comparison format identifier.
    pub format: String,
    /// Baseline report fingerprint.
    pub baseline_report_fingerprint: String,
    /// Current report fingerprint.
    pub current_report_fingerprint: String,
    /// Findings absent from the baseline.
    pub new: Vec<BaselineChange>,
    /// Findings with the same deterministic fingerprint.
    pub unchanged: Vec<BaselineChange>,
    /// Baseline findings no longer present.
    pub resolved: Vec<BaselineChange>,
    /// Related rule/sink findings whose effective evidence changed.
    pub changed: Vec<BaselineChange>,
}

impl BaselineComparison {
    /// Whether the current scan differs materially from its baseline.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !self.new.is_empty() || !self.resolved.is_empty() || !self.changed.is_empty()
    }
}

/// One auditable baseline comparison item.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BaselineChange {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Exact repository-relative sink.
    pub sink: SourceLocation,
    /// Baseline fingerprint when present.
    pub baseline_fingerprint: Option<String>,
    /// Current fingerprint when present.
    pub current_fingerprint: Option<String>,
}

/// Creates a deterministic baseline from a complete scan report.
///
/// # Errors
///
/// Returns an error when the report is incomplete or incompatible.
pub fn create_baseline(report: &ScanReport) -> Result<Baseline, BaselineError> {
    validate_report(report)?;
    let mut findings = report
        .findings
        .iter()
        .map(baseline_finding)
        .collect::<Result<Vec<_>, _>>()?;
    findings.sort();
    findings.dedup();
    Ok(Baseline {
        format: BASELINE_FORMAT.into(),
        report_schema: report.schema_version.clone(),
        repository: report.repository.clone(),
        report_fingerprint: report.report_fingerprint.clone(),
        findings,
    })
}

/// Compares a compatible baseline with a complete current report.
///
/// # Errors
///
/// Returns an error for malformed or incompatible inputs.
pub fn compare_baseline(
    baseline: &Baseline,
    report: &ScanReport,
) -> Result<BaselineComparison, BaselineError> {
    validate_baseline(baseline)?;
    validate_report(report)?;
    if baseline.report_schema != report.schema_version {
        return Err(BaselineError::Invalid(
            "report schema does not match".into(),
        ));
    }
    if baseline.repository.name != report.repository.name
        || baseline.repository.repository_kind != report.repository.repository_kind
    {
        return Err(BaselineError::Invalid(
            "baseline belongs to a different repository".into(),
        ));
    }

    let baseline_by_fingerprint = baseline
        .findings
        .iter()
        .map(|finding| (finding.fingerprint.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let baseline_by_related = baseline
        .findings
        .iter()
        .map(|finding| (finding.related_key.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let current = report
        .findings
        .iter()
        .map(baseline_finding)
        .collect::<Result<Vec<_>, _>>()?;
    let current_fingerprints = current
        .iter()
        .map(|finding| finding.fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    let current_related = current
        .iter()
        .map(|finding| finding.related_key.as_str())
        .collect::<BTreeSet<_>>();

    let mut new = Vec::new();
    let mut unchanged = Vec::new();
    let mut changed = Vec::new();
    for finding in &current {
        if let Some(previous) = baseline_by_fingerprint.get(finding.fingerprint.as_str()) {
            unchanged.push(change_current(finding, Some(previous)));
        } else if let Some(previous) = baseline_by_related.get(finding.related_key.as_str()) {
            changed.push(change_current(finding, Some(previous)));
        } else {
            new.push(change_current(finding, None));
        }
    }
    let mut resolved = baseline
        .findings
        .iter()
        .filter(|finding| {
            !current_fingerprints.contains(finding.fingerprint.as_str())
                && !current_related.contains(finding.related_key.as_str())
        })
        .map(change_resolved)
        .collect::<Vec<_>>();
    for items in [&mut new, &mut unchanged, &mut resolved, &mut changed] {
        items.sort();
        items.dedup();
    }
    Ok(BaselineComparison {
        format: BASELINE_COMPARISON_FORMAT.into(),
        baseline_report_fingerprint: baseline.report_fingerprint.clone(),
        current_report_fingerprint: report.report_fingerprint.clone(),
        new,
        unchanged,
        resolved,
        changed,
    })
}

/// Validates a deserialized baseline before use.
///
/// # Errors
///
/// Returns an error when identifiers, fingerprints, ordering, or locations are invalid.
pub fn validate_baseline(baseline: &Baseline) -> Result<(), BaselineError> {
    if baseline.format != BASELINE_FORMAT || baseline.report_schema != SCHEMA_VERSION {
        return Err(BaselineError::Invalid(
            "unsupported format or report schema".into(),
        ));
    }
    if !fingerprint_is_valid(&baseline.report_fingerprint)
        || !fingerprint_is_valid(&baseline.repository.content_fingerprint)
        || !fingerprint_is_valid(&baseline.repository.identity_fingerprint)
    {
        return Err(BaselineError::Invalid(
            "invalid report or repository fingerprint".into(),
        ));
    }
    if baseline.findings.windows(2).any(|pair| pair[0] >= pair[1])
        || baseline.findings.iter().any(|finding| {
            finding.rule_id.is_empty()
                || !fingerprint_is_valid(&finding.fingerprint)
                || !fingerprint_is_valid(&finding.related_key)
                || !location_is_safe(&finding.sink)
        })
    {
        return Err(BaselineError::Invalid(
            "findings must be unique, sorted, and structurally valid".into(),
        ));
    }
    Ok(())
}

fn validate_report(report: &ScanReport) -> Result<(), BaselineError> {
    if report.schema_version != SCHEMA_VERSION || !report.scan.complete {
        return Err(BaselineError::Invalid(
            "a complete secure-json-v1 report is required".into(),
        ));
    }
    if !fingerprint_is_valid(&report.report_fingerprint) {
        return Err(BaselineError::Invalid(
            "report fingerprint is invalid".into(),
        ));
    }
    Ok(())
}

fn baseline_finding(finding: &Finding) -> Result<BaselineFinding, BaselineError> {
    let sink = finding
        .sink
        .clone()
        .or_else(|| finding.evidence.last().cloned())
        .ok_or_else(|| BaselineError::Invalid("finding has no sink evidence".into()))?;
    if !location_is_safe(&sink) || !fingerprint_is_valid(&finding.fingerprint) {
        return Err(BaselineError::Invalid("finding evidence is invalid".into()));
    }
    Ok(BaselineFinding {
        rule_id: finding.rule_id.clone(),
        related_key: related_key(&finding.rule_id, &sink),
        fingerprint: finding.fingerprint.clone(),
        sink,
    })
}

fn related_key(rule_id: &str, sink: &SourceLocation) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [
        rule_id.as_bytes(),
        sink.path.as_bytes(),
        &sink.span.start_byte.to_le_bytes(),
    ] {
        hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(value);
    }
    hasher.finalize().to_hex().to_string()
}

fn change_current(
    current: &BaselineFinding,
    baseline: Option<&&BaselineFinding>,
) -> BaselineChange {
    BaselineChange {
        rule_id: current.rule_id.clone(),
        sink: current.sink.clone(),
        baseline_fingerprint: baseline.map(|finding| finding.fingerprint.clone()),
        current_fingerprint: Some(current.fingerprint.clone()),
    }
}

fn change_resolved(baseline: &BaselineFinding) -> BaselineChange {
    BaselineChange {
        rule_id: baseline.rule_id.clone(),
        sink: baseline.sink.clone(),
        baseline_fingerprint: Some(baseline.fingerprint.clone()),
        current_fingerprint: None,
    }
}

fn location_is_safe(location: &SourceLocation) -> bool {
    !location.path.is_empty()
        && !location.path.starts_with('/')
        && !location.path.contains('\\')
        && !location.path.split('/').any(|component| component == "..")
        && location.span.start_byte <= location.span.end_byte
}

fn fingerprint_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
