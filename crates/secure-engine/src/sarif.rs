use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::{
    ENGINE_VERSION, EVIDENCE_CONTRACT_VERSION, EVIDENCE_SEMANTICS_VERSION, Finding, RuleMetadata,
    ScanReport, SourceLocation, rules,
};

/// Canonical official SARIF 2.1.0 schema URI embedded in exported logs.
pub const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// Converts a complete Secure Engine report into deterministic SARIF 2.1.0.
///
/// The returned document contains repository-relative locations only and no source snippets.
#[must_use]
pub fn sarif_report(report: &ScanReport) -> Value {
    let catalog = rules();
    let indices = catalog
        .iter()
        .enumerate()
        .map(|(index, rule)| (rule.rule_id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let sarif_rules = catalog.iter().map(sarif_rule).collect::<Vec<_>>();
    let results = report
        .findings
        .iter()
        .map(|finding| sarif_result(finding, indices.get(finding.rule_id.as_str()).copied()))
        .collect::<Vec<_>>();
    json!({
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Secure Engine",
                    "semanticVersion": ENGINE_VERSION,
                    "informationUri": "https://github.com/usesecure/secure-engine",
                    "rules": sarif_rules
                }
            },
            "invocations": [{"executionSuccessful": report.scan.complete}],
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}},
            "results": results,
            "properties": {
                "secureSchemaVersion": report.schema_version,
                "secureReportFingerprint": report.report_fingerprint,
                "repositoryName": report.repository.name,
                "analysisComplete": report.scan.complete,
                "secureTaxonomyCatalog": report.taxonomy_catalog,
                "secureEvidenceContractVersion": EVIDENCE_CONTRACT_VERSION,
                "secureEvidenceSemanticsVersion": EVIDENCE_SEMANTICS_VERSION
            }
        }]
    })
}

fn sarif_rule(rule: &RuleMetadata) -> Value {
    json!({
        "id": rule.rule_id,
        "name": rule.rule_id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.invariant},
        "help": {"text": format!("{}\n\nInvariant: {}", rule.title, rule.invariant)},
        "defaultConfiguration": {"level": sarif_level(&rule.severity)},
        "properties": {
            "category": rule.category,
            "severity": rule.severity,
            "confidence": rule.confidence,
            "security-severity": security_score(&rule.severity),
            "taxonomy": rule.taxonomy,
            "primaryCwe": rule.primary_cwe,
            "taxonomyProvenance": rule.taxonomy_provenance
        }
    })
}

fn sarif_result(finding: &Finding, rule_index: Option<usize>) -> Value {
    let sink = finding.sink.as_ref().or_else(|| finding.evidence.last());
    let locations = sink
        .map(|location| vec![sarif_location(location, Some(&finding.title))])
        .unwrap_or_default();
    let thread_locations = finding
        .evidence_path
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let mut location = json!({
                "location": sarif_location(&step.location, Some(&step.kind)),
                "executionOrder": index.saturating_add(1),
                "importance": if index == 0 || index.saturating_add(1) == finding.evidence_path.len() { "essential" } else { "important" },
                "kinds": [step.kind]
            });
            if let Some(semantic) = &step.semantic {
                location["properties"] = json!({"secureEvidenceSemantic": semantic});
            }
            location
        })
        .collect::<Vec<_>>();
    let mut result = json!({
        "ruleId": finding.rule_id,
        "level": sarif_level(&finding.severity),
        "message": {"text": format!("{}: {}", finding.title, finding.invariant)},
        "locations": locations,
        "partialFingerprints": {
            "secureFindingFingerprint/v1": finding.fingerprint
        },
        "fingerprints": {
            "secureFindingFingerprint/v1": finding.fingerprint
        },
        "properties": {
            "findingId": finding.finding_id,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "invariant": finding.invariant,
            "taxonomy": finding.taxonomy,
            "primaryCwe": finding.primary_cwe,
            "taxonomyProvenance": finding.taxonomy_provenance,
            "prerequisites": finding.prerequisites,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "verificationState": finding.verification_state,
            "limitations": finding.limitations
        }
    });
    if !thread_locations.is_empty() {
        result["codeFlows"] = json!([{
            "message": {"text": "Secure Engine deterministic source-to-sink evidence path"},
            "threadFlows": [{"locations": thread_locations}]
        }]);
    }
    if let Some(semantic_fingerprint) = &finding.semantic_fingerprint {
        result["partialFingerprints"]["secureSemanticFingerprint/v1"] = json!(semantic_fingerprint);
        result["fingerprints"]["secureSemanticFingerprint/v1"] = json!(semantic_fingerprint);
        result["properties"]["semanticFingerprint"] = json!(semantic_fingerprint);
    }
    if let Some(contract) = &finding.evidence_contract_v2 {
        result["partialFingerprints"]["secureContractFingerprint/v2"] = json!(contract.fingerprint);
        result["fingerprints"]["secureContractDuplicateFingerprint/v2"] =
            json!(contract.duplicate_fingerprint);
        result["properties"]["evidenceContractV2"] = json!(contract);
    }
    if let Some(index) = rule_index {
        result["ruleIndex"] = json!(index);
    }
    result
}

fn sarif_location(location: &SourceLocation, message: Option<&str>) -> Value {
    let mut value = json!({
        "physicalLocation": {
            "artifactLocation": {
                "uri": uri_from_path(&location.path),
                "uriBaseId": "%SRCROOT%"
            },
            "region": {
                "startLine": location.span.start_line,
                "startColumn": location.span.start_column,
                "endLine": location.span.end_line,
                "endColumn": location.span.end_column,
                "byteOffset": location.span.start_byte,
                "byteLength": location.span.end_byte.saturating_sub(location.span.start_byte)
            }
        }
    });
    if let Some(message) = message {
        value["message"] = json!({"text": message});
    }
    value
}

fn uri_from_path(path: &str) -> String {
    let mut uri = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ignored = write!(uri, "%{byte:02X}");
        }
    }
    uri
}

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

fn security_score(severity: &str) -> &'static str {
    match severity {
        "critical" => "9.5",
        "high" => "8.0",
        "medium" => "5.5",
        "low" => "3.0",
        _ => "0.0",
    }
}
