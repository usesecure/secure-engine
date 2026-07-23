//! Phase 6.5 neutral-taxonomy, dominance, helper, and precision regression coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use secure_engine::{
    CancellationToken, SECURE_JSON_V1_SCHEMA, ScanReport, ScanRequest, TAXONOMY_CONTENT_HASH,
    TAXONOMY_DOCUMENT_SHA256, TAXONOMY_METHODOLOGY_SHA256, TAXONOMY_NAME, TAXONOMY_SCHEMA_SHA256,
    TAXONOMY_SOURCE_COMMIT, TAXONOMY_VERSION, create_baseline, rules, sarif_report,
    scan_repository, taxonomy_descriptor, taxonomy_mappings, validate_baseline,
};

fn workspace_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn precision_request() -> ScanRequest {
    let mut request = ScanRequest::new(workspace_path("fixtures/phase65-precision"));
    request.configuration.parse_cache_enabled = false;
    request
}

fn precision_report() -> Result<ScanReport, secure_engine::ScanError> {
    scan_repository(&precision_request(), &CancellationToken::new(), |_| {})
}

fn finding_locations(report: &ScanReport, rule_id: &str) -> BTreeSet<(String, u32)> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule_id)
        .filter_map(|finding| {
            finding
                .sink
                .as_ref()
                .map(|sink| (sink.path.clone(), sink.span.start_line))
        })
        .collect()
}

#[test]
fn vulnerable_direct_helper_and_non_dominating_flows_are_detected()
-> Result<(), Box<dyn std::error::Error>> {
    let report = precision_report()?;
    assert_eq!(
        finding_locations(&report, "SE1001"),
        BTreeSet::from([
            ("command.ts".into(), 4),
            ("command.ts".into(), 12),
            ("command.ts".into(), 23),
        ])
    );
    assert_eq!(
        finding_locations(&report, "SE1003"),
        BTreeSet::from([
            ("filesystem.ts".into(), 7),
            ("filesystem.ts".into(), 15),
            ("filesystem.ts".into(), 35),
        ])
    );
    assert_eq!(
        finding_locations(&report, "SE1004"),
        BTreeSet::from([
            ("outbound.ts".into(), 5),
            ("outbound.ts".into(), 13),
            ("outbound.ts".into(), 33),
            ("outbound.ts".into(), 41),
        ])
    );
    assert_eq!(
        finding_locations(&report, "SE1005"),
        BTreeSet::from([
            ("redirect.ts".into(), 7),
            ("redirect.ts".into(), 15),
            ("redirect.ts".into(), 39),
            ("redirect.ts".into(), 44),
        ])
    );
    assert_eq!(
        finding_locations(&report, "SE1007"),
        BTreeSet::from([
            ("authorization.ts".into(), 9),
            ("authorization.ts".into(), 13),
            ("authorization.ts".into(), 44),
            ("authorization.ts".into(), 49),
        ])
    );
    Ok(())
}

#[test]
fn dominant_policies_remove_only_the_intended_false_positives()
-> Result<(), Box<dyn std::error::Error>> {
    let report = precision_report()?;
    let active = report
        .findings
        .iter()
        .filter_map(|finding| {
            finding
                .sink
                .as_ref()
                .map(|sink| (sink.path.as_str(), sink.span.start_line))
        })
        .collect::<BTreeSet<_>>();
    for safe in [
        ("command.ts", 16),
        ("filesystem.ts", 27),
        ("outbound.ts", 25),
        ("redirect.ts", 26),
        ("redirect.ts", 31),
        ("authorization.ts", 28),
        ("authorization.ts", 32),
    ] {
        assert!(!active.contains(&safe), "safe control emitted at {safe:?}");
    }
    assert!(report.limitations.iter().any(|limitation| {
        limitation.code == "process-argument-semantics-not-modeled"
            && limitation.message.contains("shell processing disabled")
            && limitation.message.contains("argument injection")
    }));
    Ok(())
}

#[test]
fn unresolved_variants_are_explicitly_bounded_without_false_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let report = precision_report()?;
    let unresolved_files = report
        .files
        .iter()
        .filter(|file| file.path.contains("-unresolved."))
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(unresolved_files.len(), 5);
    assert!(report.findings.iter().all(|finding| {
        finding
            .sink
            .as_ref()
            .is_none_or(|sink| !sink.path.contains("-unresolved."))
    }));
    assert!(report.limitations.iter().any(|limitation| {
        limitation.code == "dynamic-resolution-limited"
            && limitation.message.contains("unresolved calls")
    }));
    Ok(())
}

#[test]
fn frozen_taxonomy_maps_every_rule_and_finding_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = taxonomy_descriptor();
    assert_eq!(descriptor.taxonomy_name, TAXONOMY_NAME);
    assert_eq!(descriptor.taxonomy_version, TAXONOMY_VERSION);
    assert_eq!(descriptor.source_commit, TAXONOMY_SOURCE_COMMIT);
    assert_eq!(descriptor.schema_sha256, TAXONOMY_SCHEMA_SHA256);
    assert_eq!(descriptor.taxonomy_sha256, TAXONOMY_DOCUMENT_SHA256);
    assert_eq!(descriptor.methodology_sha256, TAXONOMY_METHODOLOGY_SHA256);
    assert_eq!(descriptor.content_hash, TAXONOMY_CONTENT_HASH);

    let mappings = taxonomy_mappings();
    assert_eq!(mappings.len(), 7);
    let rule_catalog = rules();
    assert_eq!(rule_catalog.len(), 10);
    let mappings_by_rule = mappings
        .iter()
        .map(|mapping| (mapping.rule_id.as_str(), mapping))
        .collect::<BTreeMap<_, _>>();
    for mapping in &mappings {
        let rule = rule_catalog
            .iter()
            .find(|rule| rule.rule_id == mapping.rule_id)
            .ok_or("taxonomy mapping referenced an unknown rule")?;
        assert_eq!(rule.taxonomy.as_ref(), Some(&mapping.taxonomy));
        assert_eq!(rule.primary_cwe.as_ref(), Some(&mapping.primary_cwe));
        assert_eq!(
            rule.taxonomy_provenance.as_ref(),
            Some(&mapping.taxonomy_provenance)
        );
        let taxonomy = serde_json::to_value(mapping.taxonomy.clone())?;
        assert_eq!(taxonomy.as_object().map(serde_json::Map::len), Some(3));
    }
    assert!(rule_catalog.iter().skip(7).all(|rule| {
        rule.taxonomy.is_none() && rule.primary_cwe.is_none() && rule.taxonomy_provenance.is_none()
    }));

    let report = precision_report()?;
    assert_eq!(report.taxonomy_catalog, vec![descriptor]);
    assert!(report.findings.iter().all(|finding| {
        mappings_by_rule.get(finding.rule_id.as_str()).map_or_else(
            || {
                finding.taxonomy.is_none()
                    && finding.primary_cwe.is_none()
                    && finding.taxonomy_provenance.is_none()
            },
            |mapping| {
                finding.taxonomy.as_ref() == Some(&mapping.taxonomy)
                    && finding.primary_cwe.as_ref() == Some(&mapping.primary_cwe)
                    && finding.taxonomy_provenance.as_ref() == Some(&mapping.taxonomy_provenance)
            },
        )
    }));
    let schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    assert!(jsonschema::validator_for(&schema)?.is_valid(&serde_json::to_value(&report)?));
    Ok(())
}

#[test]
fn sarif_baseline_and_legacy_json_preserve_taxonomy_compatibly()
-> Result<(), Box<dyn std::error::Error>> {
    let report = precision_report()?;
    let sarif = sarif_report(&report);
    let results = sarif["runs"][0]["results"]
        .as_array()
        .ok_or("SARIF results missing")?;
    assert_eq!(results.len(), report.findings.len());
    assert!(
        results
            .iter()
            .zip(&report.findings)
            .all(|(result, finding)| {
                if finding.taxonomy.is_some() {
                    result["properties"]["taxonomy"]
                        .as_object()
                        .is_some_and(|taxonomy| taxonomy.len() == 3)
                        && result["properties"]["primaryCwe"]["id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with("CWE-"))
                        && result["properties"]["taxonomyProvenance"]["source_commit"]
                            == TAXONOMY_SOURCE_COMMIT
                } else {
                    result["properties"]["taxonomy"].is_null()
                        && result["properties"]["primaryCwe"].is_null()
                        && result["properties"]["taxonomyProvenance"].is_null()
                }
            })
    );
    assert_eq!(
        sarif["runs"][0]["properties"]["secureTaxonomyCatalog"][0]["taxonomy_version"],
        TAXONOMY_VERSION
    );

    let baseline = create_baseline(&report)?;
    assert_eq!(baseline.taxonomy_catalog, report.taxonomy_catalog);
    assert!(baseline.findings.iter().all(|finding| {
        let present = [
            finding.taxonomy.is_some(),
            finding.primary_cwe.is_some(),
            finding.taxonomy_provenance.is_some(),
        ];
        present.iter().all(|value| *value) || present.iter().all(|value| !*value)
    }));
    let mut partial = baseline.clone();
    let mapped = partial
        .findings
        .iter_mut()
        .find(|finding| finding.taxonomy.is_some())
        .ok_or("baseline had no mapped finding")?;
    mapped.primary_cwe = None;
    assert!(validate_baseline(&partial).is_err());

    let legacy: ScanReport = serde_json::from_slice(&std::fs::read(workspace_path(
        "fixtures/secure-json-v1/phase3-report.json",
    ))?)?;
    assert!(legacy.taxonomy_catalog.is_empty());
    assert!(legacy.findings.iter().all(|finding| {
        finding.taxonomy.is_none()
            && finding.primary_cwe.is_none()
            && finding.taxonomy_provenance.is_none()
    }));
    Ok(())
}

#[test]
fn phase67_fingerprint_migration_is_explicit_and_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let mut request = ScanRequest::new(workspace_path("fixtures/phase3-rules"));
    request.configuration.parse_cache_enabled = false;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let current = report
        .findings
        .iter()
        .map(|finding| finding.fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    let phase_67 = BTreeSet::from([
        "074108a8f812332f7d13143ac2c83bc7726d5adc932ebc92722abc8a27914ee9",
        "837b671f52fced544d81c9f9adfedea27895491122324b6fe654ef37b6076040",
        "a78901ffe4752b0e7f57afcbc238db8f8eac40b934ccca1c7e25aa0ac4b4a80d",
        "b8dabb7bcbaf7e7a6c5c671b64d74b4e286215dba16eb9fd671d00246efa87ae",
        "cf4edf5e17aacc16ca6604aa96b4e01ba05a1e289f697f5ee4992eee1d73f07a",
        "f14f8006f7ca5f102d107b416fa160136ab4c3f8156d4d0b36779baf5ec24aa5",
    ]);
    assert_eq!(current, phase_67);
    Ok(())
}

#[test]
fn cold_and_warm_precision_scans_are_byte_stable_after_cache_invalidation()
-> Result<(), Box<dyn std::error::Error>> {
    let cache = tempfile::tempdir()?;
    let mut request = ScanRequest::new(workspace_path("fixtures/phase65-precision"));
    request.cache.directory = Some(cache.path().to_path_buf());
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(cold.parsing.cache_misses, 10);
    assert_eq!(warm.parsing.cache_hits, 10);
    assert_eq!(cold.graph, warm.graph);
    assert_eq!(cold.findings, warm.findings);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    Ok(())
}
