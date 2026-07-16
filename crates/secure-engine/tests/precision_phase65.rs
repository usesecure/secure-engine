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
    assert_eq!(rules().len(), 7);
    let mappings_by_rule = mappings
        .iter()
        .map(|mapping| (mapping.rule_id.as_str(), mapping))
        .collect::<BTreeMap<_, _>>();
    for rule in rules() {
        let mapping = mappings_by_rule
            .get(rule.rule_id.as_str())
            .ok_or("rule was not mapped")?;
        assert_eq!(rule.taxonomy.as_ref(), Some(&mapping.taxonomy));
        assert_eq!(rule.primary_cwe.as_ref(), Some(&mapping.primary_cwe));
        assert_eq!(
            rule.taxonomy_provenance.as_ref(),
            Some(&mapping.taxonomy_provenance)
        );
        let taxonomy = serde_json::to_value(mapping.taxonomy.clone())?;
        assert_eq!(taxonomy.as_object().map(serde_json::Map::len), Some(3));
    }

    let report = precision_report()?;
    assert_eq!(report.taxonomy_catalog, vec![descriptor]);
    assert!(report.findings.iter().all(|finding| {
        mappings_by_rule
            .get(finding.rule_id.as_str())
            .is_some_and(|mapping| {
                finding.taxonomy.as_ref() == Some(&mapping.taxonomy)
                    && finding.primary_cwe.as_ref() == Some(&mapping.primary_cwe)
                    && finding.taxonomy_provenance.as_ref() == Some(&mapping.taxonomy_provenance)
            })
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
    assert!(results.iter().all(|result| {
        result["properties"]["taxonomy"]
            .as_object()
            .is_some_and(|taxonomy| taxonomy.len() == 3)
            && result["properties"]["primaryCwe"]["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("CWE-"))
            && result["properties"]["taxonomyProvenance"]["source_commit"] == TAXONOMY_SOURCE_COMMIT
    }));
    assert_eq!(
        sarif["runs"][0]["properties"]["secureTaxonomyCatalog"][0]["taxonomy_version"],
        TAXONOMY_VERSION
    );

    let baseline = create_baseline(&report)?;
    assert_eq!(baseline.taxonomy_catalog, report.taxonomy_catalog);
    assert!(baseline.findings.iter().all(|finding| {
        finding.taxonomy.is_some()
            && finding.primary_cwe.is_some()
            && finding.taxonomy_provenance.is_some()
    }));
    let mut partial = baseline.clone();
    partial.findings[0].primary_cwe = None;
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
fn legacy_finding_fingerprints_survive_additive_taxonomy_and_precision_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut request = ScanRequest::new(workspace_path("fixtures/phase3-rules"));
    request.configuration.parse_cache_enabled = false;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let current = report
        .findings
        .iter()
        .map(|finding| finding.fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    let phase_six = BTreeSet::from([
        "01a75d5a82de10de82d07249f9e095a3668709cc1462229cd9d903095b4f7f90",
        "15a11fc72e3430a6f42072fa4a979c1a6d127110c5b75708dc8b780f849372a5",
        "40be312ff376240ea0d4aabd68440bd91f58f1ad0f9430cd0305b9059b95b332",
        "44389a6dee3cf345a52ff12550a6a812d6159e19232eb8f234366cab5e1057ae",
        "55d5b2f98610325c7577e03ebe1169de0d8182998242d464b1c6772719ecf2dc",
        "5bde1f762888edbf75e03967e96ad252c6d89429154055d2cf28fb60ce21bcc0",
        "6979ca531b6b78d3d0293a1ced3d1e8e26c3cfb485947d6c5806e29fd60e90f0",
        "773e1af8ef9d021731ac6710a3164ad7020175094c8125460c34cc02256c21f3",
        "b693c9a7441120b98bb2873373f2efd5a61e7c4ced6815e0adda33507ab25f55",
        "b75de9007d07fcf02092b02cc6b0f78863557d87dfb2b5921e48b869eed87e92",
        "bd46836217254d9e2f677e5df919f7745caaa79de466a4209e199521c9fabc2d",
        "ca5b1427a20d4c466fef81f37d95c0eaf20a4152ffb38d121cce7ce63a71aff5",
    ]);
    assert!(phase_six.is_subset(&current));
    assert_eq!(current.len(), phase_six.len().saturating_add(1));
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
