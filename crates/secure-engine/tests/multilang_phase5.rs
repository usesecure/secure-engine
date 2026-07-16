//! Phase 5 isolated parser, shared-graph, cache, and mixed-monorepo integration tests.

use std::path::PathBuf;

use secure_engine::{CacheControl, CancellationToken, ScanRequest, scan_repository};
use tempfile::tempdir;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/phase5-multilang")
        .join(name)
}

fn scan(name: &str) -> Result<secure_engine::ScanReport, secure_engine::ScanError> {
    let mut request = ScanRequest::new(fixture(name));
    request.configuration.parse_cache_enabled = false;
    scan_repository(&request, &CancellationToken::new(), |_| {})
}

#[test]
fn rust_python_and_go_reuse_the_shared_rules_with_language_provenance()
-> Result<(), Box<dyn std::error::Error>> {
    for (language, grammar) in [
        ("rust", "tree-sitter-rust@0.24.2:rust"),
        ("python", "tree-sitter-python@0.25.0:python"),
        ("go", "tree-sitter-go@0.25.0:go"),
    ] {
        let report = scan(language)?;
        let coverage = report
            .parser_coverage
            .iter()
            .find(|item| item.parser_mode == language)
            .ok_or("language coverage missing")?;
        assert!(coverage.files_parsed >= 3);
        assert!(report.parser_diagnostics.iter().any(|diagnostic| {
            diagnostic.location.path.contains("broken")
                && diagnostic.recoverable
                && diagnostic.provenance.grammar == grammar
        }));
        assert!(
            report.facts.iter().any(|fact| {
                fact.location.path.contains("broken") && fact.kind == "module-import"
            })
        );
        assert!(report.facts.iter().any(|fact| fact.kind == "http-route"));
        assert!(
            report
                .facts
                .iter()
                .any(|fact| fact.kind == "process-execution")
        );
        assert!(report.facts.iter().all(|fact| {
            fact.provenance.grammar == grammar
                && fact.provenance.extractor_version == format!("normalized-{language}-facts-v1")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "SE1001"
                && finding
                    .sink
                    .as_ref()
                    .is_some_and(|sink| sink.path.contains("vulnerable"))
        }));
        let expected_rules: &[&str] = if language == "python" {
            &[
                "SE1001", "SE1002", "SE1003", "SE1004", "SE1005", "SE1006", "SE1007",
            ]
        } else {
            &["SE1001", "SE1002", "SE1003", "SE1004", "SE1005", "SE1007"]
        };
        for rule in expected_rules {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == *rule),
                "{language} did not exercise {rule}"
            );
        }
        assert!(report.findings.iter().all(|finding| {
            finding
                .sink
                .as_ref()
                .is_none_or(|sink| !sink.path.contains("safe"))
        }));
    }
    Ok(())
}

#[test]
fn mixed_repository_keeps_all_parser_modes_isolated_and_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let first = scan("mixed")?;
    let second = scan("mixed")?;
    for (mode, expected_files) in [("typescript", 1), ("rust", 1), ("python", 2), ("go", 1)] {
        assert!(
            first
                .parser_coverage
                .iter()
                .any(|item| { item.parser_mode == mode && item.files_parsed == expected_files })
        );
    }
    assert!(first.findings.iter().any(|finding| {
        finding.rule_id == "SE1001"
            && finding
                .source
                .as_ref()
                .is_some_and(|source| source.path == "worker.py")
            && finding
                .sink
                .as_ref()
                .is_some_and(|sink| sink.path == "helper.py")
    }));
    assert!(first.findings.iter().all(|finding| {
        !(finding
            .source
            .as_ref()
            .is_some_and(|source| source.path == "app.ts")
            && finding
                .sink
                .as_ref()
                .is_some_and(|sink| sink.path == "service.rs"))
    }));
    assert_eq!(first.facts, second.facts);
    assert_eq!(first.findings, second.findings);
    assert_eq!(first.report_fingerprint, second.report_fingerprint);
    Ok(())
}

#[test]
fn every_new_language_has_an_isolated_cold_and_warm_cache_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let cache = tempdir()?;
    for language in ["rust", "python", "go"] {
        let mut request = ScanRequest::new(fixture(language));
        request.cache = CacheControl {
            directory: Some(cache.path().to_path_buf()),
            clear_before_scan: true,
        };
        let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
        assert_eq!(cold.parsing.cache_hits, 0);
        assert_eq!(cold.parsing.cache_writes, cold.parsing.files_eligible);

        request.cache.clear_before_scan = false;
        let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
        assert_eq!(warm.parsing.cache_hits, warm.parsing.files_eligible);
        assert_eq!(cold.facts, warm.facts);
        assert_eq!(cold.findings, warm.findings);
        assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    }
    Ok(())
}
