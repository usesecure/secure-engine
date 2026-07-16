//! Phase 2 parsing, normalized-fact, cache, recovery, and privacy integration tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use secure_engine::{
    CacheControl, CancellationToken, ProgressEvent, SECURE_JSON_V1_SCHEMA, ScanError, ScanReport,
    ScanRequest, scan_repository,
};
use tempfile::tempdir;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/phase2-js-ts")
}

fn request_without_cache(repository: impl Into<PathBuf>) -> ScanRequest {
    let mut request = ScanRequest::new(repository);
    request.configuration.parse_cache_enabled = false;
    request
}

fn copy_directory(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_directory(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn fact_kinds(report: &ScanReport) -> Vec<&str> {
    report.facts.iter().map(|fact| fact.kind.as_str()).collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn all_four_modes_preserve_precise_normalized_evidence_for_phase_three()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = fixture();
    let report = scan_repository(
        &request_without_cache(&repository),
        &CancellationToken::new(),
        |_| {},
    )?;
    assert_eq!(report.parsing.files_eligible, 9);
    assert_eq!(report.parsing.files_parsed, 9);
    assert_eq!(report.parser_coverage.len(), 4);
    for mode in ["javascript", "jsx", "typescript", "tsx"] {
        assert!(
            report
                .parser_coverage
                .iter()
                .any(|coverage| coverage.parser_mode == mode && coverage.files_parsed > 0)
        );
    }
    let kinds = fact_kinds(&report);
    for expected in [
        "function",
        "method",
        "module-import",
        "module-export",
        "call",
        "http-route",
        "http-route-handler",
        "server-action-handler",
        "environment-access",
        "guard-candidate",
        "process-execution",
        "database-access",
        "filesystem-operation",
        "network-request",
        "redirect",
        "template-render",
        "deserialization",
        "dynamic-code-execution",
    ] {
        assert!(kinds.contains(&expected), "missing {expected}");
    }

    let get_handler = report
        .facts
        .iter()
        .find(|fact| fact.kind == "http-route-handler" && fact.name.as_deref() == Some("GET"))
        .ok_or("GET route handler fact missing")?;
    assert_eq!(get_handler.location.path, "app/api/users/[id]/route.ts");
    assert_eq!(get_handler.location.span.start_byte, 52);
    assert_eq!(get_handler.location.span.start_line, 3);
    assert_eq!(get_handler.location.span.start_column, 8);
    assert_eq!(get_handler.fact_id, "sf_b53e989c55945ff77f5c8acf");
    assert_eq!(
        get_handler.fingerprint,
        "b53e989c55945ff77f5c8acf5e8c44e0bbd5cb1eab8edd9625e931a592856f9d"
    );
    assert!(get_handler.relationships.iter().any(|relationship| {
        relationship.kind == "handles" && relationship.target == "GET /api/users/[id]"
    }));
    let express_get = report
        .facts
        .iter()
        .find(|fact| {
            fact.kind == "http-route"
                && fact.relationships.iter().any(|relationship| {
                    relationship.kind == "handles" && relationship.target == "GET /users/:id"
                })
        })
        .ok_or("Express GET route missing")?;
    assert!(express_get.relationships.iter().any(|relationship| {
        relationship.kind == "handler" && relationship.target == "getUser"
    }));

    let unicode_environment = report
        .facts
        .iter()
        .find(|fact| {
            fact.kind == "environment-access"
                && fact.location.path == "src/unicode.ts"
                && fact.name.as_deref() == Some("REGIÓN")
        })
        .ok_or("Unicode environment fact missing")?;
    assert_eq!(unicode_environment.location.span.start_line, 5);
    assert_eq!(unicode_environment.location.span.start_column, 16);
    assert_eq!(unicode_environment.location.span.end_column, 34);
    assert!(report.parser_diagnostics.iter().any(|diagnostic| {
        diagnostic.location.path == "src/broken.ts"
            && diagnostic.code == "syntax-error"
            && diagnostic.recoverable
    }));
    assert!(
        report
            .facts
            .iter()
            .any(|fact| { fact.kind == "module-import" && fact.location.path == "src/broken.ts" })
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| !finding.evidence_path.is_empty())
    );

    let schema: serde_json::Value = serde_json::from_str(SECURE_JSON_V1_SCHEMA)?;
    let validator = jsonschema::validator_for(&schema)?;
    assert!(validator.is_valid(&serde_json::to_value(&report)?));

    let json = serde_json::to_string(&report)?;
    assert!(!json.contains(&repository.to_string_lossy().to_string()));
    assert!(!json.contains("ignored/secret.ts"));
    assert!(!json.contains("DO_NOT_EXPORT_THIS_PATH"));
    Ok(())
}

#[test]
fn cold_warm_invalidated_and_corrupt_cache_entries_are_safe_and_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let repository = temporary.path().join("repository");
    let cache = temporary.path().join("cache");
    copy_directory(&fixture(), &repository)?;
    let mut request = ScanRequest::new(&repository);
    request.cache = CacheControl {
        directory: Some(cache.clone()),
        clear_before_scan: true,
    };

    let cold_started = Instant::now();
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let cold_elapsed = cold_started.elapsed();
    assert_eq!(cold.parsing.cache_hits, 0);
    assert_eq!(cold.parsing.cache_misses, cold.parsing.files_eligible);
    assert_eq!(cold.parsing.cache_writes, cold.parsing.files_eligible);
    request.cache.clear_before_scan = false;

    let warm_started = Instant::now();
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm_elapsed = warm_started.elapsed();
    assert_eq!(warm.parsing.cache_hits, warm.parsing.files_eligible);
    assert_eq!(warm.parsing.cache_misses, 0);
    assert_eq!(cold.facts, warm.facts);
    assert_eq!(cold.parser_diagnostics, warm.parser_diagnostics);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    let mut cold_json = serde_json::to_value(&cold)?;
    let mut warm_json = serde_json::to_value(&warm)?;
    remove_volatile_fields(&mut cold_json);
    remove_volatile_fields(&mut warm_json);
    assert_eq!(cold_json, warm_json);
    assert!(cold_elapsed < Duration::from_secs(10));
    assert!(warm_elapsed < Duration::from_secs(10));

    let service = repository.join("src/service.ts");
    let mut source = fs::read_to_string(&service)?;
    source.push_str("\nexport const cacheInvalidation = true;\n");
    fs::write(service, source)?;
    let invalidated = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(invalidated.parsing.cache_misses, 1);
    assert_eq!(
        invalidated.parsing.cache_hits + 1,
        invalidated.parsing.files_eligible
    );
    assert_ne!(
        warm.repository.content_fingerprint,
        invalidated.repository.content_fingerprint
    );

    let cache_entry = find_first_json(&cache).ok_or("cache entry missing")?;
    fs::write(cache_entry, b"corrupt cache entry")?;
    let recovered = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(recovered.parsing.cache_entries_ignored, 1);
    assert_eq!(recovered.parsing.cache_misses, 1);
    assert_eq!(recovered.parsing.cache_writes, 1);
    assert_eq!(recovered.facts, invalidated.facts);
    assert_eq!(recovered.report_fingerprint, invalidated.report_fingerprint);

    request.cache.clear_before_scan = true;
    let cleared = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(cleared.parsing.cache_hits, 0);
    assert_eq!(cleared.parsing.cache_misses, cleared.parsing.files_eligible);
    let json = serde_json::to_string(&cleared)?;
    assert!(!json.contains(&cache.to_string_lossy().to_string()));
    assert!(!json.contains(&repository.to_string_lossy().to_string()));
    Ok(())
}

#[test]
fn parsing_respects_ignore_exclude_binary_and_file_size_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    fs::write(repository.path().join(".gitignore"), "ignored.ts\n")?;
    fs::write(
        repository.path().join("included.ts"),
        "export function kept() {}\n",
    )?;
    fs::write(
        repository.path().join("ignored.ts"),
        "export function ignored() {}\n",
    )?;
    fs::write(
        repository.path().join("excluded.ts"),
        "export function excluded() {}\n",
    )?;
    fs::write(
        repository.path().join("binary.js"),
        b"const hidden = 1;\0binary",
    )?;
    fs::write(
        repository.path().join("oversized.ts"),
        "export function oversized() {}\n",
    )?;
    fs::write(
        repository.path().join(".hidden.ts"),
        "export function hidden() {}\n",
    )?;
    fs::create_dir_all(repository.path().join("target"))?;
    fs::write(
        repository.path().join("target/generated.ts"),
        "export function generated() {}\n",
    )?;
    fs::create_dir_all(repository.path().join("node_modules/package"))?;
    fs::write(
        repository.path().join("node_modules/package/index.js"),
        "export function vendored() {}\n",
    )?;
    let mut request = request_without_cache(repository.path());
    request.configuration.exclude_patterns = vec!["excluded.ts".into()];
    request.configuration.max_file_bytes = 30;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(report.parsing.files_eligible, 1);
    assert!(
        report
            .facts
            .iter()
            .any(|fact| fact.name.as_deref() == Some("kept"))
    );
    assert!(report.files.iter().all(|file| {
        !matches!(
            file.path.as_str(),
            "ignored.ts"
                | "excluded.ts"
                | "oversized.ts"
                | ".hidden.ts"
                | "target/generated.ts"
                | "node_modules/package/index.js"
        )
    }));
    assert!(report.facts.iter().all(|fact| {
        !matches!(
            fact.location.path.as_str(),
            "ignored.ts"
                | "excluded.ts"
                | "binary.js"
                | "oversized.ts"
                | ".hidden.ts"
                | "target/generated.ts"
                | "node_modules/package/index.js"
        )
    }));
    Ok(())
}

#[test]
fn cancellation_at_the_parsing_boundary_never_publishes_a_partial_report()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    let source = "export function work() { return fetch('/api'); }\n".repeat(50_000);
    fs::write(repository.path().join("large.ts"), source)?;
    let request = request_without_cache(repository.path());
    let cancellation = CancellationToken::new();
    let callback_token = cancellation.clone();
    let result = scan_repository(&request, &cancellation, |event| {
        if matches!(event, ProgressEvent::Parsing { .. }) {
            callback_token.cancel();
        }
    });
    assert!(matches!(result, Err(ScanError::Cancelled)));
    Ok(())
}

#[test]
fn representative_synthetic_repository_records_cold_and_warm_parse_measurements()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let repository = temporary.path().join("representative-js-ts");
    let source_directory = repository.join("src");
    let cache = temporary.path().join("cache");
    fs::create_dir_all(&source_directory)?;
    for index in 0..400 {
        let (extension, source) = match index % 4 {
            0 => (
                "js",
                format!(
                    "export function handler{index}(request) {{ if (!request.user) throw new Error('auth'); return fetch('/api/{index}'); }}\n"
                ),
            ),
            1 => (
                "jsx",
                format!(
                    "export function View{index}({{user}}) {{ return <main>{{user.name}}</main>; }}\n"
                ),
            ),
            2 => (
                "ts",
                format!(
                    "export async function load{index}(id: string): Promise<string> {{ const region = process.env.REGION; return database.query(id + region); }}\n"
                ),
            ),
            _ => (
                "tsx",
                format!(
                    "export default function Page{index}() {{ return <section>Page {index}</section>; }}\n"
                ),
            ),
        };
        fs::write(
            source_directory.join(format!("module-{index:04}.{extension}")),
            source,
        )?;
    }
    let mut request = ScanRequest::new(&repository);
    request.cache = CacheControl {
        directory: Some(cache),
        clear_before_scan: true,
    };
    let cold_wall = Instant::now();
    let cold = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let cold_wall = cold_wall.elapsed();
    assert_eq!(cold.parsing.files_eligible, 400);
    assert_eq!(cold.parsing.files_parsed, 400);
    assert_eq!(cold.parsing.cache_misses, 400);
    assert_eq!(cold.parsing.cache_writes, 400);
    assert!(cold.parsing.facts_extracted >= 800);
    assert!(cold_wall < Duration::from_secs(30));

    request.cache.clear_before_scan = false;
    let warm_wall = Instant::now();
    let warm = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let warm_wall = warm_wall.elapsed();
    assert_eq!(warm.parsing.cache_hits, 400);
    assert_eq!(warm.parsing.cache_misses, 0);
    assert_eq!(cold.facts, warm.facts);
    assert_eq!(cold.report_fingerprint, warm.report_fingerprint);
    assert!(warm_wall < Duration::from_secs(30));
    Ok(())
}

fn find_first_json(root: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_first_json(&path) {
                return Some(found);
            }
        } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
            return Some(path);
        }
    }
    None
}

fn remove_volatile_fields(report: &mut serde_json::Value) {
    if let Some(scan) = report
        .get_mut("scan")
        .and_then(serde_json::Value::as_object_mut)
    {
        for field in ["started_at", "finished_at", "duration_ms"] {
            scan.remove(field);
        }
    }
    if let Some(parsing) = report
        .get_mut("parsing")
        .and_then(serde_json::Value::as_object_mut)
    {
        for field in [
            "duration_ms",
            "cache_hits",
            "cache_misses",
            "cache_writes",
            "cache_entries_ignored",
        ] {
            parsing.remove(field);
        }
    }
    if let Some(analysis) = report
        .get_mut("analysis")
        .and_then(serde_json::Value::as_object_mut)
    {
        analysis.remove("duration_ms");
    }
}
