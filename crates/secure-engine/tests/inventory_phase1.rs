//! Phase 1 repository traversal, safety, resource-limit, and determinism integration tests.

use std::fs;
use std::path::Path;

use secure_engine::{CancellationToken, ProgressEvent, ScanError, ScanRequest, scan_repository};
use tempfile::tempdir;

fn write_file(root: &Path, relative: &str, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

fn paths(report: &secure_engine::ScanReport) -> Vec<&str> {
    report.files.iter().map(|file| file.path.as_str()).collect()
}

#[test]
fn ignore_exclude_hidden_generated_vendor_and_nested_boundaries_are_applied_before_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    fs::create_dir(repository.path().join(".git"))?;
    write_file(
        repository.path(),
        ".git/HEAD",
        "0123456789012345678901234567890123456789\n",
    )?;
    write_file(
        repository.path(),
        ".gitignore",
        "ignored/\nignored-secret.txt\n",
    )?;
    write_file(repository.path(), ".ignore", "also-ignored.txt\n")?;
    write_file(repository.path(), "src/main.rs", "fn main() {}\n")?;
    write_file(repository.path(), "src/private/key.rs", "private-source\n")?;
    write_file(repository.path(), "README.md", "documentation\n")?;
    write_file(repository.path(), ".hidden.rs", "hidden-source\n")?;
    write_file(
        repository.path(),
        "target/generated.rs",
        "generated-source\n",
    )?;
    write_file(
        repository.path(),
        "node_modules/pkg/index.js",
        "vendored-source\n",
    )?;
    write_file(
        repository.path(),
        "ignored/token.rs",
        "ignored-token-value\n",
    )?;
    write_file(
        repository.path(),
        "ignored-secret.txt",
        "ignored-secret-value\n",
    )?;
    write_file(
        repository.path(),
        "also-ignored.txt",
        "also-ignored-secret-value\n",
    )?;
    write_file(repository.path(), "nested/.git/HEAD", "nested-metadata\n")?;
    write_file(
        repository.path(),
        "nested/secret.rs",
        "nested-secret-value\n",
    )?;
    write_file(
        repository.path(),
        "submodule/.git",
        "gitdir: ../.git/modules/submodule\n",
    )?;
    write_file(
        repository.path(),
        "submodule/secret.rs",
        "submodule-secret-value\n",
    )?;
    write_file(repository.path(), "image.bin", b"GIF89a\0binary")?;

    let mut request = ScanRequest::new(repository.path());
    request.configuration.exclude_patterns = vec!["src/private/**".into()];
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let scanned = paths(&report);
    assert!(scanned.contains(&"src/main.rs"));
    assert!(scanned.contains(&"README.md"));
    assert!(scanned.contains(&"image.bin"));
    assert!(!scanned.iter().any(|path| path.contains("ignored")));
    assert!(!scanned.iter().any(|path| path.contains("private")));
    assert!(!scanned.iter().any(|path| path.contains("target")));
    assert!(!scanned.iter().any(|path| path.contains("node_modules")));
    assert!(!scanned.iter().any(|path| path.contains("nested")));
    assert!(!scanned.iter().any(|path| path.starts_with('.')));
    assert_eq!(report.inventory.binary_files, 1);
    assert_eq!(report.inventory.nested_repositories_skipped, 2);
    assert!(
        report
            .exclusions
            .iter()
            .any(|item| item.reason == "exclude-pattern")
    );
    let json = serde_json::to_string(&report)?;
    assert!(!json.contains("ignored-secret-value"));
    assert!(!json.contains("nested-secret-value"));
    assert!(!json.contains("submodule-secret-value"));
    assert!(!json.contains(&repository.path().to_string_lossy().to_string()));
    Ok(())
}

#[test]
fn gitignore_negation_nested_rules_tool_ignore_and_info_exclude_are_honored()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    fs::create_dir_all(repository.path().join(".git/info"))?;
    write_file(
        repository.path(),
        ".git/HEAD",
        "0123456789012345678901234567890123456789\n",
    )?;
    write_file(
        repository.path(),
        ".git/info/exclude",
        "info-excluded.txt\n",
    )?;
    write_file(repository.path(), ".gitignore", "*.secret\n!keep.secret\n")?;
    write_file(repository.path(), ".ignore", "tool-ignored.txt\n")?;
    write_file(repository.path(), "drop.secret", "drop\n")?;
    write_file(repository.path(), "keep.secret", "keep\n")?;
    write_file(repository.path(), "info-excluded.txt", "info\n")?;
    write_file(repository.path(), "tool-ignored.txt", "tool\n")?;
    write_file(repository.path(), "nested/.gitignore", "*.rs\n!keep.rs\n")?;
    write_file(repository.path(), "nested/drop.rs", "drop\n")?;
    write_file(repository.path(), "nested/keep.rs", "keep\n")?;

    let report = scan_repository(
        &ScanRequest::new(repository.path()),
        &CancellationToken::new(),
        |_| {},
    )?;
    let scanned = paths(&report);
    assert!(scanned.contains(&"keep.secret"));
    assert!(scanned.contains(&"nested/keep.rs"));
    assert!(!scanned.contains(&"drop.secret"));
    assert!(!scanned.contains(&"info-excluded.txt"));
    assert!(!scanned.contains(&"tool-ignored.txt"));
    assert!(!scanned.contains(&"nested/drop.rs"));
    Ok(())
}

#[test]
fn explicit_controls_can_include_hidden_generated_vendor_and_nested_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    fs::create_dir(repository.path().join(".git"))?;
    write_file(
        repository.path(),
        ".git/HEAD",
        "0123456789012345678901234567890123456789\n",
    )?;
    write_file(repository.path(), ".hidden.rs", "hidden\n")?;
    write_file(repository.path(), "target/generated.rs", "generated\n")?;
    write_file(repository.path(), "node_modules/pkg/index.js", "vendor\n")?;
    write_file(repository.path(), "nested/.git/HEAD", "metadata\n")?;
    write_file(repository.path(), "nested/source.py", "nested\n")?;

    let mut request = ScanRequest::new(repository.path());
    request.configuration.include_hidden = true;
    request.configuration.include_generated = true;
    request.configuration.include_vendor = true;
    request.configuration.include_nested_repositories = true;
    request.configuration.respect_ignore_files = false;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    let scanned = paths(&report);
    assert!(scanned.contains(&".hidden.rs"));
    assert!(scanned.contains(&"target/generated.rs"));
    assert!(scanned.contains(&"node_modules/pkg/index.js"));
    assert!(scanned.contains(&"nested/source.py"));
    assert!(
        !scanned
            .iter()
            .any(|path| path.contains("/.git/") || *path == ".git")
    );
    assert_eq!(report.inventory.generated_files, 1);
    assert_eq!(report.inventory.vendor_files, 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_escapes_are_never_followed_or_fingerprinted() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let repository = tempdir()?;
    let outside = tempdir()?;
    write_file(outside.path(), "secret.txt", "outside-secret-one\n")?;
    write_file(
        outside.path(),
        "dir/secret.rs",
        "outside-directory-secret\n",
    )?;
    symlink(
        outside.path().join("secret.txt"),
        repository.path().join("outside-file"),
    )?;
    symlink(
        outside.path().join("dir"),
        repository.path().join("outside-dir"),
    )?;
    write_file(repository.path(), "inside.rs", "fn inside() {}\n")?;

    let first = scan_repository(
        &ScanRequest::new(repository.path()),
        &CancellationToken::new(),
        |_| {},
    )?;
    write_file(outside.path(), "secret.txt", "outside-secret-two\n")?;
    let second = scan_repository(
        &ScanRequest::new(repository.path()),
        &CancellationToken::new(),
        |_| {},
    )?;
    assert_eq!(first.report_fingerprint, second.report_fingerprint);
    assert_eq!(first.inventory.symlinks_skipped, 2);
    assert!(
        first
            .skipped_files
            .iter()
            .all(|item| item.reason == "symlink-not-followed")
    );
    let json = serde_json::to_string(&first)?;
    assert!(!json.contains("outside-secret"));
    assert!(
        !paths(&first)
            .iter()
            .any(|path| path.starts_with("outside-"))
    );
    Ok(())
}

#[test]
fn large_repository_selection_is_bounded_deterministic_and_reports_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    for index in 0..5000 {
        write_file(
            repository.path(),
            &format!("src/file-{index:05}.rs"),
            format!("fn file_{index}() {{}}\n"),
        )?;
    }
    let mut request = ScanRequest::new(repository.path());
    request.configuration.max_files = 128;
    let mut discovery_updates = 0_usize;
    let first = scan_repository(&request, &CancellationToken::new(), |event| {
        if matches!(event, ProgressEvent::DiscoveryProgress { .. }) {
            discovery_updates = discovery_updates.saturating_add(1);
        }
    })?;
    let second = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(first.inventory.candidate_files, 5000);
    assert_eq!(first.inventory.files_selected, 128);
    assert!(first.inventory.hit_file_limit);
    assert!(discovery_updates >= 5);
    assert_eq!(first.files[0].path, "src/file-00000.rs");
    assert_eq!(first.files[127].path, "src/file-00127.rs");
    assert_eq!(first.report_fingerprint, second.report_fingerprint);
    Ok(())
}

#[test]
fn cancellation_is_observed_during_large_repository_discovery()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    for index in 0..700 {
        write_file(
            repository.path(),
            &format!("files/{index:04}.txt"),
            "bounded\n",
        )?;
    }
    let cancellation = CancellationToken::new();
    let callback_token = cancellation.clone();
    let result = scan_repository(
        &ScanRequest::new(repository.path()),
        &cancellation,
        move |event| {
            if matches!(
                event,
                ProgressEvent::DiscoveryProgress {
                    entries_seen: 512..,
                    ..
                }
            ) {
                callback_token.cancel();
            }
        },
    );
    assert!(matches!(result, Err(ScanError::Cancelled)));
    Ok(())
}

#[test]
fn cancellation_is_observed_before_and_during_bounded_file_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    write_file(repository.path(), "large.bin", vec![b'x'; 2 * 1024 * 1024])?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.max_file_bytes = 4 * 1024 * 1024;
    request.configuration.max_total_bytes = 4 * 1024 * 1024;
    let cancellation = CancellationToken::new();
    let callback_token = cancellation.clone();
    let result = scan_repository(&request, &cancellation, |event| {
        if matches!(event, ProgressEvent::Inspecting { .. }) {
            callback_token.cancel();
        }
    });
    assert!(matches!(result, Err(ScanError::Cancelled)));
    Ok(())
}

#[test]
fn per_file_and_total_byte_limits_skip_content_deterministically()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    write_file(repository.path(), "a.txt", "1234")?;
    write_file(repository.path(), "b.txt", "5678")?;
    write_file(repository.path(), "large.txt", "1234567890")?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.max_file_bytes = 5;
    request.configuration.max_total_bytes = 5;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert_eq!(paths(&report), ["a.txt"]);
    assert!(report.inventory.hit_total_byte_limit);
    assert_eq!(report.inventory.bytes_scanned, 4);
    assert!(
        report
            .skipped_files
            .iter()
            .any(|item| item.path == "b.txt" && item.reason == "total-byte-limit")
    );
    assert!(
        report
            .skipped_files
            .iter()
            .any(|item| item.path == "large.txt")
    );
    Ok(())
}

#[test]
fn depth_limit_prevents_deeper_content_from_being_selected()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    write_file(repository.path(), "root.txt", "root\n")?;
    write_file(repository.path(), "one/child.txt", "child\n")?;
    write_file(repository.path(), "one/two/deep.txt", "deep-private\n")?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.max_depth = Some(2);
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    assert!(paths(&report).contains(&"root.txt"));
    assert!(paths(&report).contains(&"one/child.txt"));
    assert!(!paths(&report).contains(&"one/two/deep.txt"));
    assert!(!serde_json::to_string(&report)?.contains("deep-private"));
    Ok(())
}

#[test]
fn malformed_patterns_and_limits_fail_without_a_report() -> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.include_patterns = vec!["[".into()];
    assert!(matches!(
        scan_repository(&request, &CancellationToken::new(), |_| {}),
        Err(ScanError::InvalidConfiguration(_))
    ));
    request.configuration.include_patterns = vec!["/absolute/private".into()];
    assert!(matches!(
        scan_repository(&request, &CancellationToken::new(), |_| {}),
        Err(ScanError::InvalidConfiguration(_))
    ));
    request.configuration.include_patterns.clear();
    request.configuration.max_errors = 1001;
    assert!(matches!(
        scan_repository(&request, &CancellationToken::new(), |_| {}),
        Err(ScanError::InvalidConfiguration(_))
    ));
    Ok(())
}

#[test]
fn git_worktree_metadata_is_recognized_without_exporting_its_path()
-> Result<(), Box<dyn std::error::Error>> {
    let outer = tempdir()?;
    let repository = outer.path().join("worktree");
    let git_directory = outer.path().join("git-data/worktrees/one");
    fs::create_dir_all(&repository)?;
    fs::create_dir_all(&git_directory)?;
    let revision = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
    write_file(&git_directory, "HEAD", format!("{revision}\n"))?;
    write_file(
        &repository,
        ".git",
        format!("gitdir: {}\n", git_directory.display()),
    )?;
    write_file(&repository, "src/main.rs", "fn main() {}\n")?;
    let report = scan_repository(
        &ScanRequest::new(&repository),
        &CancellationToken::new(),
        |_| {},
    )?;
    assert_eq!(report.repository.vcs.as_deref(), Some("git"));
    assert_eq!(report.repository.repository_kind, "git-worktree");
    assert_eq!(report.repository.revision.as_deref(), Some(revision));
    assert!(!serde_json::to_string(&report)?.contains(&outer.path().to_string_lossy().to_string()));
    Ok(())
}

#[cfg(unix)]
#[test]
fn unreadable_files_produce_only_bounded_relative_errors() -> Result<(), Box<dyn std::error::Error>>
{
    use std::os::unix::fs::PermissionsExt;

    let repository = tempdir()?;
    write_file(repository.path(), "unreadable.txt", "private\n")?;
    let path = repository.path().join("unreadable.txt");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000))?;
    let actually_unreadable = fs::File::open(&path).is_err();
    let mut request = ScanRequest::new(repository.path());
    request.configuration.max_errors = 2;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    if actually_unreadable {
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].path.as_deref(), Some("unreadable.txt"));
        assert_eq!(report.errors[0].code, "read-failed");
    }
    assert!(report.errors.len() <= request.configuration.max_errors);
    assert!(
        !serde_json::to_string(&report)?.contains(&repository.path().to_string_lossy().to_string())
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn ignored_and_explicitly_excluded_unreadable_files_are_never_opened()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let repository = tempdir()?;
    write_file(repository.path(), ".gitignore", "ignored.txt\n")?;
    write_file(repository.path(), "ignored.txt", "ignored-private\n")?;
    write_file(repository.path(), "excluded.txt", "excluded-private\n")?;
    write_file(repository.path(), "included.txt", "included\n")?;
    let ignored = repository.path().join("ignored.txt");
    let excluded = repository.path().join("excluded.txt");
    fs::set_permissions(&ignored, fs::Permissions::from_mode(0o000))?;
    fs::set_permissions(&excluded, fs::Permissions::from_mode(0o000))?;
    let mut request = ScanRequest::new(repository.path());
    request.configuration.exclude_patterns = vec!["excluded.txt".into()];
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    fs::set_permissions(&ignored, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(&excluded, fs::Permissions::from_mode(0o600))?;
    assert!(report.errors.is_empty());
    assert_eq!(paths(&report), ["included.txt"]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn many_unreadable_files_are_bounded_with_a_truncation_marker()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let repository = tempdir()?;
    let mut unreadable = Vec::new();
    for index in 0..10 {
        let relative = format!("private-{index}.txt");
        write_file(repository.path(), &relative, "private\n")?;
        let path = repository.path().join(relative);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000))?;
        unreadable.push(path);
    }
    let actually_unreadable = fs::File::open(&unreadable[0]).is_err();
    let mut request = ScanRequest::new(repository.path());
    request.configuration.max_errors = 3;
    let report = scan_repository(&request, &CancellationToken::new(), |_| {})?;
    for path in &unreadable {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    if actually_unreadable {
        assert_eq!(report.errors.len(), 3);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.code == "error-limit-reached")
        );
    }
    assert!(report.errors.len() <= 3);
    Ok(())
}

#[cfg(unix)]
#[test]
fn ambiguous_platform_paths_are_pruned_without_exporting_their_names()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    write_file(repository.path(), "safe.rs", "fn safe() {}\n")?;
    write_file(repository.path(), "ambiguous\\name.rs", "private\n")?;
    let report = scan_repository(
        &ScanRequest::new(repository.path()),
        &CancellationToken::new(),
        |_| {},
    )?;
    assert_eq!(paths(&report), ["safe.rs"]);
    assert!(
        report
            .exclusions
            .iter()
            .any(|item| item.reason == "unsupported-path" && item.count == 1)
    );
    assert!(!serde_json::to_string(&report)?.contains("ambiguous"));
    Ok(())
}
