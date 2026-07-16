# `secure-json-v1` contract

The public integration boundary is the `secure` process and [`schemas/secure-json-v1.schema.json`](../schemas/secure-json-v1.schema.json). Secure Skill must validate a document before consuming it and fall back when the binary or schema is unavailable.

## Stability and determinism

- `schema_version` is exactly `secure-json-v1`; incompatible identifiers are rejected.
- Unknown object fields are tolerated in v1 so producers can add optional evidence.
- All paths and spans are repository-relative, slash-normalized, and never contain source text.
- `scan.started_at`, `scan.finished_at`, and `scan.duration_ms` are documented volatile fields. `report_fingerprint` excludes them. All other fields are stable for the same files and configuration.
- `repository.content_fingerprint` hashes relative paths and file bytes. It identifies content without exporting the absolute repository path.
- Findings remain normalized but empty in Phase 1 because vulnerability rules are intentionally deferred.
- Errors are bounded and path-sanitized. Skipped files contain a stable reason, not host paths or file contents.

## Phase 1 additive inventory fields

Phase 1 does not change the schema identifier or remove/rename any v1 field. It adds optional schema properties so a Phase 0 document remains valid and deserializes with safe defaults:

- configuration: include/exclude globs, generated/vendor/nested-repository switches, total-byte/depth limits, and the error bound;
- repository: `repository_kind` distinguishes a directory, Git repository, and Git worktree;
- files: `origin` and `is_binary` extend classification without exporting contents;
- report: `inventory` contains aggregate counters and limit outcomes;
- report: `exclusions` contains reason/count pairs and deliberately omits excluded paths.

The producer emits these properties in Phase 1. Consumers must continue tolerating their absence and any future additive v1 properties. Ignore rules and exclude globs are applied before file opening; generated/vendor/nested roots are pruned before traversal. Symbolic links are never followed.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | success, no policy findings |
| 1 | completed scan with policy findings |
| 2 | invalid input or output path |
| 3 | unsupported schema/format |
| 4 | cancelled |
| 5 | internal engine failure |

Structured output goes to stdout unless `--output` is provided. Human progress and diagnostics go only to stderr. Output files are written to a sibling temporary file and renamed only after a complete report is serialized.

## Mock Secure Skill consumer

The `mock_secure_skill` example is deliberately local and independent:

```bash
cargo run -p secure-engine --example mock_secure_skill -- \
  schemas/secure-json-v1.schema.json fixtures/secure-json-v1/valid-report.json
```

It validates the schema version and JSON Schema, then reads capability evidence and findings. It neither installs nor executes Secure Skill.
