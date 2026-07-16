# ADR 0005: Phase 4 local product boundaries

## Status

Accepted for Phase 4.

## Decision

SARIF conversion, deterministic baselines, atomic exports, bounded history, and contained source preview are shared-engine APIs. The CLI and desktop call those APIs rather than reimplementing formats or security checks. `secure-json-v1` remains additive and unchanged as the canonical complete report.

Desktop scans, repository/file pickers, source reads, exports, baseline file operations, and history operations execute on background workers. The render thread owns only view state and immutable completed reports. Cancellation never publishes a partial scan or partial export.

History records use `secure-history-v1`, private `0700` directories, `0600` atomic files, and bounded retention. A private canonical repository path may be retained only to reopen a local source preview; public history summaries and reopened entries never serialize it. Source content is never copied into history.

Baselines use `secure-baseline-v1` and contain no timestamps. Exact finding fingerprints classify unchanged records. A rule plus exact sink key relates changed evidence. New findings remain visible and cannot be silently suppressed by a baseline.

SARIF uses version 2.1.0 with repository-relative URI locations, tool rules, results, levels, fingerprints, properties, and ordered `codeFlows`/`threadFlows`. No snippets or absolute/cache paths are emitted. Tests validate exports against the committed official OASIS schema fixture.

## Consequences and limits

The native app stays responsive and all product interfaces share deterministic analysis. Local history timestamps and private repository paths are intentionally local-only; exported reports and baselines remain deterministic. Source preview supports bounded UTF-8 regular files and rejects symlinks. Dynamic language-analysis limitations from Phase 3 remain unchanged. Phase 4 adds no rules, languages, AI, fixes, cloud, telemetry, or hosted service.
