# Phase 4 CLI and native desktop

## Native workflow

Launch `secure-desktop`, choose a repository with **Browse**, then use **Start**, **Cancel**, **Rescan**, or **Clear**. Recent projects remain local and are not placed in reports. The left navigation exposes Overview, Findings, Architecture, Dependencies, Scan History, optional AI Validation, and Settings; `Ctrl+1` through `Ctrl+7` selects a page, `Ctrl+R` rescans, and `Escape` cancels.

Overview shows typed scan measurements, the frozen taxonomy name/version, and JSON/SARIF/baseline actions. Findings supports search, including neutral category/invariant IDs, CWE, semantic identities, policies, and semantic fingerprints, plus severity, confidence, rule, file, category, and suppression-state filters with stable sorting. Selecting a finding shows taxonomy coordinates, provenance, semantic fingerprint, and per-step semantic identity alongside the invariant, impact, prerequisites, remediation, verification state, limitations, exact path, bounded source preview, and exact suppression creation. A reason of at least eight characters and the selected rule/path/start byte are required before rescan.

Architecture limits its display to a selected evidence path when available. Dependencies lists languages, manifests, frameworks, capabilities, and trust boundaries. History automatically retains complete scans, can reopen, compare, or explicitly delete them, and reports moved repositories without treating the record as corrupt. Settings exposes inventory, ignore, cache, graph/rule bounds, exact suppressions, retention, and text scaling. Layouts scroll instead of overlapping at the 800×600 minimum.

Every scan, picker, source read, history access, export, and baseline file operation runs outside the render thread. A cancellation retains no partial report. Source preview canonicalizes the repository, rejects absolute/parent/backslash/control paths and symlink components, enforces containment, reads at most 1 MiB without following the final symlink, requires UTF-8, and retains only the current in-memory excerpt.

## CLI

The machine-readable document remains the only stdout content. Human progress and summaries use stderr; `--quiet` suppresses them, `--verbose` expands progress, and `--no-color` guarantees the already color-free stream.

```text
secure scan <path> [--format secure-json-v1|sarif] [--output FILE]
secure explain <finding-id> --report REPORT
secure rules list
secure baseline create REPORT --output BASELINE
secure baseline compare BASELINE REPORT [--output COMPARISON]
secure history list [--history-dir DIRECTORY]
secure history show SCAN_ID [--history-dir DIRECTORY]
secure history delete SCAN_ID [--history-dir DIRECTORY]
secure doctor
```

Use `secure scan ... --save-history` to retain a completed CLI scan. Exit codes are stable: `0` success/no findings, `1` policy findings or material baseline differences, `2` invalid input, `3` unsupported schema/format, `4` cancellation, and `5` internal failure. File exports, baselines, and history records use private temporary files, `fsync`, and atomic rename.

## Formats

SARIF exports map the seven Phase 3 rules and findings to SARIF 2.1.0. Severity becomes `error`, `warning`, or `note`; deterministic fingerprints appear in both fingerprint maps; every location is based on `%SRCROOT%`; and evidence paths become ordered thread-flow locations. Phase 6.5 adds `secureTaxonomyCatalog` to run properties and exact taxonomy, primary CWE, and provenance properties to rules and results. Phase 6.6 adds the separate semantic fingerprint and semantic thread-flow properties. The test fixture at `schemas/sarif-schema-2.1.0.json` is the official OASIS SARIF schema.

`secure-baseline-v1` contains the report schema, safe repository identity, report fingerprint, taxonomy catalog, and sorted finding records with their mapping metadata and optional semantic fingerprint. Comparisons are timestamp-independent and classify `new`, `unchanged`, `resolved`, and related-but-changed evidence. Legacy baselines without taxonomy or semantics remain readable; malformed, partial-mapping, unsorted, duplicate, incompatible, or invalid-fingerprint baselines are rejected.

`secure-history-v1` stores one complete report with display metadata, safe identity, configuration already present in the report, completion state, taxonomy versions, and a private optional repository path. The public list/show API excludes that host path. Retention is 1–10,000 records; legacy entries without taxonomy remain readable, corrupt JSON is retired, missing repositories are reported, and partial scans are rejected.
