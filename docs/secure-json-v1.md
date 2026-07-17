# `secure-json-v1` contract

The public integration boundary is the `secure` process and [`schemas/secure-json-v1.schema.json`](../schemas/secure-json-v1.schema.json). Secure Skill must validate a document before consuming it and fall back when the binary or schema is unavailable.

## Stability and determinism

- `schema_version` is exactly `secure-json-v1`; incompatible identifiers are rejected.
- Unknown object fields are tolerated in v1 so producers can add optional evidence.
- All paths and spans are repository-relative, slash-normalized, and never contain source text.
- `scan.started_at`, `scan.finished_at`, `scan.duration_ms`, `parsing.duration_ms`, `analysis.duration_ms`, and the four `parsing.cache_*` counters are documented volatile fields. `report_fingerprint` excludes them. Facts, graph topology, paths, diagnostics, coverage, findings, and suppression results remain stable for the same files and configuration.
- `repository.content_fingerprint` hashes relative paths and file bytes. It identifies content without exporting the absolute repository path.
- Findings include only deterministic Phase 3 rules with reproducible graph paths; a sensitive sink alone is not a finding.
- Errors are bounded and path-sanitized. Skipped files contain a stable reason, not host paths or file contents.

## Phase 1 additive inventory fields

Phase 1 does not change the schema identifier or remove/rename any v1 field. It adds optional schema properties so a Phase 0 document remains valid and deserializes with safe defaults:

- configuration: include/exclude globs, generated/vendor/nested-repository switches, total-byte/depth limits, and the error bound;
- repository: `repository_kind` distinguishes a directory, Git repository, and Git worktree;
- files: `origin` and `is_binary` extend classification without exporting contents;
- report: `inventory` contains aggregate counters and limit outcomes;
- report: `exclusions` contains reason/count pairs and deliberately omits excluded paths.

The producer emits these properties in Phase 1. Consumers must continue tolerating their absence and any future additive v1 properties. Ignore rules and exclude globs are applied before file opening; generated/vendor/nested roots are pruned before traversal. Symbolic links are never followed.

## Phase 2 additive parsing fields

Phase 2 keeps every Phase 0 and Phase 1 field compatible and adds optional properties:

- configuration: cache, parser-diagnostic, per-file fact, and report-wide fact bounds;
- report: `parsing` contains coverage, duration, and cache counters;
- report: `facts` contains stable IDs, exact repository-relative spans, bounded normalized names and relationships, fingerprints, and parser/extractor provenance;
- report: `parser_diagnostics` contains recoverable, source-free syntax diagnostics;
- report: `parser_coverage` distinguishes JavaScript, JSX, TypeScript, TSX, Rust, Python, and Go modes.

Facts are syntax evidence only. They carry no severity or confidence and do not imply a vulnerability. Cache location and clear-cache controls are runtime-only and are never serialized. Cache state affects only the documented volatile counters; cold and warm reports have the same facts and `report_fingerprint`.

Phase 5 extends only the `parser_coverage.parser_mode` enum and accepted parser provenance values. Rust, Python, and Go facts use the same Phase 2 object shapes, while graph paths and findings use the same Phase 3 shapes. Existing JavaScript/TypeScript identifiers and fingerprints remain stable.

## Phase 3 additive graph and finding fields

Phase 3 preserves the Phase 0–2 required-property list and adds optional properties:

- configuration: graph node/edge, traversal-depth, finding, and exact suppression bounds;
- report: `graph.nodes` and `graph.edges` use only Secure Engine-owned domain objects with stable IDs, locations, provenance, and fingerprints;
- report: `analysis` records graph/rule counters, suppression counts, truncation, and volatile duration;
- report: `suppression_diagnostics` makes applied, invalid, broad, and stale suppression state auditable;
- finding: `source`, `transformations`, `guards`, `sink`, and ordered `evidence_path` extend the original normalized finding fields.

Every path step references a graph node and the edge from its predecessor. Deduplication uses the rule invariant, effective path, and sink fingerprint. Suppressions are exact `(rule_id, path, start_byte)` scopes with a required reason; wildcard and parent-traversal scopes are rejected.

## Phase 6 separate AI assessment contract

Phase 6 deliberately adds no field to the normal scan report. `secure-ai-validation-v1` is a separate document linked by `report_fingerprint`, `finding_id`, and `finding_fingerprint`. AI timestamps, provider/model, usage, cache, and consent provenance cannot affect `report_fingerprint`. Deterministic baselines ignore AI state. History omits the `ai_assessments` property when empty and may attach explicitly consented assessments later. Normal SARIF remains byte-stable; only the explicit enriched SARIF API adds `secureAiAssessment` result properties.

Assessment bodies conform to [`schemas/secure-ai-assessment-v1.schema.json`](../schemas/secure-ai-assessment-v1.schema.json). They express bounded review status and uncertainty, never a replacement severity or confidence.

## Phase 6.5 additive taxonomy contract

New reports include `taxonomy_catalog` with the frozen taxonomy name, version, public artifact hashes, source commit, and canonical content hash. Rule metadata and findings add `taxonomy`, `primary_cwe`, and `taxonomy_provenance`. `taxonomy` is deliberately exact and contains only `taxonomy_version`, `category_id`, and `invariant_id`; unknown fields are rejected by its nested schema. SARIF carries the equivalent catalog at run level and mapping at rule and result level.

All additions are optional when deserializing earlier `secure-json-v1` reports, baselines, and history entries. New Engine-produced reports populate them for every built-in rule and finding. They are included in the report fingerprint but excluded from existing finding fingerprints, so old finding identities remain stable. See [taxonomy-and-precision.md](./taxonomy-and-precision.md).

## Phase 6.6 additive evidence semantics

Security-relevant graph nodes and evidence-path steps may add `semantic`, containing a stable role, Engine-owned identity, optional policy, optional authorization scope, and certainty. Findings may add `semantic_fingerprint`. Earlier reports omit these fields and continue to deserialize; the original `fingerprint` and `finding_id` algorithms are unchanged.

SARIF adds `secureSemanticFingerprint/v1` to both fingerprint maps and `secureEvidenceSemantic` to thread-flow location properties. Baseline findings and optional AI preview payloads carry the semantic fingerprint additively. See [evidence-semantics.md](./evidence-semantics.md).

## Phase 6.7 additive evidence contract v2

Security-relevant semantics add optional `semantics_version`. Findings add optional
`evidence_contract_v2` with contract/semantics versions, an ordered canonical path, connectivity,
effective barriers, uncertainty flags, a location-independent semantic fingerprint, and a
span-aware duplicate fingerprint. Contract path elements expose only canonical source/sink kinds,
semantic roles/effects, repository-relative spans, and compression eligibility. Earlier v1 reports
remain valid and deserialize with no contract projection.

SARIF run properties expose `secureEvidenceContractVersion` and
`secureEvidenceSemanticsVersion`. Each result includes `evidenceContractV2`,
`secureContractFingerprint/v2`, and `secureContractDuplicateFingerprint/v2`. The normal report,
SARIF, history, baselines, suppressions, CLI, desktop, and AI-disabled execution remain compatible.
Corrected source/path selection and removal of multiple paths to the same semantic sink
intentionally change affected legacy finding fingerprints; deterministic Phase 6.7 values are
frozen by regression tests. See [evidence-contract-v2.md](./evidence-contract-v2.md).

Phase 6.8 does not change the JSON or SARIF schema versions. It refines normalized source,
module-resolution, positional-flow, and barrier proofs behind the same contract. Unaffected pinned
finding fingerprints remain stable; findings with newly corrected endpoints or paths migrate
through the existing deterministic fingerprint algorithm.

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

It validates the schema version and JSON Schema, then reads normalized facts, parser diagnostics, capability evidence, and findings. It neither installs nor executes Secure Skill.
