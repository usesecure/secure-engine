# Evidence contract v2 implementation

Secure Engine 0.1.3 implements public evidence contract `2.0.0` as an additive projection on each
deterministic finding. The specification is tool-neutral: scanner rule IDs, prose, variable names,
and tool identity do not participate in matching.

## Provenance

Only the following public contract inputs were used:

- contract: `142c7f31c6c584cc808410130fa7db8451427e87504e72e64868c9cbc6564c42`
- synthetic tests: `9e96c98c0688397a5fb6c070d1d55e4336c9760f02347dbbf7162a6d43dc44d4`
- JSON Schema: `c0298b4a2ceb3d176e5773ea72a057d1929807711560255e0ea6645713bfc4b6`

The immutable local copies are under `fixtures/phase67-contract-v2`. Tests verify all three hashes,
validate the contract against its schema, and execute all eleven synthetic vectors: three exact,
six no-match, and two partial.

## Canonical model

The Engine maps evidence to four source kinds (`form_data_value`, `http_body_field`,
`http_query_value`, and `protected_resource_id`) and seven sink kinds matching the seven frozen
taxonomy families. Request headers are represented as `http_body_field` because contract v2 has no
header-specific source kind; the Engine-owned node identity remains `untrusted.http-header-value`.

Every contract path:

- starts with one proven source and ends with one selected sink;
- preserves repository-relative exact spans and ordered connectivity;
- retains semantically required guards, sanitizers, and authorization nodes;
- compresses only redundant, summarizable propagation;
- uses bidirectional span containment only within the contract's three-line maximum;
- reports unresolved calls or semantic uncertainty as partial, never detection credit;
- treats an effective terminating barrier as blocking the vulnerable match.

`fingerprint` covers taxonomy and semantic path fields while excluding names, locations, prose,
tool identity, and native rule identity. `duplicate_fingerprint` adds canonical spans to distinguish
separate source-to-sink instances. Candidate selection keeps one most-specific realizable path per
rule and sink before final semantic deduplication.

## Compatibility

`secure-json-v1` is unchanged. New `semantics_version` and `evidence_contract_v2` properties are
optional when reading older reports. SARIF adds run-level contract metadata, result-level contract
data, and two v2 fingerprints. The CLI, desktop, history, baselines, suppressions, and normal
AI-disabled report identity continue using the shared typed report.

Corrected call/value identities, source choice, and duplicate removal intentionally migrate affected
finding IDs and legacy finding fingerprints. Baseline comparison therefore reports genuinely
corrected Phase 6 paths as resolved/new; Phase 6.7 values are deterministic and frozen in tests.

## Residual limits

The implementation is bounded local static analysis. Dynamic dispatch, ambiguous aliases,
callbacks, recursion, framework middleware, runtime filesystem symlink/race behavior, and
executable-specific argument semantics are not proven. These limits are emitted in reports. No
automatic fixes, network calls, telemetry, taxonomy additions, or Secure Bench integration were
introduced.
