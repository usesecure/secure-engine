# ADR 0011: Retired-evidence precision and module-scoped flow

Status: Accepted for Secure Engine 0.1.4.

## Context

Public retrospective adjudication showed two distinct issues: an external runner had classified
normal findings exits before considering authoritative reports, and the authoritative retained
reports still did not satisfy evidence contract v2. The runner issue does not belong in Secure
Engine. The analyzer-side evidence pointed to general gaps in framework source extraction,
module ownership, positional argument propagation, structural barriers, and API shell defaults.

## Decision

Use only retired public evidence as diagnostic input. Add normalized import bindings and
destructuring records; resolve JavaScript/TypeScript helpers within the same file or through one
explicit relative import; preserve multiarity argument slots; and prove exact fixed allowlists and
fallbacks structurally. Model fixed executable argument-vector APIs as no-shell unless shell use is
explicit. Keep authentication separate from operation authorization.

Advance the private parse-cache envelope to v5 so older facts become safe misses. Keep the public
graph extractor identity stable so unchanged historical findings retain their fingerprints.
Preserve JSON, SARIF, taxonomy, evidence contract v2, AI consent, privacy, baseline, suppression,
history, and cancellation contracts.

## Consequences

Independent paired regressions gain more precise sources, module-bound paths, and safe-control
handling without case-specific production logic. Findings whose source, sink, or path semantics
change receive deterministic new identities through existing fingerprint inputs; unaffected pinned
fixtures remain stable. Dynamic resolution and runtime policy remain deliberately bounded.

This decision does not rescore a historical benchmark, access an undisclosed holdout, establish a
ranking, or support superiority, complete-coverage, or production-readiness claims.
