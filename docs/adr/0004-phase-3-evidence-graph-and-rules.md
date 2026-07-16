# ADR 0004: Secure Engine-owned evidence graph and deterministic rules

- Status: accepted
- Date: 2026-07-16

## Decision

Phase 3 builds a deterministic graph from Phase 2 normalized facts plus private syntax-flow records produced by the same Tree-sitter parse. The public graph contains only Secure Engine domain types. Stable fingerprints derive node, edge, path, and finding IDs from normalized roles, repository-relative spans, provenance, and ordered relationships.

Analysis propagates request and Server Action inputs through assignments, transformations, arguments, returns, and unique local helper calls. Local call traversal is bounded by configuration. Recognized sanitizers terminate propagation. Recognized auth/authorization guards create dominance evidence for later sinks. Seven built-in rules require either a demonstrated untrusted source-to-sink path or, for missing authorization, a recognized exposed handler with a directly analyzed sensitive operation and no preceding recognized guard.

Suppressions are exact project configuration entries containing rule ID, sink path, sink start byte, and reason. Applied, invalid, overly broad, and stale entries are reported. Findings are deterministically deduplicated before suppression.

## Consequences

Cold and warm cache results preserve identical graph topology, findings, and report fingerprint. Cache keys include the private graph extractor version without changing existing normalized-fact provenance or IDs. Dynamic imports, non-unique aliases, callbacks, recursion, unresolved calls, and framework middleware remain explicit limitations. Phase 3 does not claim complete vulnerability coverage.
