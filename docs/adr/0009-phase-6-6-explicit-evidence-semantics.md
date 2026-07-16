# ADR 0009: Explicit bounded evidence semantics

## Status

Accepted for Secure Engine 0.1.2.

## Context

Source spellings and source order alone do not establish value correspondence, realizable flow, sanitizer policy, or operation-specific authorization. Findings also need a stable semantic identity that survives harmless code movement without replacing their compatible location-sensitive identity.

## Decision

Attach additive Engine-owned semantic roles and identities to relevant graph nodes and path steps. Track corresponding values through assignments, arguments, returns, aliases, and uniquely resolved helpers. Require structural dominance, terminating rejection, matching values, and policy-specific semantics before treating a guard as protective. Bound alias, candidate-path, graph, and inter-procedural resolution and report uncertainty. Add a separate semantic fingerprint while preserving the Phase 6.5 finding fingerprint and frozen taxonomy contract.

## Consequences

JSON, SARIF, baselines, optional AI previews, and the desktop can explain the demonstrated semantic family. Equivalent paths are comparable across renames and helper extraction, while authentication-only, blocklist, warning-only, unrelated-value, and filesystem lexical-only near misses remain visible. The implementation does not claim whole-program, framework-runtime, or filesystem-runtime proof.
