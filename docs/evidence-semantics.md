# Phase 6.6 evidence semantics

Secure Engine 0.1.2 attaches an optional `semantic` object to security-relevant graph nodes and ordered path steps. The object has a stable role and identity, an optional policy or authorization scope, and a certainty. These identifiers are Engine-owned abstractions, not source names, framework claims, benchmark aliases, or replacements for the frozen taxonomy.

Roles distinguish untrusted sources, transformations, guards, sanitizers, authorization checks, and sensitive sinks. Authorization scopes distinguish authentication from role, ownership, tenant, and general operation authorization. Authentication alone does not suppress `SE1007`. Sanitizers and guards apply only to their matching invariant and to a corresponding value on a realizable path.

Each finding may carry `semantic_fingerprint`, a `secure-semantic-fingerprint-v1` digest of the rule and demonstrated source/sink semantic identities. It is stable across local renames, harmless statements, aliases, and helper extraction when the invariant is unchanged. The original finding fingerprint, ID, rule IDs, taxonomy coordinates, severity, and confidence remain unchanged. Report fingerprints intentionally change because new semantic evidence is part of the deterministic report; this is additive report content, not a legacy finding-identity change.

No pre-Phase-6.6 finding fingerprint is intentionally rewritten. Newly realizable alias, destructuring, wrapper, or inter-file paths can emit new findings with new fingerprints; safe paths whose exact matching policy is now proven can disappear. Those are intentional outcome changes on independently reproduced semantics. Existing findings that remain keep their legacy location-sensitive fingerprints.

## Resolution and control-flow boundary

The analyzer resolves deterministic imports, destructuring and direct aliases through a bounded chain, propagates arguments and returns across uniquely resolved local helpers, and rejects paths whose recorded edges or local source order cannot be realized. A guard must dominate the sink, reject or prevent the unsafe branch, match the affected value, and establish the relevant policy. Blocklists, suffix/substring checks, userinfo checks, warning-only branches, unrelated-value checks, and authentication-only checks are not treated as proof.

Filesystem policy requires lexical normalization plus a separator-aware root boundary. This does not prove symlink, junction, mount, race, or filesystem permission safety. Outbound and redirect policies require parsed destination components or a named exact allowlist and a safe fixed fallback. Fixed executable/argument-array invocation with shell processing disabled is not shell command injection; executable-specific argument injection remains unresolved.

The following remain explicitly bounded: dynamic imports, ambiguous aliases, callbacks, recursion, runtime middleware, reflection, generated code, framework-specific implicit authorization, OS/filesystem state, and analysis beyond configured graph, candidate-path, finding, and inter-procedural limits. Reports expose those uncertainties as limitations instead of inferring safety.
