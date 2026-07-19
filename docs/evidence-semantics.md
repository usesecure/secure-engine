# Evidence semantics

Secure Engine 0.1.2 attaches an optional `semantic` object to security-relevant graph nodes and ordered path steps. The object has a stable role and identity, an optional policy or authorization scope, and a certainty. These identifiers are Engine-owned abstractions, not source names, framework claims, benchmark aliases, or replacements for the frozen taxonomy.

Secure Engine 0.1.3 adds `semantics_version: secure-evidence-semantics-v2` and projects proven paths
into public evidence contract v2. The original Phase 6.6 fields remain additive and compatible.
Secure Engine 0.1.4 retains those public versions and refines only the internal proof construction.
Secure Engine 0.1.5 retains the same public versions and binds immutable source identity, argument
position, object property, sanitizer output, and dominating barrier evidence to one propagated
trace. Role authorization remains an operation-level policy; ownership, tenant, general
authorization, guards, and sanitizers are associated with the protected value when a target trace
is available.
Secure Engine 0.1.6 retains the same public versions and adds private function summaries for
authenticated-principal returns, filtered-principal returns, boolean role/permission decisions,
and fail-closed enforcement. A summary is usable only when its implementation proves a trusted
principal lineage and its caller validates the same unreassigned result before the operation.
Identity equality additionally requires one authenticated side and one non-request-derived,
server-selected identity. Policy strings keep permission and identity distinct while projecting
through the compatible public authorization vocabulary.
Secure Engine 0.1.7 retains the same public semantics and contracts while freezing the six Phase
6.11 generalizations: bounded local convergence independent of call depth, same-resource
authorization, final dynamic sequence callees, composed filesystem identity and confinement,
constructed-redirect exact-origin reasoning, and field-sensitive outbound connectivity. The
private parse cache is v12; no public schema, taxonomy, rule ID, or unaffected fingerprint changes
as a consequence of the private Phase 6.12 summary and derived-identity records. RC5 barriers now
require the same typed URL projection or the same loaded record, complete tenant/owner guards, and
one authenticated principal lineage.

Roles distinguish untrusted sources, transformations, guards, sanitizers, authorization checks, and sensitive sinks. Authorization scopes distinguish authentication from role, ownership, tenant, and general operation authorization. Authentication alone does not suppress `SE1007`. Sanitizers and guards apply only to their matching invariant and to a corresponding value on a realizable path.

Each finding may carry `semantic_fingerprint`, a `secure-semantic-fingerprint-v1` digest of the rule and demonstrated source/sink semantic identities. It is stable across local renames, harmless statements, aliases, and helper extraction when the invariant is unchanged. The original finding fingerprint, ID, rule IDs, taxonomy coordinates, severity, and confidence remain unchanged. Report fingerprints intentionally change because new semantic evidence is part of the deterministic report; this is additive report content, not a legacy finding-identity change.

No pre-Phase-6.6 finding fingerprint is intentionally rewritten. Newly realizable alias, destructuring, wrapper, or inter-file paths can emit new findings with new fingerprints; safe paths whose exact matching policy is now proven can disappear. Those are intentional outcome changes on independently reproduced semantics. Existing findings that remain keep their legacy location-sensitive fingerprints.

## Resolution and control-flow boundary

The analyzer resolves deterministic imports, destructuring and direct aliases through a bounded chain, propagates arguments and returns across uniquely resolved local helpers, and rejects paths whose recorded edges or local source order cannot be realized. A guard must dominate the sink, reject or prevent the unsafe branch, match the affected value, and establish the relevant policy. Blocklists, suffix/substring checks, userinfo checks, warning-only branches, unrelated-value checks, and authentication-only checks are not treated as proof.

Filesystem policy requires lexical normalization plus a separator-aware root boundary. This does not prove symlink, junction, mount, race, or filesystem permission safety. Outbound and redirect policies require parsed destination components or structurally proven exact fixed membership and a safe fixed fallback. Fixed executable/argument-array invocation through supported APIs is no-shell by default unless an options object explicitly enables shell processing; executable-specific argument injection remains unresolved.

The following remain explicitly bounded: dynamic imports, ambiguous aliases, callbacks, recursion, runtime middleware, reflection, generated code, framework-specific implicit authorization, OS/filesystem state, and analysis beyond configured graph, candidate-path, finding, and inter-procedural limits. Reports expose those uncertainties as limitations instead of inferring safety.
