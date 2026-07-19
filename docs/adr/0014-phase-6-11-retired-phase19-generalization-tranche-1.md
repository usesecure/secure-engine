# ADR 0014: separate local convergence from call depth and bind operation authorization to resources

Status: Accepted for the Phase 6.11 development branch.

## Context

The private graph fixed point used `max_interprocedural_depth + 2` as its total round budget. A
shallow flow with body selection, primitive coercion, harmless aliases, a single unique helper, and
result binding could therefore stop before its sink even though it did not exceed the configured
call depth.

SE1007 also accepted operation authorization primarily through a taint trace or a generic handler
trace. A fail-closed decision over a fixed operation and the exact mutation resource could be
classified as authorization but still fail to attach to that mutation. Broadly trusting an
authorization-like name would hide wrong-resource and fail-open paths.

## Decision

Run at least eight bounded private fixed-point rounds, stopped early on convergence, and add an
ephemeral interprocedural-depth counter to each trace. Crossing
a uniquely resolved call increments that counter and is refused at the configured limit. This
separates local alias-chain length from the existing call-depth bound without changing a public
contract or cached program-record shape.

Expanded rounds may introduce a new candidate only for rule families whose structured barrier is
already modeled at matching value precision. Filesystem and redirect candidates retain the previous
`max_interprocedural_depth + 2` candidate budget because canonical-path/root-boundary and
constructed-destination/origin proofs are explicitly deferred. A candidate established within the
previous budget may still be removed when a later round proves its sanitizer. This is a general
capability boundary by rule semantics, not a case, path, framework, or fixture exception.

For sensitive mutations, accept a resource operation proof only when all of these hold:

- an existing operation-authorization semantic guard dominates the sink;
- a contained decision call has at least three argument positions and a fixed argument position;
- a distinct non-resource argument provides subject/context evidence;
- another argument is the exact sink resource or a plain local alias resolved within eight steps;
- the rejection branch proves validity on every continuing path.

The last condition is derived from AST operators. A fail-closed negation, null/false equality, or
inequality can dominate. `invalid && extraCondition` cannot dominate because `extraCondition` may be
false while the authorization is rejected. A disjunction can retain a proven invalid term because
continuation implies every disjunct was false. Existing exceptional-control-flow checks still reject
swallowed, conditional, unresolved, ambiguous, effectful, or finally-overridden exits.

Because structural dominance stored in private cached program records changes, advance the cache
envelope from `secure-parse-cache-v7` to `secure-parse-cache-v8`. Keep
`secure-evidence-graph-v1`, secure-json-v1, Evidence Contract v2, taxonomy 1.0.0, SARIF, public rule
IDs, and unaffected fingerprints unchanged.

## Consequences

Long but shallow deterministic flows in supported barrier families can converge without silently
increasing the configured interprocedural reach. Same-resource authorization controls stop producing SE1007 while missing,
wrong-resource, auth-only, conditionally terminating, swallowed, late, and name-only near misses
remain findings.

Worst-case local analysis remains explicitly bounded and cancellation is checked for every record
in every round. Flows needing more than eight ordered rounds, computed dispatch, ambiguous imports,
sequence-expression sinks, composed filesystem policies, and constructed redirect-object proofs
remain documented limitations. The private cache safely misses older envelopes; no public evidence
identity migrates solely due to the cache version.
