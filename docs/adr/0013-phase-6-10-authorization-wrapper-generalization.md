# ADR 0013: bounded implementation-derived authorization summaries

Status: Accepted for Secure Engine 0.1.6.

## Context

The JavaScript/TypeScript graph previously propagated authorization primarily as a guard label.
That representation could not express helpers whose return value carries a conditional principal or
boolean authorization contract, nor compose authenticated identity with a server-selected identity.
Broad name-based propagation would suppress vulnerable near misses.

## Decision

Extract private, non-exported authorization candidates from exact syntax and control flow. Build
summaries only when value lineage reaches a recognized server identity resolver and the predicate is
fixed, fail-closed, and unambiguous. At callers, filtered-principal and boolean summaries require a
dominating truthiness guard over the same current call result. Enforced summaries require the call
itself to dominate. Identity equality requires authenticated and server-selected operands.

Inside a `try` with a handler, propagate the rejection branch's possible return and throw exits
through every enclosing handler. A return bypasses `catch`; a thrown or redirect-like rejection is
accepted only when the applicable catch body terminates on every path by returning, rethrowing, or
calling one uniquely resolved local helper whose implementation always throws. Names and unresolved,
ambiguous, recursive, or normally returning helpers are not termination evidence. Every enclosing
`finally` must complete normally without calls, abrupt completion, mutation, or loop continuation;
otherwise it may override the pending exit or execute a sensitive effect and the guard is not trusted.

Keep authentication, role, permission, ownership, tenant, identity, and general policy labels
separate internally. Project them through the existing compatible public semantic vocabulary. Do
not export private summary nodes or change the graph extractor identity. Advance the private parse
cache to v7.

## Consequences

Supported wrappers and boolean helpers can establish authorization across local, explicit
relative-import, and uniquely resolved conventional `@/` or `~/` source-root alias boundaries
without application-specific knowledge. Ambiguous imports, dynamic
dispatch, runtime middleware, caught failures, and values whose origin cannot be proven remain
conservative. External identity resolvers and server-selection APIs remain a bounded semantic catalog;
custom runtime providers outside it require an explicit direct guard or future catalog support.
After the generic exceptional completion passed its independent matrix, the fourth and final
authorized read-only dogfood pass resolved all 56 original false-positive fingerprints with no
unchanged, changed, or new finding. This is iterative application evidence rather than an independent
holdout, benchmark, ranking, production-readiness, or complete-coverage result.
