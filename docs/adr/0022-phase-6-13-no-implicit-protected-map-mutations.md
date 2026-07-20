# ADR 0022: do not infer protected operations from generic mutations

Status: Accepted for Phase 6.13 tranche 2.

## Context

Eight historical authorization expectations use `Map.set`. Six lack both a
structurally recognized handler and a sensitive sink; two Server Actions have a
handler but no sink. Treating generic mutations as protected operations would
also classify local tables, caches, memoization, indexes, test doubles, sets,
and object state as authorization boundaries.

The current RC5 contract deliberately requires a supported protected-record
load, canonical resource identity, an authenticated principal, separate tenant
and owner guards, dominance, and the same resource at the operation.

## Decision

Do not change entrypoint discovery or sink classification. Do not promote
`Map.set`, `Set.add`, property assignment, generic methods, arbitrary exports,
request-shaped parameters, names, or comments. Keep private cache v15 because
analysis semantics do not change.

Lock the boundary with independent synthetic tests. Existing structurally
recognized repository/service mutations remain supported; generic local
mutations remain non-sinks; and exposure continues to require framework syntax
or registration.

## Deferred opt-in design

A future `secure-protected-operation-contract-v1` may declare exact entrypoint,
principal resolver, resource loader, canonical-ID projection, required tenant
and owner policies, and a protected mutation symbol or receiver. Every symbol
must resolve uniquely from a repository-relative module and explicit argument
positions. A declaration must never directly suppress a finding.

The analyzer must continue to prove the request-to-resource flow, authenticated
principal lineage, loaded canonical resource, both terminating dominant guards,
and the same resource at the declared operation. Ambiguous aliasing, mutation,
dynamic dispatch, ambiguous wrappers, continuing catch/finally paths, and depth
exhaustion fail closed. Adding this input is a separate schema, compatibility,
cache, and implementation decision.

## Consequences

The eight historical expectations remain explicit domain-knowledge limits.
This avoids false authorization findings for local state and preserves RC5
principal/resource identity. No public contract, report, fingerprint, cache,
rule, or product behavior changes in this tranche.
