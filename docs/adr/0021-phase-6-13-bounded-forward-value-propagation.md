# ADR 0021: bounded forward value propagation

Status: Accepted for Phase 6.13 tranche 1 development.

## Context

The local data-flow fixed point used one immutable taint snapshot per round. A
dominant reassignment correctly killed stale state, but that kill could occur
after an earlier value-producing record and before the next snapshot. Explicit
aliases, same-value joins, and exact object-property records could therefore be
permanently starved even though every individual relationship was proven.

Removing reassignment kills or treating arbitrary calls and object operations as
transparent would create paths across safe overwrites, opaque mutations,
computed properties, spreads, and ambiguous dispatch.

## Decision

Assignment, alias, and transformation records may read already proven state from
the current deterministic forward pass. Existing dominant kills remain in place,
and candidates still must pass edge realizability and source-order checks.

Add a private local-value depth of 16 to every trace and refuse a transformation
when that bound is exhausted or its record node already occurs in the path.
Configured interprocedural depth remains a separate bound.

For assignment right-hand-side calls, use the call-output identity. Preserve
direct inputs only for the existing recognized transparent coercions. Unique
local/import summaries can therefore prove a call output through the existing
bounded mechanism, while unresolved helpers and methods remain opaque.

Advance the private parse-cache envelope to `secure-parse-cache-v15`; v14 and
older entries miss safely. Keep the graph extractor version and every public
schema, rule, SARIF, taxonomy, Evidence Contract, CLI, desktop, and AI contract
unchanged.

## Consequences

Supported scalar and static-property paths converge without weakening safe
reassignment or ambiguity controls. Cycles and excessive local chains stop
without findings. Mutable collection/spread round-trips, computed properties,
heap alias mutation, reflection, ambiguous calls/imports, callbacks, and runtime
state remain unsupported.
