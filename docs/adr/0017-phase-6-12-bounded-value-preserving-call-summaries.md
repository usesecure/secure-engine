# ADR 0017: bound value-preserving arrow and `node:path` call summaries

Status: Accepted for the Phase 6.12 tranche 1 development branch.

## Context

The existing interprocedural model propagates values through explicit return
statements and uniquely resolved local functions. A JavaScript or TypeScript
arrow with an expression body did not emit an equivalent return record, and a
nested call to a value-preserving `node:path` composer produced an opaque call
output. Both gaps lose an otherwise demonstrable argument-to-result identity.

Treating arbitrary calls as transparent would connect sanitizers, guards,
shadowed functions, reassigned aliases, and dynamic dispatch unsafely. A durable
summary boundary therefore needs both a positive structural contract and
explicit conservative refusal cases.

## Decision

Emit the same private `@return` relationship for supported expression-bodied
arrows as for block-bodied arrows with an explicit return. Collect a single
unparenthesized arrow parameter as argument slot zero. For returned calls,
connect the return only to the call output; propagation still requires the
existing unique local/import resolution and interprocedural depth bound.

Propagate inputs to outputs for `join`, `resolve`, and `normalize` only when the
callee is a static identifier or dot member proven by exactly one named,
namespace, or default import from `node:path`. Retain the raw callee privately so alias
reassignment cannot be hidden by normalized resolution. Refuse shadowed or
mutated bindings, computed members, spreads, unsupported arity or expression
shape, duplicate or unresolved callees, and syntax deeper than the private
summary bound. The composer removes any inherited filesystem-confinement proof;
it never creates a sanitizer or authorization barrier.

Raise the private fixed-point convergence floor from eight to twelve passes
without changing configured interprocedural depth or graph/finding budgets. The
additional bounded rounds cover the new parameter-to-composer-to-return record
layers deterministically.

Keep the existing graph, finding, rule, taxonomy, Evidence Contract, secure-json,
SARIF, CLI, and desktop identities. The raw callee is not included in existing
record fingerprints, so unaffected public findings do not migrate. New summary
evidence may create findings only where the newly supported value relationship
is genuinely reachable.

Advance the private parse-cache envelope from `secure-parse-cache-v10` to
`secure-parse-cache-v11`. V10 entries miss safely and are never reinterpreted.

## Consequences

Supported arrow and `node:path` compositions preserve argument, return, alias,
and field identity across the existing bounded fixed point, including unique
local imports. Cold and warm scans remain deterministic.

Dynamic import/dispatch, computed members, reassigned callees, mutated
namespaces, spreads, ambiguous helpers, unsupported composition, and depth or
record-budget exhaustion remain conservative limits. Runtime path safety,
symlinks, mounts, races, and permissions are not inferred from lexical path
composition.
