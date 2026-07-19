# ADR 0015: resolve final dynamic callees and bind confinement to composed paths

Status: Accepted for the Phase 6.11 tranche 2 development branch.

## Context

JavaScript sequence-expression callees were absent from normalized call names,
so an untrusted value reaching `(sideEffect, eval)(value)` had no dynamic-code
sink. Treating any textual `eval` leaf as a sink would instead misclassify local
functions, parameters, object properties, computed members, reassigned aliases,
and non-final sequence values.

Filesystem composition already preserved partial transformation evidence, but
the old separator check inferred roots and normalization from identifier text.
Tranche 1 therefore withheld new late-round filesystem candidates: enabling them
without equally precise barriers produced known control regressions.

## Decision

Resolve a JavaScript/TypeScript sequence callee by unwrapping at most eight
parenthesized or sequence values and selecting only the final operand. Accept
`eval` only when bounded lexical inspection proves that the global built-in is
not shadowed. Accept a local alias only when a unique variable-initializer chain
ends at that same built-in; do not resolve members, computed values, ambiguous
imports, assignments, reflection, or dispatch. Keep the existing sensitive
argument selection, source tracing, realizability, and call-depth bounds.

Represent filesystem confinement with private guard inputs containing the exact
candidate, root, and lexical/canonical proof kind. Generate them only from a
supported outer path operation, a trusted bounded root origin, a structurally
separator-aware prefix rejection, and an existing dominant terminating branch.
At evaluation, require the same current candidate or plain alias at the sink and
reject any reassignment after the guard. Invalidate a carried filesystem policy
across later non-transparent transformations.

With equivalent value precision on propagation and barriers, allow filesystem
candidates in extended fixed-point rounds. Keep redirect on its earlier
candidate budget because constructed-origin proof remains deferred.

Advance the private parse-cache envelope from `secure-parse-cache-v8` to
`secure-parse-cache-v9`. Do not reinterpret v8 records: they safely miss and are
recomputed. Preserve `secure-evidence-graph-v1`, secure-json-v1, Evidence Contract
v2, taxonomy 1.0.0, SARIF 2.1.0, public rule IDs, and unaffected fingerprints.

## Consequences

Supported indirect evaluator calls gain precise SE1006 evidence without trusting
names alone. Supported composed paths gain SE1003 connectivity through bounded
helpers/imports, while exact lexical or canonical same-path controls remain
clean. Shadowing, wrong-resource, root-control, weak-prefix, late, swallowed,
reassigned, decoy, and ambiguous cases remain conservative.

Lexical containment still does not prove runtime symlink, mount, junction, race,
or permission safety. Dynamic imports, reflection, computed dispatch, redirect
object origins, and outbound property remapping remain explicit limitations.
