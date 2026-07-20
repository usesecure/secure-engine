# Phase 6.13 tranche 1: retired holdout v3 propagation causes

## Evidence boundary

This tranche starts from Secure Engine commit
`189a20ea13b6803d24a444872762e178a928571d`. The retired holdout v3 at the
expected Secure Bench commit was used only as frozen, read-only causal evidence.
No Phase 31/32 case, scanner, adapter, score, or corpus command was executed or
recalculated, and no retired source was copied into Engine fixtures.

The causal universe is the 18 vulnerable observations whose frozen Engine report
contained both an untrusted-source node and the relevant sensitive-sink class,
but no source-to-sink candidate path. The superficially similar computed-dispatch
observation is not in this universe: its frozen report had a candidate path in a
different rule family, so it was not a lost-connectivity observation.

## Complete reconciliation

The 18 observations partition exactly as follows:

| Exact subcause | Count | Causal boundary |
| --- | ---: | --- |
| Scalar aliases and dominant same-value reassignments | 5 | A later assignment killed the current variable before an earlier proven alias could consume it in a subsequent snapshot. |
| Same-value control-flow joins | 2 | The same snapshot/kill interaction starved a value-preserving join record. |
| Exact literal-to-destructuring property identity | 4 | A proven static property existed, but the later scalar reassignment prevented the property/binding chain from converging. |
| Exact object-property wrapper read | 3 | A proven static property read was disconnected by the same later reassignment starvation. |
| Exact value-preserving property mutation | 1 | A static property write preserving the same value could not converge through the nested coercion output. |
| Mutable collection plus spread/index round-trip | 3 | Set mutation, iteration order, spread materialization, and positional selection require collection semantics not present in the Engine. |
| **Total** | **18** | **5 + 2 + 4 + 3 + 1 + 3 = 18.** |

This reconciliation is a causal accounting result, not a rescore or a claim about
the final tree. The retired observations remain retired.

## Selected scope

Tranche 1 selects exactly two general causes:

1. bounded forward scalar identity across explicit aliases, dominant same-value
   reassignments, and same-value joins (7 of the 18 causal observations); and
2. bounded exact static-property identity across object literals,
   destructuring/property reads, and demonstrably value-preserving property
   writes (8 of the 18 causal observations).

The remaining three collection/spread round-trips are deferred. Treating a
mutable `Set`, arbitrary iterable, spread, or index zero as a transparent value
would require runtime order and mutation assumptions. The Engine therefore does
not create that relationship.

## Implementation and fail-closed limits

The local fixed point now lets an assignment, alias, or transformation consume
already proven earlier records from the current deterministic forward pass. A
dominant reassignment to an unrelated or unproved value still removes the prior
value and descendants. Conditional writes do not become universal kills, which
preserves the existing may-flow behavior.

Each trace may cross at most 16 local value-preserving records. A record already
present in the trace is not traversed again, so cycles cannot grow paths. The
configured interprocedural depth, graph, edge, candidate, and finding bounds
remain unchanged and independently enforced.

For an assignment whose right-hand side is a call, the assignment consumes only
the private call-output identity unless the callee is an existing recognized
transparent coercion. Unknown helpers, methods, computed dispatch, ambiguous
imports/calls, and reassigned callees therefore do not become transparent.
Static property keys are still required. Spreads, computed properties,
shadowing, unrelated reassignment, ambiguous aliases, unsupported mutation, and
excess depth remain conservative no-proof boundaries.

## Synthetic coverage

The independent Phase 6.13 test module covers vulnerable JavaScript, JSX,
TypeScript, and TSX-shaped paths for scalar aliases, same-value joins, exact
object destructuring, property reads, transparent property writes, a unique
inter-file helper, and supported sinks. Adversarial controls cover shadowing,
safe reassignment, spreads, computed keys and reads, ambiguous callable aliases,
unknown property-writing helpers, unseeded cycles, and the 16-step local bound.

Cold/warm cache identity, Evidence Contract v2 presence, finding and semantic
fingerprints, graph determinism, and v14 safe miss are checked without using
retired material. These fixtures establish only the stated synthetic invariants;
they do not establish corrected holdout metrics or complete tree coverage.

## Compatibility

No public schema, SARIF projection, taxonomy coordinate, rule ID, severity,
confidence, CLI/desktop contract, AI default, or public evidence semantic changes.
The graph extractor identity remains stable, so unaffected findings retain their
identities. Newly realizable synthetic paths receive their normal deterministic
evidence and fingerprints.

Because private analysis state changes, the parse-cache envelope advances from
v14 to v15. V14 and older entries are safe misses and are never reinterpreted.
The v0.1.7 release and the durable v0.1.8-rc1 copy remain historical and intact.

## Verification

Verification used only the Engine workspace and existing offline dependency data.
Rust formatting and strict Clippy (`-D warnings`) passed. The complete offline
workspace suite passed 178 executed tests with zero failures; the three retired
corpus diagnostics were excluded explicitly by their test names. This run
included Phase 6.11 and 6.12 regression modules, CLI, desktop, Evidence Contract,
SARIF, privacy, deterministic bounds, cancellation, and disabled-AI tests.

RustSec checked 427 locked dependencies against the existing 1,160-advisory
database with no fetch and only the two already documented historical ignores
(`RUSTSEC-2026-0194` and `RUSTSEC-2026-0195`). Offline `cargo-deny` passed
advisories, bans, licenses, and sources. No scanner or retired-corpus command,
packaging, installation, release, tag, or push was performed.
