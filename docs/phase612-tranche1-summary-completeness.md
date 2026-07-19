# Phase 6.12 tranche 1: bounded summary completeness

## Scope

This tranche implements only RC3 from
[the Phase 6.12 prioritization](./phase612-root-cause-prioritization.md): incomplete
value-preserving summaries for JavaScript/TypeScript arrow functions and
structurally proven `node:path` composition. RC2, RC4, and RC5 remain deferred.
The public product version remains 0.1.7.

The earlier causal inventory associated ten historical false-negative
classifications with RC3. That number is historical causal reach only. This
tranche did not access or execute Secure Bench, a retired corpus, a scanner
campaign adapter, OpenGrep, or Semgrep; it did not rescore or requalify any case
and supports no benchmark, ranking, superiority, production-readiness, or
complete-coverage claim.

## Root cause and invariants

Expression-bodied arrows were collected as functions but emitted no `@return`
record. A single unparenthesized parameter was also absent from the parameter
table. Separately, nested `node:path` calls were represented by an opaque
`@call` output even when a named or namespace import and every argument were
structurally resolvable. The common failure was a missing bounded
argument-to-result summary.

The correction preserves these invariants:

- expression and block arrow bodies use equivalent return connectivity;
- argument slot, return value, alias, field, source span, and value identity are
  retained through a supported summary;
- a local or imported helper must still resolve uniquely and remain stable;
- only `join`, `resolve`, and `normalize` from an unambiguous `node:path` named,
  namespace, or default import are value-preserving built-in summaries;
- path composition is never a sanitizer or authorization proof and clears a
  prior filesystem-confinement proof before recomposition;
- existing graph/finding schemas, rule IDs, taxonomy 1.0.0, Evidence Contract
  v2, secure-json-v1, SARIF, CLI/desktop parity, and unaffected fingerprints do
  not change;
- configured graph, record, interprocedural, cancellation, privacy, and
  deterministic fixed-point bounds remain authoritative.

The private convergence floor is twelve deterministic passes. It remains
bounded and does not increase configured interprocedural depth; the extra four
rounds let an already in-bound argument traverse parameter, local alias,
composer output, return, and caller assignment records without depending on
source ordering.

## Fail-closed boundary

The summary is refused for shadowed imports, reassigned callees, mutated
namespace objects or members, computed members, duplicate or ambiguous helper
definitions, unresolved imports, unsupported argument identity or arity,
spreads, dynamic/binary composition, and syntax or interprocedural depth beyond
the configured/private bounds. Normal variable and member inputs remain
supported because their identity is explicit in the syntax tree. Unsupported
forms stay opaque and retain the existing dynamic-resolution limitation.

## Implementation

The graph extractor now:

1. collects a single unparenthesized arrow parameter as argument slot zero;
2. emits a private return record for a supported expression body;
3. binds a returned call to its call output rather than opportunistically to
   identifiers nested inside the call;
4. retains the raw call target privately and rejects overwritten local/imported
   aliases before interprocedural return propagation;
5. marks only statically shaped `node:path` candidates and proves the exact
   import plus binding stability during analysis;
6. propagates a demonstrable input trace to the composed result without adding
   any barrier semantics.

These private serialized facts change, so the parse-cache envelope advances to
`secure-parse-cache-v11`. A V10 directory remains untouched and produces a safe
miss. The public extractor identity remains `secure-evidence-graph-v1` so the
cache change alone cannot migrate public fingerprints. The architectural
boundary is recorded in
[ADR 0017](./adr/0017-phase-6-12-bounded-value-preserving-call-summaries.md).

## Independent fixtures

The Phase 6.12 suite uses only new, synthetic Secure Engine fixtures with
unrelated identifiers and structure. It covers:

- expression and explicit-block identity arrows with exact source/sink spans;
- an arrow through a bounded helper and a uniquely exported/imported arrow;
- nested named, named-aliased, namespace, and default `node:path`
  `join`/`resolve` calls;
- an arrow plus `node:path` chain within the existing depth bound;
- fixed-value controls, shadowed imports, reassigned local/import aliases,
  namespace mutation, static and dynamic computed members, spread arguments,
  dynamic composition, duplicate helpers, and beyond-depth chains;
- an advisory check that remains vulnerable and an exact same-value terminating
  confinement guard that remains effective;
- cold/warm cache equality for findings, graph, spans, and report fingerprint,
  plus a V10-to-V11 safe miss.

An inherited generic path-semantics fixture now declares its previously implicit
`node:path` namespace import. Its safe/unsafe assertion is unchanged; the fixture
now exercises the same structurally proven import boundary as production logic.

No benchmark-specific aliases, paths, case IDs, wording, suppressions, or
exceptions are present.

## Verification and remaining risk

The final non-repeated matrix passed formatting, strict workspace Clippy with
all targets and features, and 160 offline tests. Exactly three retired-diagnostic
tests were filtered without execution because they read or scan the explicitly
prohibited retired corpus; every other workspace test ran. The 160 include all
eight Phase 6.12 tests (12 detected synthetic vulnerable scenarios and 14 clean
or fail-closed controls), JSON Schema and official SARIF validation,
CLI/desktop parity, determinism/fingerprints, cache cold/warm/V10-safe-miss,
privacy/symlink, bounds/cancellation, and AI-disabled checks.

RustSec passed without fetching, using 1,160 local advisories against 427 locked
dependencies and only the two already documented build-time exceptions.
`cargo-deny` passed advisories, bans, licenses, and sources with network access
disabled. No package was built and no external scanner or corpus was executed.

The remaining risk is intentionally conservative: arbitrary library summaries,
callbacks, reflection, computed dispatch, mutation not proven by local syntax,
runtime module replacement, and runtime filesystem behavior are not modeled.
RC2 shell-interpreter classification, RC4 object-literal destructuring, and RC5
derived guard/resource identity are not changed by this tranche.
