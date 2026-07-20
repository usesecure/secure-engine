# Phase 6.12 tranche 4: object-literal destructuring identity

## Scope

This tranche implements only RC4 from
[the Phase 6.12 prioritization](./phase612-root-cause-prioritization.md). A value stored in a static
property of an object literal could lose its identity when a later object pattern extracted that
property into a local binding. The correction covers the demonstrated structural boundary without
inferring identity from names.

RC2 shell program-text identity, RC3 bounded value summaries, and RC5 derived guard/resource
identity remain compatible. RC1 remains outside a sound Engine boundary because an unbound name in
another lexical or module scope is not data flow. The three historical false negatives assigned to
RC4 describe causal diagnostic reach only. This tranche did not access or execute a benchmark and
does not claim a measured three-case correction or rescored result.

## Structural solution

For a bounded JavaScript or TypeScript object literal, the extractor creates a private identity
from the repository-relative path and exact literal span. Each unique static property receives a
separate child identity connected to the exact expression assigned to that property. A supported
object pattern then connects only the matching property identity to its extracted binding.

The proof requires the exact literal, exact static key, exact property value, corresponding pattern,
and a unique visible declaration. It supports shorthand properties, explicit key/value pairs,
shorthand extraction, `{ key: localName }`, direct literal destructuring, bounded nested static
object patterns, and a uniquely stored literal extracted through `const`, `let`, or `var`. The
resulting binding uses the existing helper,
arrow-summary, and unique-import propagation boundaries. Sibling properties remain separate: a
safe sibling cannot inherit another property's untrusted identity, and a key mismatch creates no
flow.

Direct destructuring has a language evaluation order that differs from source-span order: the
right-hand literal is evaluated before the pattern creates bindings. A private `evaluation_order`
value models that ordering for the extracted binding while retaining the original property and
pattern spans in public evidence. The realizability check consults this private order only for the
affected record; graph locations and public fingerprints remain location based.

## Temporal and fail-closed boundary

A stored literal is accepted only when one unique declaration is visible in the same function and
lexical scope. Reassignment, property writes, computed writes, partial-control-flow writes,
shadowing ambiguity, alias creation, escape to an unresolved helper, or an unresolved method call
before extraction invalidates the proof. Mutation after extraction does not rewrite an already
created scalar binding; reassignment of that binding still kills its identity through the existing
assignment semantics.

The property proof is refused for computed keys or member selection, spreads, rest patterns,
duplicate keys, defaults, getters, setters, methods, nested arrays or object patterns beyond eight
levels, dynamic objects, unknown helper returns, ambiguous imports, multiple aliases, exhausted
syntax bounds, and unsupported shapes. The resolver visits at most 4,096 syntax nodes and continues
to use the configured graph,
candidate, finding, cancellation, and interprocedural limits. Refusal never becomes sanitizer or
suppression evidence and never fabricates property flow.

## Evidence, cache, and compatibility

Evidence retains the original value expression, static-property pair, destructuring pair or
shorthand binding, and existing sink span. The private object identity is not exposed as a source
identifier or new public graph vocabulary. Existing rule IDs, schemas, taxonomy 1.0.0, Evidence
Contract v2, secure-json-v1, SARIF, CLI/desktop parity, and public version 0.1.7 remain unchanged.
Unaffected public finding fingerprints retain their existing extractor identity.

`ProgramRecord` now serializes private object-property identity and evaluation order. The private
cache envelope therefore advances from `secure-parse-cache-v13` to `secure-parse-cache-v14`. V13
directories remain untouched and miss safely. Cold and warm v14 scans must reproduce facts, graph,
findings, spans, and report fingerprints.

The durable decision is recorded in
[ADR 0020](./adr/0020-phase-6-12-object-literal-property-identity.md). Implementation is confined to
`crates/secure-engine/src/graph.rs`, the private cache version in
`crates/secure-engine/src/cache.rs`, independent tranche fixtures, cache regressions, and these
documents.

## Independent fixtures and verification

New synthetic fixtures cover shorthand and explicit properties, local aliases, direct and stored
literals, `const`/`let`/`var`, SE1002/SE1006/SE1007 sinks, helper and RC3 arrow propagation, a unique
inter-file import, multiple properties, deterministic spans, metamorphic renames, cache cold/warm
identity, v13 safe miss, and interprocedural depth exhaustion.

Controls cover safe siblings, wrong keys, computed keys and patterns, spreads, rest, duplicates,
defaults, getters/setters/methods, unsupported nested arrays, object and binding reassignment,
direct and computed writes, partial writes, shadowing, aliasing, unknown helpers and methods, ambiguous
imports, and unsupported depth. They contain no benchmark paths, identifiers, cases, fingerprints,
aliases, or exceptions.

The final matrix passed formatting, strict workspace Clippy, 173 permitted offline tests with zero
failures and exactly the three retired-corpus tests explicitly skipped, RustSec without fetching,
and cargo-deny offline. That suite includes the tranche fixtures, RC2/RC3/RC5 regressions, schemas,
SARIF, CLI/desktop parity, evidence spans and fingerprints, privacy/symlinks, bounds/cancellation,
cache behavior, and AI-disabled operation. No scanner, corpus, adapter, package, installation,
release, or remote mutation is part of this tranche.

This work makes no benchmark ranking, superiority, production-readiness, complete-coverage, or
measured historical correction claim.
