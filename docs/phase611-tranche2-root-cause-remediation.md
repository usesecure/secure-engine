# Phase 6.11 tranche 2 root-cause remediation

## Scope and independence

This tranche implements exactly two causes deferred by tranche 1:

1. structurally resolving a sequence-expression callee whose final value is the
   unshadowed built-in JavaScript evaluator; and
2. retaining composed filesystem-path identity while accepting confinement only
   for the same current path, a trusted root, and a separator-aware terminating
   boundary check.

The fixtures are Engine-owned synthetic programs with unrelated identifiers,
literals, paths, and structure. No known Phase 19 case was executed, rescored,
or copied. The known corpus remains development material and this tranche
produces no estimated score, independent result, ranking, superiority,
production-readiness, or complete-coverage claim.

## Pre-correction evidence

Before production edits, the focused six-test matrix compiled and ran. Four
groups failed:

- direct, parenthesized, local-alias, helper, and unique-import sequence callees
  did not produce SE1006;
- equivalent sequence callees lost argument-position and metamorphic behavior;
- a supported long-but-bounded composed filesystem path did not produce SE1003;
  and
- an exact canonical same-path confinement control still produced SE1003.

The two groups covering shadowed, member, non-final, computed, reassigned, and
runtime-limit controls already passed. This isolated the two selected causes
without reopening handler discovery, dynamic dispatch, redirect, or outbound
property connectivity.

## Cause 1: final sequence-expression callee

The JavaScript/TypeScript extractor now unwraps at most eight parentheses or
sequence nodes and considers only the final sequence value. It creates a dynamic
code sink only when that value is exactly the built-in `eval`, or a bounded
unique local variable alias whose initializer chain ends at that built-in.

Resolution rejects lexical bindings or assignments that shadow `eval`, including
parameters, local or hoisted functions, variables, imports, catch bindings, and
reassigned aliases. Members such as `object.eval`, computed members, an `eval`
that is not the final sequence value, ambiguous aliases, comments, and strings
are not sinks. The normalized-fact adapter applies the same direct built-in and
shadowing rule. Existing `Function` constructor/call handling is unchanged.

The sink retains the whole call span while `argument_values` continues to select
only the existing sensitive argument position. Taint, sanitizer, helper/import,
fixed-point, realizability, and interprocedural limits remain shared with the
other deterministic rules.

## Cause 2: composed path and exact confinement

Supported `join`, `resolve`, `normalize`, `realpath`, and `canonicalize` calls
retain the selected source identity through aliases, unique arguments/returns,
and explicit relative imports. Filesystem candidates may now be created during
the extended fixed-point rounds; redirect candidates retain the tranche 1
budget restriction.

A filesystem guard receives private proof markers only when AST structure proves
all of these properties:

- the checked value is the output of a supported outer path operation;
- the composition includes the same root used by the boundary check;
- the root resolves, within eight bindings, to a fixed value or a recognized
  non-request-controlled dependency root;
- the prefix boundary uses `path.sep` or a `sep` binding imported from `path`;
- the rejection branch dominates and terminates under the existing exceptional
  control-flow model; and
- the guarded candidate, or a current plain alias, is the exact filesystem sink
  argument and has not been reassigned after the guard.

Bare path operations require a matching platform-module import. Conventional
`path.*`/`fs.*` forms remain compatible only when the namespace is not shadowed.
An already confined trace loses its filesystem policy after any later
non-transparent transformation; plain aliases, transparent string coercions,
and uniquely resolved return binding retain it.

The proof rejects prefix checks without a separator, request-controlled roots,
multi-argument roots containing request data, different checked/sink values,
late checks, catch-and-continue, warnings, reassignment, decoy path calls, fake
module namespaces, and ambiguous helpers/imports. Lexical confinement does not
prove symlink, mount, junction, race, or runtime filesystem-state safety; the
existing explicit report limitation remains.

## Independent verification matrix

The focused suite contains 39 synthetic scenario executions across JavaScript,
JSX, TypeScript, and TSX. It covers direct, local alias, helper, unique inter-file,
control-flow, adversarial, and metamorphic forms. Every newly recognized surface
has clean or near-miss controls that remove the structural invariant rather than
renaming a helper or file.

Inherited Phase 6.6–6.11 suites pass, including exact evidence-contract vectors,
retired Engine-owned controls, path semantic identities, source/sink spans,
argument positions, fingerprints, ambiguity, try/catch/finally, fixed-point
bounds, and cache behavior. Cache v8 is an intentional miss and only v9 entries
can be reused after these private fact/program changes.

The final matrix passed formatting, strict workspace Clippy, 149 offline tests,
RustSec against the local advisory database, and all cargo-deny advisory, ban,
license, and source checks. The workspace tests cover schema and SARIF
validation, CLI/desktop parity, deterministic cold/warm behavior, privacy,
bounds, cancellation, disabled-by-default AI, baselines, history, suppressions,
and the preserved public contracts.

## Deferred backlog

This tranche deliberately does not implement:

- constructed-origin and constructed-destination redirect reasoning;
- inline outbound property/destructuring connectivity;
- computed higher-order dispatch;
- reflection, dynamic imports, non-unique imports, callback expansion, or other
  ambiguous runtime resolution.

Phase 6.11 therefore remains open for explicitly scoped future tranches. No
release, package, public version, tag, or remote state is changed here.
