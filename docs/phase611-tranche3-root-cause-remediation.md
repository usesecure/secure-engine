# Phase 6.11 tranche 3 root-cause remediation

## Scope and independence

This development tranche implements exactly two remaining general causes:

1. constructed redirect destination identity paired with an exact fixed-origin
   proof over the same current URL value; and
2. field-sensitive outbound connectivity through static object properties and
   destructuring.

The fixtures are Engine-owned synthetic programs with independent identifiers,
domains, literals, paths, and structures. Secure Bench and the known Phase 19
development corpus were not accessed or executed. No retrospective rescore,
estimated result, ranking, superiority, production-readiness, or complete
coverage claim is produced.

## Pre-correction evidence

Before production edits, the six focused test groups compiled and ran. Five
groups failed:

- a constructed redirect through a nested coercion and unique local import was
  not connected;
- exact fixed-origin controls remained findings;
- hostname-only validation incorrectly suppressed a redirect finding;
- nested destructuring lost outbound connectivity; and
- a safe sibling property tainted the complete object and produced an outbound
  false positive.

Only the group covering already-connected outbound aliases and argument
positions passed. This separated both selected causes from computed dispatch,
dynamic properties, reflection, or new sink discovery.

## Cause 1: constructed redirect and exact origin

The extractor adds private redirect proof markers only when AST structure
demonstrates an exact equality or rejection comparison between `.origin` on a
bounded, unshadowed `URL`/`URL.parse` construction and a fixed HTTP(S) origin.
Fixed origins may pass through at most eight unique immutable bindings, must
contain a complete authority, and reject userinfo, paths, queries, fragments,
whitespace, and malformed ports. Comparing the complete origin preserves
scheme, hostname, and explicit port semantics.

At guard evaluation, the checked URL must be the redirect argument, the current
plain alias of that argument, or the exact value returned by a uniquely resolved
helper. The candidate and redirect value must remain unreassigned between the
dominant terminating guard and the sink. A separately constructed URL that
shares the same input source is not equivalent. Structural proof can be carried
through a unique helper return and local import; redirect candidates are now
allowed in extended fixed-point rounds because propagation and the barrier use
the same value precision.

`new URL(userValue, fixedBase)` remains tainted because an absolute input can
replace the base origin. Prefix, suffix, substring, hostname-only, blocklist,
userinfo, request-controlled origin, mutable allowlist, wrong-object, late,
reassigned, and catch-and-continue checks do not create the private proof.
Existing fixed relative allowlists and explicit sanitizer helpers remain
compatible.

## Cause 2: outbound property connectivity

An unambiguous object literal now emits bounded records for each static leaf
property instead of tainting its container. Nested object properties retain
their full path. Recursive object destructuring preserves the selected property
through rename and nested unwrap, while keeping the historical pair span for
existing evidence and fingerprints.

Unique local calls and local imports carry exact property traces into plain or
destructured parameters. Nested `String`, `toString`, and `valueOf` calls retain
the existing transparent-coercion semantics. Argument slots preserve call
outputs, and outbound sinks continue to select only their existing sensitive
argument. A dominating reassignment invalidates the selected property and its
descendants without breaking identity-preserving self-assignment.

Computed keys, spread/merge shapes, duplicate keys, rest destructuring,
ambiguous calls/imports, unresolved callbacks, and computed dispatch do not
gain property propagation. Static sibling fields and non-sensitive arguments
remain isolated. Existing exact protocol/host policies retain the same value
binding and continue to sanitize only the selected outbound destination.

## Independent verification matrix

The focused suite contains 40 unique synthetic scenarios across JavaScript,
JSX, TypeScript, and TSX: 25 vulnerable or insufficient-control scenarios and
15 clean controls. It covers direct, property-bound, local helper, unique
inter-file, alias, nested, adversarial, mutation, argument-position, and
metamorphic forms. One direct outbound scenario additionally asserts exact
source and sink spans.

Inherited Phase 6.6–6.11 focused suites cover public Evidence Contract v2 and
taxonomy mappings, SARIF metadata, exact source/sink spans, semantic identities,
fingerprints, fixed-point and interprocedural bounds, guard dominance,
try/catch/finally behavior, cache lifecycle, and ambiguous runtime limits.
Cache v9 is an intentional miss; only v10 records can be reused after these
private program-record changes.

The frozen final matrix passed `cargo fmt --check`, workspace-wide Clippy with
all targets and features under `-D warnings`, all 155 offline tests, RustSec
without fetching advisory data, and every `cargo-deny` advisory, ban, license,
and source check. The tranche-specific expectations were 25/25 vulnerable or
insufficient-control scenarios detected and 15/15 clean controls without a
finding.

## Development closure and remaining limits

Phase 6.11 development now records six completed improvements across three
tranches: bounded local convergence, same-resource authorization, final dynamic
sequence callees, composed filesystem confinement, constructed redirect origin,
and outbound property connectivity.

The following remain intentional limits:

- computed higher-order dispatch and unresolved callbacks;
- dynamic/computed properties, ambiguous spreads, and runtime object mutation;
- reflection and runtime code/module loading;
- ambiguous imports, calls, recursion, or non-unique helpers; and
- filesystem symlink, mount, junction, race, and other runtime state not proven
  by lexical or canonical static evidence.

The next evaluation requires a new independent holdout. Phase 6.11 closure does
not make release 0.1.7 evaluated, production-ready, superior, or complete. No
package, public version, tag, release, or remote state changes in this tranche.
