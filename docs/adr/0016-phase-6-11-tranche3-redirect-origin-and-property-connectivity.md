# ADR 0016: bind redirect origin and outbound fields to exact values

Status: Accepted for the Phase 6.11 tranche 3 development branch.

## Context

Constructed redirect values could reach a sink after the legacy redirect
candidate budget, while generic destination guards did not distinguish two URL
objects derived from the same source. Separately, object literals collapsed
field identity into one tainted container: this connected safe siblings and
could not recursively unwrap nested destructuring.

Name-based redirect suppression or whole-object taint would make both failures
worse. The matching barrier and propagation therefore need the same bounded,
structural value precision before extended candidates are enabled.

## Decision

Represent exact redirect origin with private guard inputs containing the checked
URL candidate, fixed trusted origin, and exact-origin proof kind. Generate the
proof only for an unshadowed structural `URL`/`URL.parse` construction, a full
fixed HTTP(S) origin, and an existing dominant terminating branch. At use, require
the same unreassigned URL or plain alias at the redirect/return boundary. Do not
equate separately constructed objects merely because their taint source matches.

Emit leaf records for static, unambiguous object literals and recursively map
static destructuring paths. Carry those exact fields through bounded unique
arguments, returns, local imports, aliases, and transparent coercions. Clear a
field and its descendants on dominant replacement. Refuse computed keys,
spread/merge ambiguity, duplicate keys, rest patterns, unresolved callbacks,
ambiguous imports, and computed dispatch.

With redirect propagation and barriers using equivalent identity, allow SE1005
candidates in the shared extended fixed-point rounds. Advance the private parse
cache from `secure-parse-cache-v9` to `secure-parse-cache-v10`; v9 entries safely
miss and are never reinterpreted.

Preserve `secure-evidence-graph-v1`, secure-json-v1, Evidence Contract v2,
taxonomy 1.0.0, SARIF 2.1.0, public rule IDs, CLI/desktop behavior, and unaffected
fingerprints.

## Consequences

Supported constructed redirects retain source identity and become clean only
after a same-value exact-origin proof. Supported outbound object remapping and
nested destructuring gain field-accurate evidence without contaminating sibling
fields or later arguments.

Computed dispatch/properties, reflection, ambiguous imports/calls, runtime
mutation, and runtime filesystem state remain explicit limits. Development
closure requires a new independent holdout before any later evaluation claim.
