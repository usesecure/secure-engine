# Phase 6.12 tranche 2: derived guard and resource identity

## Scope

This tranche implements only RC5 from
[the Phase 6.12 prioritization](./phase612-root-cause-prioritization.md). It
does not change source discovery, sink classification, public rules, or public
contracts. RC3 remains compatible; RC2 and RC4 remain deferred, and RC1 remains
non-remediable in Engine because unbound cross-module names are not evidence of
data flow. The public product version remains 0.1.7.

The preserved prioritization associated five historical redirect false
positives and four historical authorization false positives with RC5. Those
nine classifications are causal reach, not a measured result of this tranche.
No benchmark was accessed or executed and no rescoring was performed.

## Structural solution

The JavaScript/TypeScript extractor emits private typed derivation facts for
relationships that syntax can prove:

- original destination input to an unshadowed `URL`/`URL.parse` result;
- that exact URL object to a relative `pathname`, `search`, or `hash`
  projection and to a supported concatenation of those projections;
- requested resource identifier to a statically shaped protected-record load;
- the load result to its canonical `id`, including bounded direct aliases and
  unambiguous property destructuring;
- loaded-record tenant and owner properties to two dominant mismatch guards;
- both guards to one authenticated principal lineage; and
- the guarded record or canonical ID to the sensitive operation's resource
  argument.

These are private record inputs representing directed identity edges. They
retain the source record span and parser provenance. They do not create a new
public graph edge kind, sanitizer, suppression, taxonomy mapping, or finding
contract field.

Duplicate parser/graph guard representations at the same span cannot bypass
the typed proof. When an exact-origin proof exists at a guard location, every
equivalent redirect-policy record at that location is evaluated through the
same RC5 chain.

## Exact barrier conditions

An exact-origin redirect guard is effective for a relative projection only
when the fixed origin is a valid HTTP(S) origin, which fixes both protocol and
authority; the mismatch branch terminates; the guard dominates the sink; the
URL constructor is unshadowed; the destination input, URL object, and selected
projection remain unchanged; and every dynamic part of the redirect is a
supported projection of that same URL object. A complete URL object remains
compatible with the pre-existing exact-origin behavior.

A protected-record barrier is effective only when a supported read operation
has exactly one statically identifiable requested ID; the sink receives the
same loaded record or its canonical `id`; separate tenant and owner mismatch
guards both terminate and dominate; both compare the loaded record with the
same authenticated principal lineage; and the request ID, record, canonical
ID, and principal remain unchanged. Explicit external operation-policy calls
retain their pre-existing behavior and are not reinterpreted as RC5 record
identity.

## Fail-closed boundary

The proof is refused for suffix, substring, partial blocklist, conditional, or
non-dominating checks; a different URL; absolute reconstruction; computed URL
properties; ambiguous aliases; unsupported expressions; unresolved helpers;
reassignment; receiver calls or property mutation; and try/catch/finally paths
that may continue.

Resource proof is refused for request-supplied principals, decoy records,
different operation IDs, tenant-only or owner-only policy, advisory branches,
reassigned IDs, record/principal mutation, ambiguous object identity, computed
or spread load selectors, dynamic dispatch, and incomplete identity. Unknown
getters and exhausted syntax, interprocedural, graph, or candidate bounds are
uncertainty, never evidence of safety.

The implementation recognizes only a bounded static load shape and semantic
tenant/owner/identity property families. Names alone never establish safety:
the complete load, guard, trusted-principal, dominance, mutation, and sink
relationships must all resolve.

## Independent fixtures

The new Secure Engine suite uses unrelated synthetic inventory and navigation
domains. Redirect controls cover direct, helper-mediated, full
`pathname + search + hash`, and uniquely imported sink-alias forms. Adversarial
fixtures cover suffix and substring checks, a second URL, object and input
mutation, projection reassignment, caught rejection, active `finally`,
conditional/non-dominating enforcement, absolute reconstruction, computed
properties, ambiguous aliases, and an unresolved helper.

Authorization controls cover direct, helper-mediated authenticated-principal,
control-flow, metamorphic rename, direct-ID load, object-selector load, unique
alias, and property-destructuring forms. Adversarial fixtures cover a decoy
record, request principal, each partial policy, non-termination, late guards,
reassigned canonical ID, record mutation, a different operation resource,
ambiguous selection, catch continuation, and active `finally`.

No fixture uses benchmark paths, identifiers, case text, case IDs,
fingerprints, or special-case suppressions.

## Cache and compatibility

The new private identity markers are serialized in `ProgramRecord.inputs`, so
the parse-cache envelope advances from `secure-parse-cache-v11` to
`secure-parse-cache-v12`. V11 directories remain untouched and miss safely;
only V12 entries are reusable. Cold and warm V12 analysis must reproduce the
same facts, graph, findings, spans, and report fingerprint.

The public extractor identity remains `secure-evidence-graph-v1`. Rule IDs,
taxonomy 1.0.0, Evidence Contract v2, secure-json-v1, SARIF, CLI/desktop
behavior, AI-disabled defaults, and unaffected finding fingerprints remain
unchanged. RC3 arrow and `node:path` summaries keep their existing bounds and
tests.

The durable boundary is recorded in
[ADR 0018](./adr/0018-phase-6-12-derived-guard-resource-identity.md).

## Verification and remaining risk

The final verification matrix passed formatting, strict workspace Clippy, and
165 permitted offline tests. Exactly three retired-corpus tests were explicitly
filtered and not executed. The total includes the five tranche-specific tests
covering 7 clean controls and 27 vulnerable/adversarial scenarios, all RC3
regressions, schemas, SARIF, CLI/desktop parity, spans/fingerprints, cold/warm
cache identity and V11 safe miss, privacy/symlinks, bounds/cancellation, and
AI-disabled operation.

RustSec passed without fetching against 1,166 local advisories and 427 locked
dependencies with only the two already documented build-time exceptions.
Offline cargo-deny passed advisories, bans, licenses, and sources. No package
was built and no external scanner or corpus was executed.

Remaining risk is conservative: arbitrary ORM APIs, runtime getters,
framework middleware, dynamic dispatch, reflection, runtime policy behavior,
and identity beyond the supported static bounds are not inferred. This tranche
makes no benchmark ranking, superiority, production-readiness, complete
coverage, or measured nine-case correction claim.
