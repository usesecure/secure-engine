# ADR 0018: bind guards to typed derived value and resource identity

Status: Accepted for the Phase 6.12 tranche 2 development branch.

## Context

A dominant fail-closed guard is not sufficient evidence by itself. Redirect
policy can validate one parsed URL while a different or absolute value reaches
the sink. Resource policy can validate one record or principal while a
different ID is mutated. Treating similar names, properties, or policy types as
identity would convert false positives into false negatives.

The existing records already retain value, call, field, dominance, trusted
principal, and control-flow information. RC5 requires a durable rule for when
those facts may be composed into a barrier.

## Decision

Represent supported derivations as private typed markers on the exact
source-spanned records that establish them. URL markers bind one original input
to one unshadowed constructed URL and bind only dot-property `pathname`,
`search`, and `hash` projections or statically relative concatenations to that
same object. A fixed exact HTTP(S) origin supplies the protocol-and-authority
proof. Equivalent guard records at the same source span share the typed proof;
an untyped duplicate cannot bypass it.

Resource markers bind one statically shaped requested-ID argument to one
supported protected-record load. Authorization requires two separate dominant
terminating guards: tenant and owner. Each must relate a property of that exact
loaded record, including a bounded unambiguous alias or destructured property,
to the same principal whose lineage resolves to an authenticated source. The
sensitive operation must use the record or its canonical `id`.

Reject the proof after reassignment, descendant mutation, receiver calls,
computed or spread properties, ambiguous aliases, unresolved helpers, partial
policy, request-supplied identity, alternate resources, conditional guards, or
try/catch/finally continuation. Existing configured bounds remain hard limits.
Unsupported identity is not a barrier.

Keep explicit external operation-policy authorization separate from the new
derived-record proof. Do not change public rules, graph edge kinds, schemas,
taxonomy, Evidence Contract, secure-json, SARIF, CLI/desktop behavior, or the
public extractor identity.

Advance the private parse-cache envelope from `secure-parse-cache-v11` to
`secure-parse-cache-v12` because serialized record inputs now contain the typed
identity markers. V11 entries miss safely and are never reinterpreted.

## Consequences

Exact relative redirects and same-record tenant/owner authorization can use an
existing guard only through a demonstrable identity chain. Wrong-value,
wrong-object, wrong-principal, partial, mutated, caught, and ambiguous paths
remain reportable.

The model intentionally does not infer arbitrary ORM reads, getters, helper
effects, runtime middleware, or policy semantics. Semantic property families
help classify an edge but never prove it without load identity, authenticated
principal lineage, termination, dominance, stability, and same-resource sink
use. RC3 remains independent; RC2 and RC4 remain deferred, and RC1 remains
outside Engine's sound remediation boundary.
