# ADR 0023: bind exact outbound policy to one URL projection

Status: Accepted for Phase 6.13 tranche 3.

## Context

An outbound guard can prove exact protocol and host policy for a constructed
`URL` while the network sink consumes that object's `href`. Treating every
property as equivalent would be unsafe; refusing every projection loses the
proof. Fixed string collections may also be wrapped in an unshadowed
`Object.freeze`, but names such as allowed or trusted cannot establish their
contents or immutability.

Recoverable parser errors are a separate reliability boundary. The presence of
a diagnostic cannot justify suppressing a finding.

## Decision

Record a private outbound proof only when one constructed URL object supplies
both protocol and hostname/host components, the protocol is compared exactly
to a fixed literal, and the host is compared exactly or checked against a
structurally fixed string collection. Permit a single-argument unshadowed
`Object.freeze` wrapper around that fixed collection.

Apply the proof only to the same source-derived, unmodified URL object or its
exact `href`, under a dominant fail-closed guard. Follow aliases and unique
local returns to depth eight. Reject conjunctions that do not terminate every
invalid case, mutation, reassignment, shadowing, computed properties, spreads,
ambiguous calls, cycles, exceptional continuation, and exhausted depth.

Do not infer allowlists from identifiers, comments, fixture labels, or case
IDs. Do not suppress findings solely because parser recovery occurred.

Advance the private cache envelope from v15 to v16. Keep public graph identity,
schemas, Evidence Contract, SARIF, rule IDs, taxonomy, and fingerprint
algorithms unchanged.

## Consequences

Exact outbound policy can follow the semantically equivalent serialized URL
value without authorizing unrelated fields or objects. Mutable or ambiguous
collections and projections fail closed. Older cache entries are safe misses.
The decision makes no historical metric, retired-corpus recovery, production
readiness, ranking, or complete-coverage claim.
