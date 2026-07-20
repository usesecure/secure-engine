# ADR 0020: bind destructured values to exact object-literal properties

Status: Accepted for the Phase 6.12 tranche 4 development branch.

## Context

An object pattern names the property to read, but a scalar-name alias graph does not by itself prove
which value an object literal stored under that key. Treating the whole object as one value permits
cross-property propagation. Treating destructuring as an ordinary textual assignment also orders a
direct pattern before its right-hand literal, contrary to JavaScript evaluation semantics.

## Decision

Create a private location-derived identity for each bounded exact object literal and a distinct
child identity for every unique static property. Connect the exact property expression to that
child and connect only a structurally matching supported object-pattern entry to its local binding.
Support shorthand and explicit property forms, shorthand and aliased extraction, direct literals,
bounded nested static object patterns, and uniquely visible stored literals declared with `const`,
`let`, or `var`.

Record a private evaluation order for direct-literal binding records so the literal properties are
evaluated before pattern binding while retaining original source spans in evidence. Use that order
only for internal record traversal and path realizability. Do not change public graph locations,
extractor identity, schemas, or fingerprint construction.

Require a unique visible declaration and no relevant reassignment, mutation, shadowing, alias, or
escape before extraction. Reject computed keys or access, spreads/rest, duplicates, defaults,
getters/setters/methods, nested arrays or object patterns beyond eight levels, unknown helper
returns, ambiguous imports, partial writes, and exhausted bounds. A mutation after extraction does
not retroactively alter the scalar binding; an explicit reassignment of that binding retains the
existing kill semantics.

Advance the private parse-cache envelope from `secure-parse-cache-v13` to
`secure-parse-cache-v14`, because serialized `ProgramRecord` property identities and evaluation
order change. Keep public version 0.1.7, `secure-evidence-graph-v1`, rule IDs, schemas, taxonomy
1.0.0, Evidence Contract v2, secure-json-v1, SARIF, CLI/desktop output, and unaffected finding
fingerprints unchanged.

## Consequences

Supported property-to-binding paths preserve exact value identity and evidence across existing
helper, arrow-summary, and unique-import boundaries without propagating between siblings. Direct
destructuring follows language evaluation order without falsifying public spans.

Dynamic or ambiguous shapes intentionally remain unresolved. The proof may refuse benign programs
when an object escapes before extraction or configured bounds are exhausted; this is the chosen
fail-closed tradeoff. RC2, RC3, and RC5 remain compatible. RC1 remains outside the Engine's sound
remediation boundary.
