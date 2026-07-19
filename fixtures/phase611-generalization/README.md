# Phase 6.11 independent generalization fixtures

These Engine-owned synthetic fixtures exercise two bounded structural causes:

1. a field selected from an HTTP body remains the same untrusted value after
   primitive coercion, aliases, and uniquely resolved local or imported helper
   calls; and
2. a fail-closed operation-authorization decision applies to a sensitive
   mutation only when it dominates the mutation and is bound to the same
   protected resource value.

The executable fixture sources live in
`crates/secure-engine/tests/generalization_phase611.rs` so every scenario is
created in an isolated temporary repository. They use unrelated identifiers,
locations, and wording and do not contain benchmark cases, paths, fingerprints,
or case identifiers.

The corpus includes vulnerable cases, safe controls, misleading names and
comments, wrong-resource guards, conditional termination, swallowed rejection,
late guards, local and imported helpers, and harmless metamorphic edits.
