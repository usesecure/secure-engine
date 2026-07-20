# Phase 6.13 tranche 2 independent fixture boundary

Executable fixtures live in
`crates/secure-engine/tests/generalization_phase613_tranche2.rs`. They use a
synthetic ledger domain and prove the current structural boundary rather than a
historical expected result.

The positive path combines an exposed Server Action with an already supported
repository mutation. Controls cover local `Map.set`, `Set.add`, computed
property writes, cache-like generic methods, bound aliases, local wrappers,
dynamic receivers, unregistered exports, and explicit route registration.
The export/registration pair asserts graph handler evidence; it does not change
the compatible request-source fallback used for already supported mutations.

No historical fixture path, identifier, literal, source text, case ID, or
fingerprint is present. The fixtures make no claim that generic mutations are
safe; they prove only that sensitivity requires a supported or future explicit
domain contract.
