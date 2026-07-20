# Phase 6.13 tranche 1 independent fixtures

The executable fixtures live in
`crates/secure-engine/tests/generalization_phase613_tranche1.rs`. They were
written from two Engine-owned invariants: a proven forward scalar identity may
survive a bounded explicit alias/reassignment/join, and a proven static object
property may survive a bounded literal/destructuring/read or value-preserving
write path.

Positive fixtures exercise supported vulnerable flows. Paired adversarial
controls cover shadowing, unrelated reassignment, spreads, computed properties,
ambiguous callable aliases, opaque mutation helpers, cycles, and depth
exhaustion. Identifiers, literals, paths, structures, and fingerprints are
synthetic and independent of retired benchmark material.
