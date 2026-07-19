# Phase 6.11 tranche 2 independent fixtures

The executable fixtures in
`crates/secure-engine/tests/generalization_phase611_tranche2.rs` derive from two
general invariants:

1. a dynamic-code call is a sink only when the final value of a structurally
   resolved callee is the unshadowed built-in evaluator; and
2. a filesystem confinement proof applies only to the same composed path that
   reaches the sink, under a trusted root and separator-aware terminating
   boundary check.

The matrix covers JavaScript, JSX, TypeScript, and TSX; direct, helper, local
alias, unique inter-file, and control-flow forms; paired vulnerable and safe
controls; shadowing, reassignment, wrong-resource, late, swallowed, misleading,
and metamorphic variants. Identifiers, literals, paths, and structures are
Engine-owned and independent of known evaluation material.
