# Phase 6.15 cross-language security invariants

This phase uses public vulnerability patterns only as development prompts. Its fixtures are
independent synthetic vulnerable/control pairs; no public CVE is treated as independent
evaluation data.

## Tranche 1: identity and authorization ordering

JavaScript/TypeScript analysis now refuses to count a local `async` authorization helper when its
result is neither awaited nor returned. Authorization attached to a tainted identity is also
invalidated by a later decode, normalization, canonicalization, case-folding, trim, or resolution
transformation. `SE1007` remains the public rule because both cases violate its existing
authorization-before-sensitive-operation invariant.

Static coverage requires a structurally resolved local helper and a directly represented
transformation. Dynamic callees, opaque imported wrappers, mutation through reflection, ambiguous
aliases, and analysis beyond configured depth do not earn authorization credit. General
exception-to-success recovery and semantic state-machine validity remain deferred because the
current normalized facts do not prove success semantics or legal transition graphs.
