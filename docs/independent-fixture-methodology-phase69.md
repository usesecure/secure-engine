# Phase 6.9 independent fixture methodology

Phase 6.9 separates two evidence sets:

1. `fixtures/phase69-retired-handoff/summary.json` pins only the seven permitted artifact hashes and
   the exact disclosed aggregate accounting. It imports no benchmark source or case-level answer.
2. `generalization_phase69.rs` and `remediation_phase69.rs` contain independently authored Engine
   regressions based on general framework and security semantics.

The cause matrix contains seven vulnerable/control pairs: source identity, source span, value
connectivity, guard recognition, sanitizer recognition, dominance/value association, and overbroad
false-positive propagation. It covers JavaScript, JSX, TypeScript, and TSX; Node.js, Express,
Next.js App Router, and Server Actions; and direct, helper-mediated, inter-file aliased, and
control-flow-sensitive paths. Every vulnerable case must emit exactly its intended rule with the
exact introducing source span, exact sink file/span prefix, and an ordered contract-v2 path whose
edges are all connected. Every paired control must emit zero findings.

Additional adversarial and metamorphic checks cover:

- multiple source and sink arguments and position swaps;
- safe and unsafe object destructuring, including renamed fields;
- unique, function-scoped, ambiguous, stale, and conditionally reassigned aliases;
- guard before/after sink, wrong-value guard, terminating throw, and early return;
- exact allowlists, weak suffix checks, sanitized transformed values, and original unsafe values;
- source tie-breaking, variable/function renames, harmless insertions and reordering, helper
  extraction/inlining, barrier addition/removal/weakening, and stable semantic fingerprints;
- recursion, cycles, callbacks, dynamic imports, unresolved imports, and reflective dispatch as
  bounded limitations rather than fabricated connected paths;
- host-path privacy and deterministic report construction.

The existing independent Phase 6.8 28/28 matrix and Phase 6.7 70/70 matrix remain separate
compatibility gates. Phase 6.9 fixtures do not copy Secure Bench code, paths, aliases, case IDs,
expected spans, or wording. Passing them supports only the implemented regression invariants.
