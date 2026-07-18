# Phase 6.10 independent fixture methodology

The frozen handoff is used only for aggregate reproduction and root-cause boundaries. Production
logic contains no application helper name, source path, alias, role literal, case identifier,
suppression, or allowlist derived from CMS Nova.

`generalization_phase610.rs` was authored before the production correction and initially reproduced
all three false-positive classes. It contains paired safe and vulnerable examples across:

- JavaScript, JSX, TypeScript, and TSX;
- Node.js, Express, Next.js App Router, and Server Actions;
- local helpers, caller-side control flow, aliases, destructuring, explicit relative imports, and
  conventional `@/` and `~/` source-root module aliases;
- return, throw, and framework redirect failure termination;
- authenticated principal, fixed role, fixed permission, and server-selected identity guarantees.

Adversarial mutations cover unconditional true helpers, deceptive helper names/comments/paths,
attacker-controlled role values, caught throw/redirect-and-continue failures, nullable fallback,
non-dominating checks, reassignment, wrong-value
identity comparisons, and ambiguous relative/source-root imports. Existing Phase 6.7–6.9 suites
retain dynamic,
unresolved, malformed, bounded, cancellation, privacy, sanitizer, ownership, tenant, and historical
fingerprint coverage.

A safe fixture passes only when the exact implementation establishes a trusted authorization
guarantee and a same-result guard dominates the sensitive operation. Its vulnerable counterpart
must continue to produce `SE1007`. The frozen application scan occurred once, read-only, after the
initial independent corpus and implementation freeze. It exposed a missing generic module-topology
case (`@/` aliases), which was then covered by independent paired and ambiguous-import fixtures
before the bounded resolver was extended. An explicitly authorized iterative second pass retired
55 fingerprints and retained one, exposing a blanket `try`/`catch` conservatism boundary. A new
paired fixture proves that a return-terminated rejection inside `try` remains fail-closed while a
caught thrown rejection that continues to the sink remains vulnerable. Additional fixtures prove
that a side-effect-free `finally` preserves a pending return, while return, throw, redirect/call,
assignment mutation, and `continue` in `finally` are conservative. The final application pass left
six exact fingerprints. A subsequent independent matrix reproduces their general exceptional-flow
shape without application vocabulary: throw-to-rethrow, throw-to-return, structurally always-throwing
local helpers, mixed return/throw branches, multiple sinks, and nested terminating handlers are safe.
Logging/continuation, conditional or swallowed catches, sensitive `finally` work, continuation-
overriding `finally`, user-controlled decoys, outer swallowing catches, unresolved helpers, and
optimistically named helpers that return normally remain findings. The correction was implemented
and independently verified before the explicitly authorized fourth and final application scan. That
iterative dogfood pass resolved all 56 original exact fingerprints with no unchanged, changed, or new
finding. It was not a one-shot benchmark or independent holdout, and no fifth scan was performed.
