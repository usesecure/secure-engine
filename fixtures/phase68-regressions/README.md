# Phase 6.8 independent regression corpus

The Phase 6.8 corpus is authored independently in Secure Engine from general vulnerability and
safe-control patterns. It does not copy Secure Bench fixtures, identifiers, paths, hashes, or
answers. The executable corpus generator and exact assertions live in
`crates/secure-engine/tests/remediation_phase68.rs`.

The balanced 56-scenario matrix covers all seven SE1001–SE1007 families across JavaScript, JSX,
TypeScript, and TSX; Node.js, Express, Next.js App Router, and Server Actions; and direct,
helper-mediated, inter-file aliased, and control-flow-sensitive topology. Additional cases cover
identifier renaming, harmless statement insertion, destructuring, exact barriers, ambiguous
aliases, cycles, recursion, authentication-versus-authorization, blocklists, suffix checks, and
shell opt-in behavior.

This is a development regression corpus, not an unseen benchmark and not evidence of production
readiness, superiority, complete coverage, or performance on any undisclosed holdout.
