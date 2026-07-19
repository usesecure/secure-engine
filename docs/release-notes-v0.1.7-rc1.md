# Secure Engine 0.1.7 release candidate notes

Version 0.1.7 freezes the completed Phase 6.11 development line. It includes:

- bounded local convergence independent of configured call depth;
- authorization bound to the same protected resource;
- resolution of a final unshadowed dynamic sequence-expression callee;
- composed filesystem path identity with separator-aware confinement;
- constructed redirects protected by exact-origin proof over the same URL value;
- outbound property and destructuring connectivity through supported helpers and imports; and
- private parse cache v10, with older cache envelopes producing safe misses.

The release retains secure-json-v1, Evidence Contract v2, taxonomy 1.0.0, SARIF 2.1.0, existing
rule IDs, unaffected fingerprints, CLI/desktop parity, baselines, history, suppressions, privacy,
bounds, cancellation, and disabled-by-default AI validation.

This candidate has not received an independent holdout evaluation. It is not a final Phase 19
result and supports no benchmark, ranking, superiority, production-readiness, or complete-coverage
claim. Computed dispatch, computed/dynamic properties, reflection, ambiguous calls/imports,
unresolved callbacks, and unproven runtime filesystem behavior remain conservative limitations.
