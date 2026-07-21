# Secure Engine 0.1.8-rc2 release candidate notes

Secure Engine 0.1.8-rc2 freezes the corrections already integrated through Phase 6.13. It retains
the Phase 6.12 bounded summaries and exact value identities from RC1 and adds:

- bounded forward propagation only from proven earlier scalar and exact static-property records;
- an explicit boundary that refuses to infer protected operations or exposed handlers from generic
  mutations, names, comments, or arbitrary exports; and
- exact outbound policy projection to the same unmodified constructed URL or its `href`, while
  rejecting mutable, shadowed, ambiguous, exceptional, cyclic, or depth-exhausted evidence.

The public version remains 0.1.8. Taxonomy 1.0.0, Evidence Contract v2, secure-json-v1, SARIF
2.1.0, existing rule IDs, unaffected fingerprints, CLI/desktop parity, baselines, history,
suppressions, privacy, bounds, cancellation, and disabled-by-default AI validation remain
compatible. Structured 0.1.7 reports remain compatible secure-json-v1 inputs. The private parse
cache is v16; v15 and older entries produce safe misses. No dependency or new rule is part of this
candidate.

RC1 remains a retired-corpus erratum outside the Engine's sound data-flow boundary. This candidate
has not received an independent holdout evaluation and supports no benchmark, ranking,
superiority, production-readiness, or complete-coverage claim. Computed dispatch and properties,
reflection, ambiguous calls/imports, unresolved callbacks, and unproven runtime filesystem state
remain conservative limitations.

Qualification requires two fresh, isolated, offline and locked Fedora 44 builds from this signed
candidate commit. The RPM, staged CLI and desktop binaries, and RPM-extracted CLI and desktop
binaries must be byte-identical, carry identical GNU build IDs, and contain no physical checkout or
target paths.
