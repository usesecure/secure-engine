# Phase 6.7 root-cause analysis

## Scope and disclosure

The retired Phase 6 diagnostics are a fully disclosed development corpus, not an unbiased benchmark.
The permitted package hash is
`6966c507db9fb0c1efda62dd9e07ccecb80aff56962c29af27a1b0f2877cd4f4`; its regression manifest is
`68269560554cb9f3c1d837912321e2f34a1cc1bef81602aec9994efa726a7a17`. The public postmortem hash is
`6d6939febb6299d54189c9cc4c74d4f12b8a37105d4c07129b28abf59a4cf9cf`.

Using the unchanged 0.1.2 release binary independently reproduced the historical black-box result:
12 of 28 vulnerable cases emitted a finding, 16 were clean, 10 of 28 controls were flagged, and 32
findings were emitted. No Secure Bench executable was invoked.

## Systemic causes and remediation

| Boundary | Root cause | General remediation |
| --- | --- | --- |
| Parser/source | Framework values were inferred mainly from generic handler parameters | Separate framework source classification and recognize form, body, query, header, cookie, URL, and Server Action accessors structurally |
| Value identity | Repeated accessor spellings shared one key; call arguments were alphabetically reordered | Give each call site a byte-location key, retain nested call markers, preserve argument order, and prefer higher-specificity traces |
| Graph | Helper/import/return paths could bind arguments to the wrong parameter | Preserve positional inputs and propagate only uniquely resolved local calls within configured depth |
| Evidence | A generic handler source could outrank the actual selected request value | Rank explicit accessor evidence above generic parameters and handler reachability |
| Guards | Broad name/substring checks over-credited non-terminating, unrelated, or attacker-selected conditions | Require structural dominance, corresponding values, terminating failure, fixed literal destination components, separator-aware filesystem confinement, and trusted authorization context |
| Sinks | Authorization reachability was emitted for unrelated injection sinks | Restrict operation-authorization findings to protected mutations |
| Fallbacks | Constant redirect maps were not recognized | Prove object-literal values and a fixed fallback before treating a selection as safe |
| Duplicates | One sink accumulated generic and explicit paths over analysis passes | Keep the most-specific realizable candidate per rule/sink and apply semantic duplicate identity |
| Serialization | Public contract semantics were implicit | Add versioned contract-v2 JSON and SARIF projections with canonical kinds and fingerprints |

The production implementation contains no retired case ID, fixture path, benchmark alias, or
fixture-specific exception. An automated source scan enforces that property.

## Results and limits

The frozen development copy now yields 28/28 exact vulnerable paths, 28/28 clean controls, and 28
total findings with no duplicates or unrelated findings. This is development-corpus conformance
only. It supports no ranking, superiority, coverage, or production-readiness claim.

Residual risks include runtime authorization supplied outside analyzed code, dynamic call targets,
callback and reflection behavior, and filesystem runtime effects beyond lexical confinement. The
independent suite and near-miss tests exercise those boundaries without claiming completeness.
