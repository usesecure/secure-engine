# Phase 6.8 root-cause analysis

## Evidence boundary

Phase 6.8 used only the public retired Phase 7 reports, recorded execution metadata, Phase 8
adjudication, process-status policy, taxonomy, and evidence contract v2. The immutable Phase 7
report-set digest is `cae419c2eb6831919d61b8889088bb2bf376ef5f74e3f929bc672cf65bf3e8da`;
the additive Phase 8 adjudication result is
`ddec5302afe6cf3dc60620654c905bfb2604bb8d0f39676d0a78a2889bed8f88`.
No Secure Bench executable or case was run, and no undisclosed holdout material was used.

The Phase 8 correction established that 33 exit-code-1 processes had complete, adapter-valid
reports containing findings and no scanner-internal errors. That runner classification defect is
separate from analyzer behavior. After report-authoritative adjudication, the retained reports
contained 33 unrelated findings, 13 flagged controls, and no exact or partial evidence-contract-v2
matches. Phase 6.8 therefore addresses analyzer evidence and precision generally; it does not
reinterpret the runner defect as an analyzer crash.

## General root causes and corrections

| Boundary | Root cause | General correction |
| --- | --- | --- |
| Framework sources | Imported accessors and destructured request collections lost their framework identity | Resolve local aliases before source classification and emit precise destructuring records |
| Helper ownership | Globally unique function names could link unrelated files, while explicit relative imports were not modeled | Prefer same-file definitions and otherwise require a unique explicit relative-import binding for JavaScript/TypeScript |
| Call flow | Flattened multiarity inputs could bind a tainted value to the wrong formal parameter | Preserve source order and group values by argument position before parameter propagation |
| Exact barriers | Safe controls were inferred through narrow naming conventions, while unsafe suffix or blocklist checks could look similar | Prove fixed-value membership, literal comparisons, constant fallback branches, and relevant dominance structurally |
| Process execution | Fixed executable plus argument-array calls were treated as shell execution even when the API default did not start a shell | Treat supported argument-vector APIs as no-shell unless options explicitly request shell execution |
| Authorization | Authentication-shaped helpers could be mistaken for operation authorization | Keep authentication distinct and require ownership, role, tenant, or general authorization evidence before a protected mutation |
| Contract projection | Cookie-derived request values fell through to a query classification | Project cookie inputs as HTTP body/header-class request fields under the frozen contract vocabulary |
| Cache compatibility | New normalized facts could be read from an older cache envelope | Advance the private parse-cache envelope while retaining stable public extractor identity for unaffected fingerprints |

Production code contains no retired case identifier, fixture path, report hash, or scanner-specific
exception. The implementation is based on syntax, import ownership, graph flow, and policy
semantics.

## Interpretation and limitations

The independent Phase 6.8 development corpus passes its paired vulnerable and safe assertions, but
that is regression conformance, not an external benchmark result. Phase 6.8 does not rescore or
replace Phase 7/8 and makes no ranking, superiority, complete-coverage, or production-readiness
claim.

Residual limitations include dynamic module loading, higher-order callbacks, reflective dispatch,
runtime policy supplied outside analyzed code, native filesystem behavior beyond lexical evidence,
and process argument interpretation performed by downstream programs even without a shell. These
remain explicit analysis boundaries.
