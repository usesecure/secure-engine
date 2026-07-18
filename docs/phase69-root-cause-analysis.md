# Phase 6.9 root-cause analysis

## Evidence boundary

Phase 6.9 used only the seven retired Phase 15 handoff artifacts permitted by the task. Their
SHA-256 values are pinned in `fixtures/phase69-retired-handoff/summary.json` and verified by the
Phase 6.9 handoff test. No Secure Bench executable, fixture source, expectation, evaluator,
Phase 14 raw report, future holdout, or undisclosed artifact was read or executed. Secure Bench was
not modified. The separately disclosed adapter projection defect affected ten vulnerable cases and
is explicitly outside Secure Engine.

The disclosed historical population contains 112 cases: 56 vulnerable cases and 56 safe controls.
The retained diagnostic findings covered all 56 vulnerable cases and 40 controls. Under the
authoritative evidence contract v2 projection, vulnerable outcomes were 10 exact, 0 partial, and
46 no-match. Forty controls were false positives and 16 were clean. The handoff did not export
benchmark source, so Phase 6.9 preserves this exact retired accounting but does not claim a new
benchmark rescore.

## General root causes and corrections

| Boundary | Disclosed evidence | Engine-side cause | General correction |
| --- | ---: | --- | --- |
| Source identity | 30 primary, 21 contributing | Generic request parameters, unscoped aliases, and propagated container identity could eclipse the actual introducing expression | Emit explicit framework sources, scope aliases by qualified function, reject ambiguous targets, and carry one stable source node plus relative field identity through propagation |
| Source spans | 16 primary, 32 contributing | Iterative propagation could replace the introducing expression with a declaration, call site, or later occurrence | Retain immutable source path/start/end metadata and select multiple sources deterministically by specificity and repository-relative span |
| Value connectivity | contributing across the handoff | Flattened inputs could join unrelated formal parameters, sibling fields, or sink options | Preserve argument slots, object-property slots, relative field identity, formal binding paths, and return correspondence; keep unresolved dispatch conservative |
| Guard recognition | 32 contributing | Barrier-like names or historical value-name overlap could suppress unrelated flows | Require a structurally recognized, terminating, dominating guard with a trace linked to the same source identity |
| Sanitizer recognition | 8 contributing | A sanitizer call could be applied to the original value or propagated too broadly through a helper | Attach sanitizer policy only to the returned transformed trace and accept exact allowlists only when they protect that trace |
| Dominance and association | 40 contributing | Provisional candidates and global barrier application could survive or disappear independently of final fixed-point evidence | Re-evaluate candidates at the fixed point, propagate a dominating caller barrier only with its matching argument, remove only the candidate proven safe, and associate ownership/tenant/general authorization with the protected value; role authorization remains a distinct operation-level policy |
| Overbroad controls | 40 primary | All call arguments could be treated as sensitive sink data, and unconditional reassignment did not kill stale identity | Select semantic sink positions, separate object fields, kill stale unconditional assignments, preserve conditional uncertainty, and reject ambiguous aliases/boundaries |

Production code contains no Phase 15 case identifier, benchmark path, expected span, fixture wording,
or scanner-specific exception. The corrections are expressed in parser records, scoped name
resolution, graph traces, dominance, and sink semantics.

## Fingerprint behavior

Taxonomy 1.0.0, evidence contract v2, `secure-json-v1`, and the public graph extractor identity are
unchanged. Harmless renaming, statement insertion/reordering, and helper extraction preserve the
semantic fingerprint in the independent tests. Findings whose selected source, evidence path,
sink input, or effective barrier changes can receive a deterministic report/evidence fingerprint;
that is intentional because their evidence changed. Historical Phase 6.7 pinned semantic
fingerprints and unaffected compatibility fixtures remain passing. The private parse-cache envelope
advances to v6 so v5 records become safe misses.

## Interpretation and limitations

The exact retired accounting is historical diagnostic evidence, not a rerun. The independently
authored cause pairs are regression conformance, not a future holdout or external score. Dynamic
imports, reflective dispatch, higher-order callbacks, recursive cycles, ambiguous aliases,
unresolved imports, framework middleware, and runtime-only policy remain conservative boundaries.
Role authorization can prove an operation-level policy without binding to the resource identifier;
ownership, tenant, general authorization, guards, and sanitizers require value association where a
target trace is available.

Phase 6.9 makes no ranking, superiority, production-readiness, complete-security-coverage, or future
Secure Bench performance claim.
