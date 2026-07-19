# Phase 6.12 tranche 0: root-cause analysis and remediation prioritization

## Scope and limits

This tranche is a documentation-only causal analysis of the preserved Secure Engine/native
observations from Secure Bench Phases 27–30. Phase 27–30 is a retired, public, post-open diagnostic
corpus. It is not a new independent holdout, and this analysis supports no ranking, superiority,
production-readiness, or complete-coverage claim.

The authoritative Phase 30 result is 112/112 completed, with 23 TP, 9 FP, 47 TN, and 33 FN
(precision 0.718750, recall 0.410714, F1 0.522727, balanced accuracy 0.625000, zero retries). This
tranche did not execute a scanner, campaign adapter, or corpus case; it did not rescore or modify the
preserved result. Native and capability-normalized lanes were kept separate. No failed, unavailable,
or missing evidence was converted to zero.

The review used Secure Engine commit `1e3d300cb7092097f21be164b6c403b71f2b2520` and read-only
Secure Bench commit `30a7bc9d3708c83bab56c4f341dcdaf9343ff5ef` (tree
`65456e01ec81d01fa04817ba34ae420d6b334d5f`). The principal preserved inputs were:

- `phase27/manifest-v2.json` (`6478cd1d86c62956d9e7ce07cee5387fe011d7beb22b292b3d3bbaebb3795912`);
- `phase27/contracts/evidence-contract-v2.json`
  (`1181e027efb0e731eec9d038e96457103ee0e30113f46ba1e8588dada33fdf95`);
- `phase29/raw-evidence-index.json`
  (`e487449b99a11c83f15a1668d9344dd3632b757e80a1f02f32f82c26fa8d4798`);
- `phase29/results.json` (`2af8d14104e4972b916dfeb04cfaef5f4e8b53ad4b196a068bc3bdf5f6f16b6e`);
- `phase30/certified-results.json`
  (`def9de33d942b9146d69056470dfcfffdbb1761d7272f8b92dd7c5711185476d`);
- `phase30/comparison.json` (`d1953b4e80526b0016253f8193615a47ca01b7c302c021de275671c026ef857d`).

No OpenGrep or Semgrep result informed the diagnosis. Their capability-normalized lanes were not
used to infer or imitate tool-specific behavior.

## Method

For each preserved Secure Engine/native observation, the Phase 30 classification was joined to the
Phase 29 native observation and raw report, the Phase 27 case metadata and expectation, and the
corresponding frozen source. A case entered the inventory only when the preserved classification was
FN or FP. The source, expected evidence span, extracted graph nodes, relevant finding or its absence,
and the responsible Secure Engine stage were inspected. The implicated Engine implementation was
then traced through [the parser and graph model](./evidence-graph-and-rules.md) and
[semantic limits](./evidence-semantics.md).

Each anomaly has exactly one primary cause. A contributor is recorded only where another limitation
would remain after the primary cause were corrected. The counts below group existing classifications;
they do not create a new benchmark result.

Cause identifiers used in the inventory are:

- **RC1 — retired-corpus source/expectation mismatch:** the inter-file callee declares `candidate`
  but its sensitive expression uses an unbound caller-local identifier (`transitValue` or
  `approvedLookingValue`). The expected connected edge crosses lexical/module scope without a real
  binding. This is not an Engine remediation target; following it would be unsound.
- **RC2 — shell-interpreter argv misclassification:** a fixed `execFileSync` executable is downgraded
  to argument execution even when that executable is `/bin/sh` and tainted data is part of the
  `-c` program text.
- **RC3 — incomplete value-preserving call summaries:** expression-bodied arrows have no extracted
  return flow, while nested `node:path` composition produces an untainted call-output key. Both are
  instances of a call result that should preserve input influence but has no bounded summary.
- **RC4 — object-literal destructuring extraction gap:** `{ signal: value } = { signal: tainted }`
  produces no assignment record because the object-literal initializer has no scalar base identity.
- **RC5 — derived guard/resource identity mismatch:** a valid dominating guard is extracted, but the
  guard proof is not attached to a sink value derived from the guarded object. This appears as URL
  origin proof to URL-property redirect (five FP) and loaded-record authorization to canonical record
  ID mutation (four FP).

## Exact reconciliation

| Primary cause | FN | FP | Total |
|---|---:|---:|---:|
| RC1 retired-corpus source/expectation mismatch | 14 | 0 | 14 |
| RC2 shell-interpreter argv misclassification | 6 | 0 | 6 |
| RC3 incomplete value-preserving call summaries | 10 | 0 | 10 |
| RC4 object-literal destructuring extraction gap | 3 | 0 | 3 |
| RC5 derived guard/resource identity mismatch | 0 | 9 | 9 |
| **Total** | **33** | **9** | **42** |

The FN equation is `14 + 6 + 10 + 3 = 33`; the FP equation is `9 = 9`. No anomaly is
unclassified or counted twice.

| Cause | Rule distribution | Framework distribution | Format distribution | Topology distribution |
|---|---|---|---|---|
| RC1 (14 FN / 0 FP) | SE1001–SE1007: 2 FN each | express 4, next-app-router 4, node 3, server-actions 3 | javascript 4, jsx 4, tsx 3, typescript 3 | inter-file-aliased 14 |
| RC2 (6 FN / 0 FP) | SE1001: 6 FN | express 1, next-app-router 1, node 2, server-actions 2 | javascript 2, jsx 1, tsx 2, typescript 1 | control-flow-sensitive 2, direct 2, helper-mediated 2 |
| RC3 (10 FN / 0 FP) | SE1002: 1, SE1003: 6, SE1005: 1, SE1006: 1, SE1007: 1 FN | express 1, next-app-router 2, node 5, server-actions 2 | javascript 2, jsx 3, tsx 2, typescript 3 | control-flow-sensitive 3, direct 4, helper-mediated 3 |
| RC4 (3 FN / 0 FP) | SE1002: 1, SE1006: 1, SE1007: 1 FN | express 1, server-actions 2 | javascript 1, jsx 1, typescript 1 | control-flow-sensitive 2, helper-mediated 1 |
| RC5 (0 FN / 9 FP) | SE1005: 5, SE1007: 4 FP | express 2, next-app-router 2, node 2, server-actions 3 | javascript 2, jsx 2, tsx 3, typescript 2 | control-flow-sensitive 3, direct 3, helper-mediated 3 |

## Compact anomaly inventory

`Absent(0)` means that the native report contained no finding for the vulnerable case. `Finding(1)`
means that the native report emitted the listed rule for a control; its expected barrier was present
in source but absent from `effective_barriers`. Evidence locations are the frozen contract's source
and sink for FN, or barrier and sink for FP.

| # | Case / pair | Label / result | Rule | Framework | Format | Topology | Relevant finding | Engine stage and primary cause | Concrete evidence |
|---:|---|---|---|---|---|---|---|---|---|
| 3 | `aurora-0e15af1d23466efaa7` / `orbit-se1005-64124c076966fb` | control / FP | SE1005 | express | jsx | helper-mediated | Finding(1), guard recorded but ineffective | barrier application — RC5 (URL projection) | `entry.jsx:18 -> entry.jsx:19`; guarded `destination.origin`, sink uses pathname/search/hash |
| 5 | `aurora-1375361a99d2111c48` / `orbit-se1007-1834a9d14cdbed` | vulnerable / FN | SE1007 | server-actions | jsx | control-flow-sensitive | Absent(0) | extraction/alias — RC4 | `entry.jsx:6 -> entry.jsx:13`; object-literal destructuring emits no `transitValue` record |
| 8 | `aurora-1a497aadc573077a4e` / `orbit-se1001-ca317a71dc7f5b` | vulnerable / FN | SE1001 | next-app-router | typescript | control-flow-sensitive | Absent(0) | sink classification — RC2 | `entry.ts:9 -> entry.ts:13`; `/bin/sh`, `-c`, tainted program text classified as fixed argv |
| 13 | `aurora-25a3b89088138fe15c` / `orbit-se1001-3535aac4112ed6` | vulnerable / FN | SE1001 | server-actions | tsx | control-flow-sensitive | Absent(0) | sink classification — RC2 | `entry.tsx:8 -> entry.tsx:14`; shell program text contains the source-derived value |
| 16 | `aurora-2d8e9603b51fbffef3` / `orbit-se1005-d9e52c8e0c63c7` | control / FP | SE1005 | server-actions | tsx | direct | Finding(1), guard recorded but ineffective | barrier application — RC5 (URL projection) | `entry.tsx:14 -> entry.tsx:15`; exact origin rejection dominates derived relative redirect |
| 21 | `aurora-40fc0de62dc11b47a2` / `orbit-se1007-de9972445664c2` | vulnerable / FN | SE1007 | next-app-router | javascript | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.js:8 -> policy.js:4`; callee parameter `candidate` unused, sink uses unbound `transitValue` |
| 22 | `aurora-43145d27d2bad2fff6` / `orbit-se1003-718f848e4b1f1b` | vulnerable / FN | SE1003 | express | tsx | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.tsx:8 -> policy.tsx:5`; callee parameter unused, path sink uses unbound `transitValue` |
| 23 | `aurora-433eb2e5a1b68b1a9d` / `orbit-se1003-3bfddc5abd5184` | vulnerable / FN | SE1003 | node | typescript | helper-mediated | Absent(0) | call propagation — RC3 (path composer) | `entry.ts:10 -> entry.ts:19`; `resolve(base, candidate)` call output has no input-to-return summary |
| 26 | `aurora-4b4da1e02a38a24315` / `orbit-se1004-bb3c4da4a1eb37` | vulnerable / FN | SE1004 | server-actions | typescript | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.ts:7 -> policy.ts:2`; callee parameter unused, `fetch` uses unbound `transitValue` |
| 27 | `aurora-4ea413803f009f2c13` / `orbit-se1003-9480de59cc710f` | vulnerable / FN | SE1003 | next-app-router | javascript | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.js:8 -> policy.js:5`; callee parameter unused, path sink uses unbound `transitValue` |
| 30 | `aurora-6092efcb359ee32ee3` / `orbit-se1001-a670cbf4e603c6` | vulnerable / FN | SE1001 | server-actions | tsx | direct | Absent(0) | sink classification — RC2 | `entry.tsx:8 -> entry.tsx:12`; weak replacement still reaches `/bin/sh -c` program text |
| 33 | `aurora-654ee1cffa1fb210b7` / `orbit-se1003-5bdf19ebeaccb6` | vulnerable / FN | SE1003 | express | tsx | helper-mediated | Absent(0) | call propagation — RC3 (path composer) | `entry.tsx:10 -> entry.tsx:21`; lexical replacement and helper remain influential through `resolve` |
| 38 | `aurora-6c889bc24ce161ce4a` / `orbit-se1001-fb809adedb7329` | vulnerable / FN | SE1001 | node | javascript | helper-mediated | Absent(0) | sink classification — RC2 | `entry.js:9 -> entry.js:20`; local parameter reaches `/bin/sh -c`, then is downgraded as argv |
| 40 | `aurora-6dcd68095644dfb976` / `orbit-se1001-9a80d47281f575` | vulnerable / FN | SE1001 | node | javascript | direct | Absent(0) | sink classification — RC2 | `entry.js:9 -> entry.js:11`; direct alias enters shell program text |
| 43 | `aurora-707683102ef9b2e08a` / `orbit-se1007-f8d9a6d68074c7` | vulnerable / FN | SE1007 | express | tsx | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.tsx:8 -> policy.tsx:4`; callee parameter unused, sink uses unbound `approvedLookingValue` |
| 48 | `aurora-7724f259d2007fa8b3` / `orbit-se1007-801c3741264d7f` | control / FP | SE1007 | node | typescript | direct | Finding(1), two auth guards recorded but ineffective | barrier application — RC5 (record identity) | `entry.ts:13 -> entry.ts:15`; tenant/owner rejection dominates update by loaded record ID |
| 50 | `aurora-7a8e1c8562d1062a4b` / `orbit-se1003-4b8671385bd874` | vulnerable / FN | SE1003 | next-app-router | javascript | control-flow-sensitive | Absent(0) | call propagation — RC3 (arrow + path composer) | `entry.js:10 -> entry.js:14`; expression arrow lacks return flow and `resolve` lacks a preserving summary |
| 53 | `aurora-865cc3574b8ccd6142` / `orbit-se1006-6661227d7208f4` | vulnerable / FN | SE1006 | node | jsx | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.jsx:8 -> policy.jsx:2`; callee parameter unused, dynamic-code sink uses unbound `transitValue` |
| 54 | `aurora-89b2939d1b71291696` / `orbit-se1006-6130b57424bf9b` | vulnerable / FN | SE1006 | express | typescript | control-flow-sensitive | Absent(0) | extraction/alias — RC4 | `entry.ts:7 -> entry.ts:10`; object-literal destructuring loses the source before `Function` |
| 56 | `aurora-8ca0719a8b9a015b49` / `orbit-se1005-3647d3fc20592d` | control / FP | SE1005 | server-actions | tsx | control-flow-sensitive | Finding(1), guard recorded but ineffective | barrier application — RC5 (URL projection) | `entry.tsx:13 -> entry.tsx:14`; fail-closed origin guard dominates relative redirect |
| 58 | `aurora-9017b7a3a292b71547` / `orbit-se1007-715e1c46fe02b4` | vulnerable / FN | SE1007 | node | typescript | helper-mediated | Absent(0) | call propagation — RC3 (arrow return) | `entry.ts:7 -> entry.ts:19`; identity arrow has no `@return` trace before mutation helper |
| 60 | `aurora-93d4043651777193c9` / `orbit-se1001-8c4d87e4543862` | vulnerable / FN | SE1001 | next-app-router | typescript | inter-file-aliased | Absent(0) | contract/source boundary — RC1; RC2 contributes | `entry.ts:8 -> policy.ts:4`; callee parameter unused, shell text uses unbound `transitValue` |
| 61 | `aurora-9531c341fd806134dd` / `orbit-se1001-b94f31dc9d96eb` | vulnerable / FN | SE1001 | express | jsx | helper-mediated | Absent(0) | sink classification — RC2 | `entry.jsx:9 -> entry.jsx:20`; destructured caller value reaches local helper's shell text |
| 63 | `aurora-994c684017459e0c31` / `orbit-se1004-8821977ffa2f39` | vulnerable / FN | SE1004 | node | tsx | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.tsx:8 -> policy.tsx:2`; callee parameter unused, `fetch` uses unbound `transitValue` |
| 64 | `aurora-9a0333c50bf161e7dd` / `orbit-se1002-89978e1b8f2368` | vulnerable / FN | SE1002 | node | jsx | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.jsx:8 -> policy.jsx:2`; callee parameter unused, SQL expression uses unbound `transitValue` |
| 65 | `aurora-9dc8cda58995922d18` / `orbit-se1007-9916a523e47fd3` | control / FP | SE1007 | next-app-router | javascript | control-flow-sensitive | Finding(1), two auth guards recorded but ineffective | barrier application — RC5 (record identity) | `entry.js:14 -> entry.js:16`; exact tenant/owner guard precedes canonical-ID update |
| 70 | `aurora-a68fc6a56569322afa` / `orbit-se1007-59b5b624c958ea` | control / FP | SE1007 | server-actions | jsx | direct | Finding(1), two auth guards recorded but ineffective | barrier application — RC5 (record identity) | `entry.jsx:13 -> entry.jsx:15`; rejected mismatch cannot reach update of authorized record ID |
| 71 | `aurora-aa0705eded863f7004` / `orbit-se1006-e6fd3f4aacc22a` | vulnerable / FN | SE1006 | next-app-router | tsx | direct | Absent(0) | call propagation — RC3 (arrow return) | `entry.tsx:7 -> entry.tsx:12`; identity arrow output is not connected to `Function` |
| 77 | `aurora-b0dbeef73c128089b2` / `orbit-se1003-10de49f0b19419` | vulnerable / FN | SE1003 | server-actions | jsx | control-flow-sensitive | Absent(0) | call propagation — RC3 (path composer) | `entry.jsx:9 -> entry.jsx:17`; advisory boolean does not sanitize, but nested `resolve` loses influence |
| 78 | `aurora-b497bfbbe4b6fd0cbf` / `orbit-se1005-023b69239acc9e` | control / FP | SE1005 | node | javascript | helper-mediated | Finding(1), guard recorded but ineffective | barrier application — RC5 (URL projection) | `entry.js:16 -> entry.js:17`; helper-local exact origin rejection dominates derived redirect |
| 80 | `aurora-b8363361eb21438438` / `orbit-se1003-ae0a1822c032d8` | vulnerable / FN | SE1003 | node | typescript | direct | Absent(0) | call propagation — RC3 (path composer) | `entry.ts:10 -> entry.ts:13`; swallowed rejection is irrelevant; `resolve` output lacks taint |
| 83 | `aurora-c6fad2f3685db348ca` / `orbit-se1002-f7746ecb3ffacc` | vulnerable / FN | SE1002 | server-actions | javascript | helper-mediated | Absent(0) | extraction/alias — RC4 | `entry.js:6 -> entry.js:14`; object-literal destructuring loses the value before SQL helper |
| 89 | `aurora-cbdbb8583f2f4321e8` / `orbit-se1002-5670b76abfe935` | vulnerable / FN | SE1002 | node | jsx | control-flow-sensitive | Absent(0) | call propagation — RC3 (arrow return) | `entry.jsx:7 -> entry.jsx:13`; identity arrow output is not connected to SQL construction |
| 90 | `aurora-cc4fd0db94b6a21cf2` / `orbit-se1005-a5e35aab135bb8` | control / FP | SE1005 | next-app-router | typescript | control-flow-sensitive | Finding(1), guard recorded but ineffective | barrier application — RC5 (URL projection) | `entry.ts:13 -> entry.ts:14`; exact origin guard controls pathname/search/hash redirect |
| 92 | `aurora-d16b7b86d65ef7c5e0` / `orbit-se1001-f731fb13bacb5a` | vulnerable / FN | SE1001 | express | jsx | inter-file-aliased | Absent(0) | contract/source boundary — RC1; RC2 contributes | `entry.jsx:8 -> policy.jsx:4`; callee parameter unused, shell text uses unbound `transitValue` |
| 95 | `aurora-d7f17314dd1642e5e9` / `orbit-se1002-d6185de03fdc35` | vulnerable / FN | SE1002 | server-actions | javascript | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.js:7 -> policy.js:2`; callee parameter unused, SQL expression uses unbound `transitValue` |
| 96 | `aurora-d92f3ee5f56ae4421e` / `orbit-se1005-71e401578fd601` | vulnerable / FN | SE1005 | express | jsx | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.jsx:8 -> policy.jsx:2`; callee parameter unused, redirect uses unbound `transitValue` |
| 100 | `aurora-de06ea3f96407e4cea` / `orbit-se1007-9b0f73fff303d6` | control / FP | SE1007 | express | tsx | helper-mediated | Finding(1), two auth guards recorded but ineffective | barrier application — RC5 (record identity) | `entry.tsx:23 -> entry.tsx:25`; helper guard authorizes loaded record before canonical-ID update |
| 102 | `aurora-dfc697e3a3b189024b` / `orbit-se1005-c8e9dbecdd698f` | vulnerable / FN | SE1005 | node | javascript | direct | Absent(0) | call propagation — RC3 (arrow return) | `entry.js:7 -> entry.js:10`; identity arrow output is not connected to redirect |
| 106 | `aurora-f33f08f0c4c38774ff` / `orbit-se1003-9fe8f82f2bf2a2` | vulnerable / FN | SE1003 | server-actions | jsx | direct | Absent(0) | call propagation — RC3 (path composer) | `entry.jsx:9 -> entry.jsx:14`; misleading alias still influences un-summarized `resolve` output |
| 108 | `aurora-f646072c5dace2cdd9` / `orbit-se1006-67a145adaa2ae4` | vulnerable / FN | SE1006 | server-actions | javascript | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.js:7 -> policy.js:2`; callee parameter unused, dynamic-code sink uses unbound `transitValue` |
| 112 | `aurora-fd429703e8ca3744a8` / `orbit-se1005-41f9f03c6c25b9` | vulnerable / FN | SE1005 | next-app-router | typescript | inter-file-aliased | Absent(0) | contract/source boundary — RC1 | `entry.ts:8 -> policy.ts:2`; callee parameter unused, redirect uses unbound `transitValue` |

## Distributions

| Rule | FN | FP | Total |
|---|---:|---:|---:|
| SE1001 | 8 | 0 | 8 |
| SE1002 | 4 | 0 | 4 |
| SE1003 | 8 | 0 | 8 |
| SE1004 | 2 | 0 | 2 |
| SE1005 | 3 | 5 | 8 |
| SE1006 | 4 | 0 | 4 |
| SE1007 | 4 | 4 | 8 |
| **Total** | **33** | **9** | **42** |

| Framework | FN | FP | Total |
|---|---:|---:|---:|
| express | 7 | 2 | 9 |
| next-app-router | 7 | 2 | 9 |
| node | 10 | 2 | 12 |
| server-actions | 9 | 3 | 12 |
| **Total** | **33** | **9** | **42** |

| Source format | FN | FP | Total |
|---|---:|---:|---:|
| javascript | 9 | 2 | 11 |
| jsx | 9 | 2 | 11 |
| tsx | 7 | 3 | 10 |
| typescript | 8 | 2 | 10 |
| **Total** | **33** | **9** | **42** |

| Topology | FN | FP | Total |
|---|---:|---:|---:|
| control-flow-sensitive | 7 | 3 | 10 |
| direct | 6 | 3 | 9 |
| helper-mediated | 6 | 3 | 9 |
| inter-file-aliased | 14 | 0 | 14 |
| **Total** | **33** | **9** | **42** |

## Cause grouping and prioritization

| Cause | Rules | Frameworks / topologies | Estimated correction reach | Regression risk and required negative controls | Likely Engine components | Decision |
|---|---|---|---|---|---|---|
| RC1 | SE1001–SE1007 | all four frameworks; inter-file-aliased only | 14 FN are explained, but zero are sound Engine-fix targets | Extreme risk: connecting unbound identifiers across modules would invent data flow. Require lexical binding, parameter use, and unique import resolution. | No Engine change; retired-corpus errata boundary | Deferred / non-remediable in Engine |
| RC2 | SE1001 | all four frameworks; direct, helper, control-flow | 6 FN | Medium. Preserve fixed non-shell executable argv safety; distinguish shell program text, positional data, fixed scripts, and explicit `shell:false`. | `graph.rs` sink classification and sensitive argument selection | Deferred |
| RC3 | SE1002, SE1003, SE1005, SE1006, SE1007 | all four frameworks; direct, helper, control-flow | 10 FN: five arrow-return and five path-composer primaries | Medium. Do not summarize ambiguous/shadowed calls, conditionals, callbacks, or side-effectful returns; path normalization is not confinement. | `graph.rs` record extraction, call summaries, taint propagation; focused parser facts/tests | **Selected 1** |
| RC4 | SE1002, SE1006, SE1007 | express and server-actions; helper and control-flow | 3 FN | Medium. Computed keys, spreads, rest, duplicate keys, defaults, and reassignment must remain conservative. | `graph.rs` destructuring/object-field records and value identity | Deferred |
| RC5 | SE1005, SE1007 | all four frameworks; direct, helper, control-flow | 9 FP: five redirect and four authorization controls | Medium-high because an unsound guard suppresses a real finding. Require same object/resource, complete policy, fail-closed dominance, no reassignment, and trusted principal. | `graph.rs` guard proof, derived values, resource authorization; `semantics.rs`; focused cache invalidation in a future tranche | **Selected 2** |

The selected causes have a causal reach of 10 FN and 9 FP in this preserved inventory. This is a
prioritization estimate, not a rescored result. RC3 is selected over the six-case RC2 because one
bounded summary abstraction spans five rule families and both local functions and known library
composition. RC5 is selected because it accounts for every FP, spans all frameworks and topologies,
and directly targets precision without suppression or benchmark-specific exceptions.

## Selected cause 1: bounded value-preserving call summaries (RC3)

### Structural solution

Introduce one private, bounded call-effect summary representation that maps selected argument
identities to return identity. Populate it from two independently justified sources:

1. a uniquely resolved local expression-bodied arrow whose body is a supported value expression;
2. an unshadowed, uniquely resolved `node:path` composition operation whose output preserves the
   influence of every dynamic path segment.

The summary must create ordinary argument/return propagation edges with source spans and depth
accounting. It must not mark a path operation as a sanitizer or confinement proof. Existing explicit
`return` propagation and public finding contracts remain unchanged. Likely work is concentrated in
`crates/secure-engine/src/graph.rs`, with narrowly scoped normalized facts in
`crates/secure-engine/src/parser.rs` only if the graph cannot retain the required syntax provenance.

### Limits and fail-closed conditions

- Require a unique lexical function/callee and stable import binding; dynamic dispatch, callbacks,
  recursion, shadowed built-ins, computed callees, and ambiguous imports receive no fabricated
  summary and retain an explicit limitation.
- Summarize only modeled argument-to-result influence. A constant return, different argument,
  conditional branch, closure capture, mutation, throw, sequence expression, or unknown helper does
  not become a transparent identity summary by name.
- Treat `resolve`, `join`, and `normalize` as influence-preserving, never as validation. Only a
  separate structural confinement proof may sanitize SE1003.
- Apply existing interprocedural, graph, and candidate budgets; exhausted or missing evidence is
  uncertainty, never evidence of safety.

### Future synthetic fixtures

All fixtures must be original and structurally different from the retired corpus. Proposed
vulnerable fixtures include an invoice reference passed through a concise arrow into a raw SQL call,
a request fragment passed through a typed async concise arrow into dynamic evaluation, and an upload
name composed with an imported path utility before a filesystem read. Add a two-step case combining
a concise arrow with a path composer to prove summary composition.

Negative and adversarial controls must cover arrows returning a fixed literal, another parameter, a
validated replacement, or a conditional result; shadowed and reassigned helpers; ambiguous imports;
computed property calls; callbacks; path functions receiving only fixed segments; a genuine
canonicalization-plus-root-containment barrier; and budget exhaustion. Metamorphic renaming and
format variants must not change semantics.

### Regression gates and acceptance

Run formatting, strict Clippy, the complete offline workspace suite, RustSec, cargo-deny, focused
JavaScript/TypeScript parser and graph tests, public schema/taxonomy/Evidence Contract checks,
fingerprint stability checks, and deterministic cold/warm scans over only the new independent
fixtures. Acceptance requires every supported concise-arrow and path-composition vulnerable fixture
to produce a connected source-to-sink path, every control to remain clear, no new finding for
ambiguous/shadowed cases, explicit limitations when a summary is unavailable, and unchanged public
fingerprints where semantics did not change.

## Selected cause 2: derived guard and resource identity (RC5)

### Structural solution

Extend private value identity with explicit, typed derivation edges rather than name matching:

- URL construction binds the parsed URL object to its input destination; `origin` proof may protect
  only modeled relative projections of that same, unreassigned object after a dominating fail-closed
  rejection.
- A protected-record load binds the loaded object and canonical ID to the exact requested resource;
  a trusted-principal ownership/tenant proof may protect only a later sensitive operation on that
  same loaded resource and principal.

Guard extraction already exists in all nine FP reports; the change is to make the existing proof
applicable only through a demonstrable derivation chain. Likely work is in
`crates/secure-engine/src/graph.rs` (`redirect_guard_proves_values`, resource authorization, property
and object records) and `crates/secure-engine/src/semantics.rs`. A future private cache-format bump
may be necessary, but public rule IDs, schemas, taxonomy 1.0.0, Evidence Contract v2, SARIF, CLI and
desktop behavior, and unaffected fingerprints must remain compatible.

### Limits and fail-closed conditions

- URL proof requires exact protocol/origin policy, a terminating rejection, dominance, the same URL
  object, supported relative projections, and no reassignment or catch/finally continuation.
- Resource proof requires a trusted principal, the same load result and requested resource,
  complete required predicates, terminating mismatch, dominance, and an operation bound to the
  loaded record. Authentication alone, attacker claims, one-sided predicates, decoy records, or
  unrelated IDs are insufficient.
- Unknown property getters, alias ambiguity, mutation, dynamic calls, unresolved helpers, partial
  control flow, and budget exhaustion never become an effective barrier.
- The solution must not suppress findings by path, fixture text, case ID, fingerprint, framework, or
  rule-specific benchmark exception.

### Future synthetic fixtures

Use unrelated domains and structures. Redirect controls should parse a callback URL, reject a
non-matching origin, and emit a relative route derived from the same guarded object; vulnerable
counterparts should use suffix checks, a different URL object, mutation after the guard, swallowed
rejection, or an absolute attacker-controlled projection. Authorization controls should load a
warehouse item, obtain a trusted worker identity, reject tenant and ownership mismatch, then mutate
the loaded item's canonical ID. Vulnerable counterparts should use a decoy item, requester-supplied
identity, missing predicate, non-terminating rejection, reassigned ID, or unrelated mutation target.

Add helper-mediated and direct forms, try/catch/finally adversaries, property destructuring,
same-value and wrong-value pairs, ambiguous aliases, and metamorphic renames. None may reuse retired
case wording, paths, identifiers, or fixture structure.

### Regression gates and acceptance

Use the same full future implementation gates listed for RC3, plus targeted authorization and
redirect dominance suites, public-fingerprint comparisons, and deterministic cache parity.
Acceptance requires all independently written safe controls to have no SE1005/SE1007 finding, every
wrong-value, partial-policy, non-dominating, reassigned, caught, or ambiguous counterpart to retain a
finding, and evidence to show a structural guard/derivation chain rather than suppression.

## Deferred causes and risks

RC1 must not be implemented in Secure Engine. A separate Secure Bench maintenance decision could
record a post-open erratum, but this tranche neither changes nor rescores the retired evidence. The
14 authoritative FN remain in the reconciliation.

RC2 is a sound, narrow future tranche after the selected work: recognize known shell interpreters
and distinguish program-text arguments from positional data while preserving safe fixed-binary argv
behavior. RC4 is also actionable, but should follow the call-summary work so object-literal field
identity can reuse the same bounded derivation model.

The main risks are over-propagating through unknown calls (new FP), over-crediting incomplete guards
(new FN), changing unaffected public fingerprints, and accidentally encoding retired-corpus details.
The acceptance criteria above make ambiguity explicit, preserve public contracts, require original
synthetic fixtures and adversarial controls, and prohibit benchmark-specific aliases or exceptions.

## Tranche conclusion

All 42 preserved anomalies are assigned exactly once: 33/33 FN and 9/9 FP. The two selected general
causes are RC3 (bounded value-preserving call summaries) and RC5 (derived guard/resource identity).
No implementation, rule, version, schema, taxonomy, Evidence Contract, fingerprint, cache-version,
package, or release artifact changed in this tranche. There was no new benchmark execution and no
new benchmark result.
