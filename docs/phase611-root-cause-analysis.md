# Phase 6.11 retired Phase 19 root-cause analysis

## Status and methodology

Phase 19's 112 cases are opened development/regression data. This analysis is not an independent
holdout, benchmark result, ranking, or release evaluation. The historical Secure Engine native lane
is immutable: TP 23, FP 8, TN 48, FN 33; precision 23/31, recall 23/56, F1 46/87, and balanced
accuracy 3976/6272.

The canonical result document is tied to Secure Bench commit
`df1cf5f078ec861581f1d11dcc8d4ae35feb0315` and SHA-256
`6266b1c1b064cd15f9f812d66d638eb2edcf0ccac2fbf9162d79134902034185`.
`tools/phase611-classify-results.sh` reads only the completed native Secure Engine lane and emits the
required outcome/family/framework/format/topology/classification/pair matrix. It neither reads the
corpus nor invokes a scanner. Source inspection was limited to the 41 historical errors and their
paired controls, in read-only mode. OpenGrep and Semgrep were not executed.

The historical `family` values below are retained exactly for traceability. The semantic surface is
listed separately because the retired corpus family labels do not equal Secure Engine rule IDs.
No case identifier is used in the analyzer, fixtures, tests, or selection decision.

## Complete classification: 41/41

| Outcome | Pair | Historical family | Framework / format / topology | Semantic surface | Primary structural cause | Contributor or intentional limit | Scope |
| --- | --- | --- | --- | --- | --- | --- | --- |
| FN | `pair-p19-0002` | SE1006 | Next / TS / control flow | redirect | Fixed-point rounds expire before the body-field trace crosses the coercion, aliases, and helper boundary | Constructed-destination barrier semantics are incomplete, so extended-round candidates stay disabled | deferred |
| FN | `pair-p19-0003` | SE1005 | Node / TS / direct | outbound request | Object property remapping is not connected to the selected sink value | Inline destructuring/property unwrap | deferred |
| FN | `pair-p19-0004` | SE1005 | Next / TSX / control flow | outbound request | Object property remapping is not connected to the selected sink value | Inline property unwrap under control flow | deferred |
| FN | `pair-p19-0005` | SE1003 | Express / TSX / inter-file alias | dynamic code | Indirect sequence-expression callee is not normalized as `eval` | Inter-file trace is secondary; the sink is absent | deferred |
| FN | `pair-p19-0007` | SE1007 | Node / TSX / inter-file alias | SQL query | Fixed-point rounds expire before the body-field trace reaches the imported helper sink | SQL concatenation is already a recognized sink once connected | selected recall cause |
| FN | `pair-p19-0008` | SE1006 | Node / JS / control flow | redirect | Fixed-point rounds expire along a shallow alias/helper chain | Extended reach exposes unmodeled constructed-origin controls | deferred |
| FN | `pair-p19-0009` | SE1003 | Server action / JSX / control flow | dynamic code | Indirect sequence-expression callee is not normalized as `eval` | Sink extraction fails before taint analysis | deferred |
| FN | `pair-p19-0010` | SE1002 | Node / TS / inter-file alias | command execution | Computed higher-order dispatch has no unique callee | Intentional dynamic-dispatch limit | deferred |
| FN | `pair-p19-0014` | SE1007 | Node / JS / inter-file alias | SQL query | Fixed-point rounds expire before the imported helper parameter reaches the sink | Long local alias chain after one import | selected recall cause |
| FN | `pair-p19-0015` | SE1006 | Node / TSX / helper | redirect | Fixed-point rounds expire before the helper sink is evaluated with the propagated trace | Constructed-origin controls require a separate value-object proof | deferred |
| FN | `pair-p19-0017` | SE1002 | Next / JS / helper | command execution | Fixed-point rounds expire before a shallow helper/alias chain reaches the sink | Independently reproduced with unrelated syntax | selected recall cause |
| FN | `pair-p19-0018` | SE1003 | Server action / JS / helper | dynamic code | Indirect sequence-expression callee is not normalized as `eval` | Sink extraction, not handler recognition | deferred |
| FN | `pair-p19-0019` | SE1005 | Next / JS / inter-file alias | outbound request | Fixed-point rounds expire before the imported helper sink receives the selected field | Unique import is otherwise resolvable | selected recall cause |
| FN | `pair-p19-0021` | SE1004 | Node / JS / control flow | filesystem read | Path composition result is not retained as the selected resource path | Requires paired confinement semantics, not extra rounds alone | deferred |
| FN | `pair-p19-0022` | SE1005 | Node / TS / helper | outbound request | Fixed-point rounds expire along the coercion/helper/alias chain | Shallow call depth but longer fact depth | selected recall cause |
| FN | `pair-p19-0024` | SE1003 | Express / TS / control flow | dynamic code | Indirect sequence-expression callee is not normalized as `eval` | Sink record absent | deferred |
| FN | `pair-p19-0025` | SE1003 | Node / JS / direct | dynamic code | Indirect sequence-expression callee is not normalized as `eval` | Direct topology confirms extraction cause | deferred |
| FN | `pair-p19-0026` | SE1006 | Next / JSX / inter-file alias | redirect | Fixed-point rounds expire before the imported helper sink receives the field trace | Unique import is insufficient without constructed-destination barrier parity | deferred |
| FN | `pair-p19-0032` | SE1004 | Server action / JSX / helper | filesystem read | Path-join result loses the protected path identity | Confinement control must remain value-bound | deferred |
| FN | `pair-p19-0033` | SE1003 | Node / JSX / direct | dynamic code | Indirect sequence-expression callee is not normalized as `eval` | Direct topology confirms extraction cause | deferred |
| FN | `pair-p19-0034` | SE1003 | Next / TSX / helper | dynamic code | Indirect sequence-expression callee is not normalized as `eval` | Helper flow cannot compensate for an absent sink | deferred |
| FN | `pair-p19-0037` | SE1004 | Node / TSX / direct | filesystem read | Path composition result is not connected to the filesystem argument | Paired realpath/root proof needs separate treatment | deferred |
| FN | `pair-p19-0038` | SE1001 | Node / JSX / inter-file alias | protected mutation | Fixed-point rounds expire before the selected resource reaches the mutation | Missing-auth candidate is not a substitute for value flow | selected recall cause |
| FN | `pair-p19-0042` | SE1004 | Next / TSX / helper | filesystem read | Path composition result is not retained through helper propagation | Boundary-aware confinement remains required | deferred |
| FN | `pair-p19-0043` | SE1001 | Node / JSX / control flow | protected mutation | Fixed-point rounds expire along the selected-resource alias chain | Control-flow noise increases rounds, not call depth | selected recall cause |
| FN | `pair-p19-0046` | SE1004 | Next / JSX / direct | filesystem read | Path-join result loses the selected field identity | Direct topology isolates composition | deferred |
| FN | `pair-p19-0047` | SE1004 | Express / TS / inter-file alias | filesystem read | Composed path identity is not propagated across the imported helper | Needs separate path-policy cause | deferred |
| FN | `pair-p19-0048` | SE1002 | Node / JSX / helper | command execution | Fixed-point rounds expire before the helper sink consumes the aliased value | Same cause across another format/framework | selected recall cause |
| FN | `pair-p19-0049` | SE1004 | Express / JS / inter-file alias | filesystem read | Composed path identity is not propagated across the imported helper | Needs separate path-policy cause | deferred |
| FN | `pair-p19-0050` | SE1007 | Next / JSX / helper | SQL query | Fixed-point rounds expire before the query helper consumes the field trace | SQL sink recognition itself is present | selected recall cause |
| FN | `pair-p19-0051` | SE1007 | Next / TS / control flow | SQL query | Fixed-point rounds expire along the coercion/alias/query chain | Shallow control flow, longer fact chain | selected recall cause |
| FN | `pair-p19-0052` | SE1004 | Server action / TS / control flow | filesystem read | Path composition result is not retained as the selected path | Requires separate normalization/confinement reasoning | deferred |
| FN | `pair-p19-0056` | SE1003 | Next / TS / inter-file alias | dynamic code | Indirect sequence-expression callee is not normalized as `eval` | Imported flow is secondary to absent sink | deferred |
| FP | `pair-p19-0006` | SE1006 | Express / TSX / direct | redirect | Exact-origin proof over a constructed URL is not associated with the redirect value | Destination-object identity is separate from operation auth | deferred |
| FP | `pair-p19-0011` | SE1001 | Express / TSX / control flow | protected mutation | Resource-bound operation authorization is discarded when the same-resource proof is not associated with the mutation | Fail-closed, fixed operation, same current resource | selected precision cause |
| FP | `pair-p19-0013` | SE1006 | Express / JS / direct | redirect | Exact-origin proof over a constructed URL is not associated with the redirect value | Separate destination-policy cause | deferred |
| FP | `pair-p19-0028` | SE1001 | Express / JS / helper | protected mutation | Resource-bound operation authorization is not applied to the same mutation resource | Helper topology is uniquely resolvable | selected precision cause |
| FP | `pair-p19-0030` | SE1001 | Next / TSX / direct | protected mutation | Resource-bound operation authorization is not applied to the same mutation resource | Existing handler fallback is too coarse | selected precision cause |
| FP | `pair-p19-0036` | SE1001 | Server action / JS / inter-file alias | protected mutation | Resource-bound operation authorization summary loses the caller's resource binding | Unique import; ambiguous calls remain unsupported | selected precision cause |
| FP | `pair-p19-0040` | SE1001 | Server action / TS / helper | protected mutation | Resource-bound operation authorization is not applied to the same mutation resource | Helper summary already proves the policy | selected precision cause |
| FP | `pair-p19-0044` | SE1001 | Next / TS / direct | protected mutation | Resource-bound operation authorization is not applied to the same mutation resource | Direct topology isolates value association | selected precision cause |

Totals: 33/33 FN and 8/8 FP classified; 41/41 errors accounted for.

## Selected tranche

Only these two causes are in scope:

1. **Bounded fixed-point separation (recall).** Ten historical FN span four semantic sink
   surfaces, Node/Next, JS/JSX/TS/TSX, and helper/import/control-flow shapes. A synthetic flow
   produced zero findings at the normal depth but one when depth was increased, proving that the old
   round budget conflated local fact-chain length with interprocedural depth. The correction gives
   local convergence an independent eight-pass bound while every trace carries and enforces the
   configured interprocedural hop count. New late candidates remain at the prior budget for
   filesystem and redirect until their value-object barrier semantics can advance as a pair; already
   established candidates may still be removed by a later proven sanitizer.
2. **Same-resource operation authorization (precision).** Six historical FP span Express, Next, and
   server actions. A guard can suppress SE1007 only if an already established operation policy
   dominates the sink, the decision has a fixed argument, has an independent subject, and one
   argument is the exact current mutation resource or a bounded plain alias. Authentication alone,
   names alone, a different resource, `&&` conditional termination, swallowed rejection, late
   checks, ambiguous resolution, and effectful exceptional paths remain findings.

Pre-fix independent evidence was recorded before production edits:

- the long shallow flow returned `default=0, extended=1`;
- a valid same-resource fail-closed operation control produced one SE1007 false positive; and
- all initially executed authorization near misses still produced SE1007.

After correction, the focused Phase 6.11 suite passes six tests. The inherited Phase 6.9/6.10
generalization and remediation suites pass 16 tests, including try/catch/finally, wrong-value,
ambiguity, cache, fingerprint, span, and metamorphic checks.

## Deferred causes and limitations

- Eight indirect dynamic-code FN require sequence-expression callee normalization.
- Eight filesystem FN require composed-path propagation paired with realpath/root-boundary proof;
  extended-round candidates are conservatively held at the prior budget.
- Two outbound FN require inline property/destructuring value connectivity.
- One command FN uses unresolved computed higher-order dispatch and remains an intentional limit.
- Four redirect FN and two redirect FP require exact-origin proof over constructed destination
  objects; extended-round candidates are conservatively held at the prior budget.
- Local fixed-point convergence uses at least eight rounds and remains finitely bounded; a larger
  configured legacy budget remains authoritative. Interprocedural traversal remains bounded by
  configuration. Ambiguous imports, dynamic dispatch, and unresolved terminating helpers stay
  conservative.

These are backlog for later tranches. They were not implemented or opportunistically widened here.
