# Phase 6.10 root-cause analysis

Phase 6.10 used only the three frozen aggregate artifacts and clean source commit listed in
`fixtures/phase610-cms-nova-handoff/summary.json`. Their supplied SHA-256 values were verified before
inspection. No Secure Bench corpus, evaluator, expected outcome, result file, or private artifact
was inspected or executed.

The frozen Secure Engine 0.1.5 report contained 56 `SE1007` findings. Independent classification
found 56 false positives, no validated vulnerability, and no uncertain case. The 56 outcomes reduce
to three general proof-construction gaps:

1. A helper could return an authenticated principal only after a fixed role predicate, but the graph
   did not retain the conditional return contract or require the caller to reject the null result.
2. A helper could return a boolean fixed-role decision bound to the same request principal, but the
   graph propagated only name-derived guard labels and not the boolean result contract.
3. A handler could combine authenticated-principal existence with exact equality to a trusted,
   server-selected identity, but authentication and identity evidence were not composed into one
   dominating operation guarantee.

The correction adds private candidates and bounded summaries. It validates a trusted principal
origin, a fixed role/permission predicate or exact identity comparison, an accepted return shape,
unambiguous call resolution, parameter/request-context binding, current value origin, and a
terminating failure branch. Filtered and boolean results become authorization only after a caller
guard rejects the same unreassigned result. Identity checks require authenticated and server-selected
values on opposite comparison sides.

Resolution remains deliberately bounded. It accepts explicit relative imports and conventional
source-root `@/` or `~/` aliases only when exactly one local module destination exists. The alias form
is treated as module topology, never as authorization evidence; ambiguous or missing destinations
remain unresolved.

Iterative dogfood verification exposed a distinct control-flow precision boundary around broad
request-handler `try`/`catch` blocks. A return-terminated rejection inside `try` exits the function
and cannot be caught, so it remains fail-closed. A thrown or redirect-like rejection may be caught;
it remains untrusted unless the analyzer can prove every catch path also terminates. The completion
tracks both exit kinds through nested handlers: returns bypass catches, while throws are transformed
by an unconditional catch return, rethrow, or uniquely resolved local helper that structurally always
throws. Unresolved, ambiguous, recursive, conditionally terminating, normally returning, or
sensitive-effect handlers remain conservative. This distinction is structural and applies
independently of framework, helper, route, and application names.

The third authorized application pass left six exact fingerprints unchanged after resolving 50.
After the exceptional-control-flow completion passed its independent safe/vulnerable matrix, a
fourth and final authorized read-only pass resolved all 56 exact original fingerprints: none remained
unchanged, none changed identity, and none was newly introduced. No further inference is made from
the shared semantic fingerprint used by multiple `SE1007` findings; exact finding fingerprints are
the comparison authority. No fifth application scan was performed.

The analyzer intentionally rejects names and comments as proof. It also rejects user-controlled
policy values, unconditional success, nullable fallback, caught throw/redirect continuation,
non-terminating or late
checks, wrong-value comparisons, reassignment, ambiguous local imports, and unresolved/dynamic
calls. Authentication alone remains insufficient for `SE1007`.

The public taxonomy, evidence contract v2, evidence semantics v2, secure-json-v1, SARIF, rule IDs,
and graph extractor identity remain unchanged. The private cache advances to v7 because serialized
program records now include internal authorization candidates. This work makes no benchmark ranking,
superiority, production-readiness, complete-coverage, or future-corpus claim.
