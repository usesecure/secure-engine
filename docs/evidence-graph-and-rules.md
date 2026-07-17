# Evidence graph and deterministic rules

The graph is an exported, deterministic projection of repository-local syntax evidence. `nodes` represent files, modules, functions, methods, handlers, request/configuration sources, arguments, assignments, transformations, returns, guards, sanitizers, calls, and sensitive sinks. `edges` represent containment, imports, calls, argument flow, returns, assignments, control flow, guard dominance, sanitization, and source-to-sink propagation.

All identifiers and fingerprints are stable for the same repository content and scan configuration. Locations are exact half-open, repository-relative spans. Parser and graph-extractor provenance is attached to every node, edge, and path step. Tree-sitter and any future internal graph implementation remain private.

## Analysis boundary

Propagation is intraprocedural by default and crosses only uniquely resolved local function calls, including calls between supported-language files. `max_interprocedural_depth` bounds repeated propagation; graph and finding counts have independent limits. A sanitizer applies only to its matching invariant. In TypeScript, its successful condition must structurally dominate the sink, while rejection branches must terminate or prevent the operation. Parameterized SQL call shapes do not become raw-query findings. A preceding local auth/authorization guard, recognized dependency/decorator, or locally visible framework middleware produces guard-dominance evidence. Unresolved runtime middleware, dynamic imports, ambiguous dispatch, callbacks, reflection, generated code, and unresolved calls are not inferred.

Phase 6.5 propagates return taint, sanitizer policy, authorization guards, and handler reachability through uniquely resolved local helpers. Filesystem confinement requires canonicalization plus approved-root containment. Outbound requests require a dominating protocol and hostname policy; redirects require an explicit destination allowlist or fixed safe fallback. A fixed executable invoked through a supported argument-vector API is not shell command injection unless options explicitly enable a shell. Executable-specific argument injection remains unsupported and is reported as an analysis limitation.

Phase 6.6 adds explicit semantic roles and stable identities to relevant nodes and path steps. Imports, destructuring, direct aliases, arguments, and returns are resolved conservatively; every candidate must have internally consistent edges and a realizable source-to-sink order. Guards protect only corresponding values and must establish the exact rule policy. Authentication is distinct from operation authorization. Candidate paths have a derived deterministic budget and report truncation when exhausted. See [evidence-semantics.md](./evidence-semantics.md).

Phase 6.7 assigns every call expression a location-stable value key, preserves source-argument
ordering, and selects the most specific proven source rather than the first lexicographic value.
Only one best path is retained per rule and sink. Framework source classification is separated from
tree-sitter syntax extraction. Contract projection removes only summarizable propagation nodes and
always retains source and sink endpoints. See [evidence-contract-v2.md](./evidence-contract-v2.md).

Phase 6.8 binds JavaScript/TypeScript helper calls to the same file or one explicit relative import,
groups multiarity inputs by formal-parameter position, and classifies aliased or destructured
framework accessors before generic handler inputs. Exact fixed arrays, sets, literal comparisons,
and constant fallback branches can establish a matching barrier; suffix checks, blocklists,
ambiguous aliases, and authentication-only checks cannot. The private cache format advances while
the public extractor identity remains stable for unaffected finding fingerprints.

## Findings and suppressions

Rules `SE1001`–`SE1006` require an ordered untrusted source-to-sensitive sink path; a sensitive call by itself is never enough. `SE1007` requires a recognized handler, a sensitive operation, and the demonstrated absence of a known preceding guard in that handler. The same rule identifiers and finding contract apply across JavaScript/TypeScript, Rust, Python, and Go. Findings retain source, transformations, guards, sink, prerequisites, impact, remediation, confidence, severity, verification state, limitations, and a deduplication fingerprint.

Use `secure rules list` for the catalog and `secure explain <finding-id> --report <report.json>` for one complete path. Exact suppressions use `--suppress RULE_ID:RELATIVE_PATH:START_BYTE:REASON`; every entry produces an auditable diagnostic.

Every built-in rule and emitted finding carries the exact three-field taxonomy coordinates, primary CWE reference, and signed-contract provenance described in [taxonomy-and-precision.md](./taxonomy-and-precision.md). These fields do not replace `SE1001`–`SE1007` or participate in legacy finding fingerprints. Phase 6.6 adds a separate location-independent semantic fingerprint.
