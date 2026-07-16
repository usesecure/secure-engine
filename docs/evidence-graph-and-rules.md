# Evidence graph and deterministic rules

The graph is an exported, deterministic projection of repository-local syntax evidence. `nodes` represent files, modules, functions, methods, handlers, request/configuration sources, arguments, assignments, transformations, returns, guards, sanitizers, calls, and sensitive sinks. `edges` represent containment, imports, calls, argument flow, returns, assignments, control flow, guard dominance, sanitization, and source-to-sink propagation.

All identifiers and fingerprints are stable for the same repository content and scan configuration. Locations are exact half-open, repository-relative spans. Parser and graph-extractor provenance is attached to every node, edge, and path step. Tree-sitter and any future internal graph implementation remain private.

## Analysis boundary

Propagation is intraprocedural by default and crosses only uniquely resolved local function calls, including calls between supported-language files. `max_interprocedural_depth` bounds repeated propagation; graph and finding counts have independent limits. Sanitizer-like calls stop taint. Parameterized SQL call shapes do not become raw-query findings. A preceding local auth/authorization guard, recognized dependency/decorator, or locally visible framework middleware produces guard-dominance evidence. Unresolved runtime middleware, dynamic imports, ambiguous dispatch, callbacks, reflection, generated code, and unresolved calls are not inferred.

## Findings and suppressions

Rules `SE1001`–`SE1006` require an ordered untrusted source-to-sensitive sink path; a sensitive call by itself is never enough. `SE1007` requires a recognized handler, a sensitive operation, and the demonstrated absence of a known preceding guard in that handler. The same rule identifiers and finding contract apply across JavaScript/TypeScript, Rust, Python, and Go. Findings retain source, transformations, guards, sink, prerequisites, impact, remediation, confidence, severity, verification state, limitations, and a deduplication fingerprint.

Use `secure rules list` for the catalog and `secure explain <finding-id> --report <report.json>` for one complete path. Exact suppressions use `--suppress RULE_ID:RELATIVE_PATH:START_BYTE:REASON`; every entry produces an auditable diagnostic.
