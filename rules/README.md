# Deterministic rules

Phase 3 ships seven built-in rules from the shared engine. `secure rules list` is the canonical machine-readable catalog.

- `SE1001`: untrusted input reaches command execution.
- `SE1002`: untrusted input reaches dynamically constructed or raw SQL.
- `SE1003`: an untrusted path reaches a filesystem operation.
- `SE1004`: an untrusted URL reaches an outbound request.
- `SE1005`: an untrusted URL reaches a redirect.
- `SE1006`: untrusted input reaches dynamic code execution.
- `SE1007`: a proven exposed handler reaches a sensitive operation without a dominating auth guard.
- `SE1008`: untrusted input reaches CLI option parsing without an end-of-options boundary.
- `SE1009`: untrusted input reaches a shared prototype mutation.

A sink alone is not sufficient for `SE1001`–`SE1006`; the report must contain a reproducible source-to-sink path. `SE1007` is emitted only for a recognized handler with a directly analyzed sensitive operation and no preceding recognized guard. Known limitations are recorded in each report.
