# Fedora Phase 3 verification

- Date: 2026-07-16
- Host: Fedora 44 (Forty Four), x86_64, kernel 7.1.3-200.fc44
- Rust: rustc 1.96.1 and Cargo 1.96.1 from Fedora updates
- Native session: Wayland with XWayland available through `DISPLAY=:0`

The clean Phase 2 commit `460a2c0` passed its complete 45-test gate before `main` was fast-forwarded from `9f6e8f4` without squashing or rewriting. Phase 3 was developed only on `codex/phase-3-graph-and-rules`.

## Verified gates

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass.
- `cargo test --workspace --all-features`: pass; 54 tests cover the original Phase 0–2 contracts plus graph topology, exact spans, evidence-path references, all seven rules, safe controls, local helper argument flow, sanitizers, guard dominance, deterministic deduplication, exact/invalid/stale suppressions, bounds, cancellation, privacy, cache reuse, schema compatibility, and core/CLI/desktop equivalence.
- `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195`: pass with only the two documented eframe build-time exceptions in ADR 0001.
- `cargo deny check`: advisories, bans, licenses, and sources pass.
- `secure rules list`, `secure explain`, policy exit 1, invalid-input exit 2, schema output, and the mock consumer pass.
- Generated reports validate against the additive `secure-json-v1` schema. Phase 0, Phase 1, Phase 2, and Phase 3 committed fixtures remain valid.
- Cold and warm reports compare exactly after removing documented timing and cache counters. Graph topology, findings, evidence paths, suppressions, normalized facts, and `report_fingerprint` are identical.
- The native desktop binary remains running without startup/backend errors for the five-second graphical smoke window.

## Evaluation

The paired `fixtures/phase3-rules` corpus contains one demonstrated vulnerable flow for each of `SE1001`–`SE1006`, six directly sensitive unguarded handlers for `SE1007`, five guarded/sanitized/parameterized safe handlers, malformed TypeScript, and unresolved dynamic behavior.

- Source-to-sink rule detection: 6/6 (100%).
- Direct missing-guard handler detection: 6/6 (100%).
- Safe-control findings: 0/5; observed false-positive rate 0% on this corpus.
- Findings: 12 unique fingerprints from 12 candidate effective paths; duplicate rate 0%.
- Graph: 326 nodes and 518 edges from 99 unchanged normalized facts across five inventoried files.
- Recoverable parser diagnostics: one malformed-source diagnostic; analysis continues without source leakage.

The cold scan records 20 ms total, 11 ms parsing/cache, 5 ms graph/rules, 0 hits/4 misses/4 writes, and 14,392 KiB peak RSS. The warm scan records 14 ms total, 4 ms parsing/cache, 6 ms graph/rules, 4 hits/0 misses/0 writes, and 12,408 KiB peak RSS. `/usr/bin/time -v` measured process RSS.

Dynamic imports, non-unique aliases, callbacks, recursion, unresolved calls, and framework middleware remain explicit bounded limitations. Inter-procedural propagation follows only uniquely resolved local calls within the configured depth. No AI, automatic fixes, SARIF, baselines, release packaging, cloud service, extra language, or Secure Skill installation/execution/modification was added.
