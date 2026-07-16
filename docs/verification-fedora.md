# Fedora Phase 2 verification

- Date: 2026-07-16
- Host: Fedora 44 (Forty Four), x86_64, kernel 7.1.3-200.fc44
- Rust: rustc 1.96.1 and Cargo 1.96.1 from Fedora updates
- Native session: Wayland session with XWayland available through `DISPLAY=:0`

The host did not have `rustup`, `rustfmt`, or Clippy installed globally and passwordless package installation was unavailable. The official Fedora 44 `rustfmt-1.96.1-1.fc44` and `clippy-1.96.1-1.fc44` RPMs were downloaded and extracted under `/tmp` for the local gates; no system package or Codex skill directory was modified.

The clean Phase 1 commit `9f6e8f4` passed its complete 30-test gate before `main` was fast-forwarded from `b33deb2` without squashing or rewriting. Phase 2 was then developed only on `codex/phase-2-parsing-normalized-facts`.

## Verified gates

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass.
- `cargo test --workspace --all-features`: pass; 45 tests preserve all Phase 1 coverage and add four parser modes, exact Unicode spans, stable fact IDs/fingerprints, malformed-source recovery, Next.js and Express evidence, sensitive-operation candidates, cache reuse/invalidation/tamper recovery/clear, bounded and cancelled cache writes, concurrent in-parser cancellation, parsing boundaries, additive schema compatibility, and CLI/desktop/core equivalence. A 400-file synthetic JavaScript/TypeScript performance case completes cold and warm passes within its 30-second budget.
- `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195`: pass with only the two documented eframe build-time exceptions in ADR 0001.
- `cargo deny check`: advisories, bans, licenses, and sources pass.
- `secure --help`, `secure doctor --format secure-json-v1`, and `secure schema print secure-json-v1`: pass; the printed schema is semantically identical to the committed schema and machine output remains isolated on stdout.
- Cold and warm scans of `fixtures/phase2-js-ts` compare exactly after removing documented timing and cache counters; both have the same 79 facts and report fingerprint.
- The cold scan records 9 ms total, 6 ms parsing, 0 hits/9 misses/9 writes, and 11,956 KiB peak RSS. The warm scan records 5 ms total, 1 ms parsing, 9 hits/0 misses/0 writes, and 9,128 KiB peak RSS. `/usr/bin/time -v` measured process RSS on the feature-complete fixture.
- The malformed TypeScript fixture produces a recoverable diagnostic while retaining its import fact. Cancellation returns no report, and corrupt or tampered cache entries are ignored and atomically replaced.
- The mock Secure Skill consumer validates the legacy Phase 0 fixture, additive Phase 1 and Phase 2 fixtures, and newly generated cold/warm reports.
- Generated Phase 2 reports validate against the committed schema, export no absolute repository/cache path or ignored source content, and keep `findings` empty.
- The native desktop binary built and remained running in the Fedora graphical session for the five-second smoke-test window without startup or backend errors.

No Secure Skill installation, execution, vendoring, or modification occurred. No capability/data-flow graph, vulnerability rule, severity, AI integration, automatic fix, source upload, or non-JavaScript/TypeScript parser was added.
