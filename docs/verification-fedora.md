# Fedora Phase 1 verification

- Date: 2026-07-16
- Host: Fedora 44 (Forty Four), x86_64, kernel 7.1.3-200.fc44
- Rust: rustc 1.96.1 and Cargo 1.96.1 from Fedora updates
- Native session: Wayland session with XWayland available through `DISPLAY=:0`

The host did not have `rustup`, `rustfmt`, or Clippy installed globally and passwordless package installation was unavailable. The official Fedora 44 `rustfmt-1.96.1-1.fc44` and `clippy-1.96.1-1.fc44` RPMs were downloaded and extracted under `/tmp` for the local gates; no system package or Codex skill directory was modified.

## Verified gates

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass.
- `cargo test --workspace --all-features`: pass; 30 tests cover Git-aware traversal, nested ignore and negation behavior, include/exclude controls, generated/vendor/nested-repository policies, binary, unreadable, and ambiguous platform paths, symlink escapes, worktrees and submodules, deterministic large-repository limits, bounded errors and bytes, cancellation during discovery and reads, additive schema compatibility, shared interfaces, and CLI behavior.
- `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195`: pass with only the two documented eframe build-time exceptions in ADR 0001.
- `cargo deny check`: advisories, bans, licenses, and sources pass.
- `secure --help`, `secure doctor --format secure-json-v1`, and `secure schema print secure-json-v1`: pass; the printed schema is semantically identical to the committed schema and machine output remains isolated on stdout.
- Two controlled scans of `fixtures/integration-project` compare exactly after removing only `scan.started_at`, `scan.finished_at`, and `scan.duration_ms`.
- The mock Secure Skill consumer validates the legacy Phase 0 fixture, the additive Phase 1 fixture, and a newly generated report.
- A scan of this workspace inventories 38 files, validates against the committed schema, exports no absolute workspace path or source content, reports zero findings, and records its inventory-only limitations.
- The native desktop binary built and remained running in the Fedora graphical session for the five-second smoke-test window without startup or backend errors.

No Secure Skill installation, execution, vendoring, or modification occurred. No Tree-sitter adapter, semantic graph, cache, AI integration, or vulnerability rule was added.
