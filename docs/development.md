# Development on Fedora

Secure Engine requires Rust 1.92 or newer. Fedora packages used for the verified native build are:

```bash
sudo dnf install rustfmt clippy libX11-devel libxkbcommon-devel mesa-libGL-devel
```

Run all gates:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195
cargo deny check
```

`cargo deny` is a CI dependency-policy gate; install it locally with `cargo install cargo-deny --locked` when it is not packaged. The two audit exceptions are documented in ADR 0001 and `deny.toml`; no other advisory is accepted. The scanner works offline after Cargo has fetched dependencies. It does not contact Secure Skill, a cloud service, or an AI provider.

To exercise the native shell, run `cargo run -p secure-desktop -- <repository>`. The scan runs outside the render thread. Closing the window or pressing Cancel signals the shared cancellation token.

Phase 3 graph/rule and parse-cache checks can use an isolated local directory. A vulnerable fixture returns policy exit code 1 after writing the complete report:

```bash
secure scan fixtures/phase2-js-ts --cache-dir /tmp/secure-engine-phase2-cache --clear-cache --output cold.json
secure scan fixtures/phase2-js-ts --cache-dir /tmp/secure-engine-phase2-cache --output warm.json
secure scan fixtures/phase3-rules --cache-dir /tmp/secure-engine-phase3-cache --clear-cache --output phase3-cold.json || test $? = 1
secure scan fixtures/phase3-rules --cache-dir /tmp/secure-engine-phase3-cache --output phase3-warm.json || test $? = 1
secure rules list
secure explain fd_FINDING_ID --report phase3-cold.json
```

The default repository-specific cache lives below `XDG_CACHE_HOME`, then `XDG_RUNTIME_DIR`, or the platform temporary directory. Reports never contain that path. Use `--no-cache` to disable reads and writes and `--clear-cache` to atomically retire the selected repository cache before scanning.

Exact project suppressions use `--suppress 'SE1001:src/handler.ts:123:reviewed fixed command allowlist'`. Rule ID, repository-relative sink path, zero-based sink byte, and reason are serialized in the configuration. Invalid rules/reasons/scopes, stale entries, and applied entries are all retained as `suppression_diagnostics`.
