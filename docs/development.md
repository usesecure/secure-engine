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

Phase 2 parse-cache checks can use an isolated local directory:

```bash
secure scan fixtures/phase2-js-ts --cache-dir /tmp/secure-engine-phase2-cache --clear-cache --output cold.json
secure scan fixtures/phase2-js-ts --cache-dir /tmp/secure-engine-phase2-cache --output warm.json
```

The default repository-specific cache lives below `XDG_CACHE_HOME`, then `XDG_RUNTIME_DIR`, or the platform temporary directory. Reports never contain that path. Use `--no-cache` to disable reads and writes and `--clear-cache` to atomically retire the selected repository cache before scanning.
