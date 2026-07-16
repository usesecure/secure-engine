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
packaging/fedora/build-rpm.sh
packaging/fedora/verify-rpm.sh
```

`cargo deny` is a CI dependency-policy gate; install it locally with `cargo install cargo-deny --locked` when it is not packaged. The two audit exceptions are documented in ADR 0001 and `deny.toml`; no other advisory is accepted. The deterministic scanner works offline after Cargo has fetched dependencies. Tests, CI, packaging, and automatic verification use only mock or recorded AI responses and never contact an AI provider. A live adapter is reachable only through an explicit enabled project configuration, exact preview consent, and an `secure ai validate` operation.

Phase 6 AI boundary, redaction, schema, consent, replay, cancellation, CLI/desktop, and Phase 5 compatibility checks remain part of the workspace and Fedora gates. Phase 6.5 adds exact taxonomy/schema, structural-dominance, false-positive, false-negative, cache-invalidation, and legacy-fingerprint coverage. Phase 6.6 adds 102 independent semantic scenarios, mutation/metamorphic checks, resource bounds, and additive JSON/SARIF/baseline coverage. Packaging writes only below `target/phase66-rpm`; installation, upgrade, and removal are documented in `docs/fedora-packaging.md` and are not automated.

To exercise the native shell, run `cargo run -p secure-desktop -- <repository>`. The scan runs outside the render thread. Closing the window or pressing Cancel signals the shared cancellation token.

Phase 3 graph/rule and parse-cache checks can use an isolated local directory. A vulnerable fixture returns policy exit code 1 after writing the complete report:

```bash
secure scan fixtures/phase2-js-ts --cache-dir /tmp/secure-engine-phase2-cache --clear-cache --output cold.json
secure scan fixtures/phase2-js-ts --cache-dir /tmp/secure-engine-phase2-cache --output warm.json
secure scan fixtures/phase3-rules --cache-dir /tmp/secure-engine-phase3-cache --clear-cache --output phase3-cold.json || test $? = 1
secure scan fixtures/phase3-rules --cache-dir /tmp/secure-engine-phase3-cache --output phase3-warm.json || test $? = 1
secure scan fixtures/phase5-multilang --cache-dir /tmp/secure-engine-phase5-cache --clear-cache --output phase5-cold.json || test $? = 1
secure scan fixtures/phase5-multilang --cache-dir /tmp/secure-engine-phase5-cache --output phase5-warm.json || test $? = 1
secure rules list
secure explain fd_FINDING_ID --report phase3-cold.json
```

The default repository-specific cache lives below `XDG_CACHE_HOME`, then `XDG_RUNTIME_DIR`, or the platform temporary directory. Reports never contain that path. Use `--no-cache` to disable reads and writes and `--clear-cache` to atomically retire the selected repository cache before scanning.

Exact project suppressions use `--suppress 'SE1001:src/handler.ts:123:reviewed fixed command allowlist'`. Rule ID, repository-relative sink path, zero-based sink byte, and reason are serialized in the configuration. Invalid rules/reasons/scopes, stale entries, and applied entries are all retained as `suppression_diagnostics`.
