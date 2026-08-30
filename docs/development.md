# Development on Fedora

Secure Engine requires Rust 1.92 or newer. Fedora packages used for the verified native build are:

```bash
sudo dnf install rustfmt clippy libX11-devel libxkbcommon-devel mesa-libGL-devel
```

Run all gates:

```bash
export PATH="$HOME/.rustup/toolchains/1.92.0-x86_64-unknown-linux-gnu/bin:$PATH"
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195
cargo deny check
packaging/fedora/build-rpm.sh
packaging/fedora/verify-rpm.sh
```

The verified correction milestone used that explicit Rust 1.92 toolchain, which includes
`cargo-fmt`, `rustfmt`, `cargo-clippy`, and `clippy-driver`. Do not infer tool availability from the
host's default `PATH`.

CI uses the fixed `ubuntu-24.04` runner label, checkout action commit
`df4cb1c069e1874edd31b4311f1884172cec0e10` without persisted credentials, Rust 1.92.0,
`cargo-audit` 0.22.2, and `cargo-deny` 0.20.2. Tool installers use exact versions and `--locked`.
Reasonable job timeouts bound unavailable runners, registry access, and unexpectedly expensive builds.
The native APT packages resolve from the Ubuntu 24.04 runner repositories and are not byte-pinned;
they remain an upstream build-environment residual rather than part of the Rust dependency lock.

`cargo deny` is a CI dependency-policy gate; install version 0.20.2 locally with
`cargo install cargo-deny --version 0.20.2 --locked` when it is not packaged. Install the matching
audit gate with `cargo install cargo-audit --version 0.22.2 --locked`. The two audit exceptions are
documented in ADR 0001 and `deny.toml`; no other advisory is accepted. The deterministic scanner
works offline after Cargo has fetched dependencies. Tests, CI, packaging, and automatic
verification use only mock or recorded AI responses and never contact an AI provider. A live
adapter is reachable only through an explicit enabled project configuration, exact preview consent,
and an `secure ai validate` operation.

Phase 6 AI boundary, redaction, schema, consent, replay, cancellation, CLI/desktop, and Phase 5 compatibility checks remain part of the workspace and Fedora gates. Phase 6.5 adds exact taxonomy/schema and precision coverage; Phase 6.6 adds explicit semantic coverage. Phase 6.7 adds the public contract vectors and independent generalization coverage. Phase 6.8 adds a separate 56-scenario matrix, structural near misses, module ownership, destructuring, positional propagation, stable-fingerprint, and cache-invalidation checks. Phase 6.9 adds retired-handoff aggregate verification plus independent cause pairs for exact source/span identity, property/position connectivity, value-associated barriers, sink-argument precision, mutation, and metamorphic behavior. Phase 6.10 adds implementation-derived authorization summaries, same-result caller barriers, compound identity proof, and adversarial fail-closed coverage. Packaging writes only below `target/phase610-rpm`; installation, upgrade, and removal are documented in `docs/fedora-packaging.md` and are not automated.

To exercise the native shell, run `cargo run -p secure-desktop -- <repository>`. The scan runs outside the render thread. Closing the window or pressing Cancel signals the shared cancellation token.

Phase 3 graph/rule and parse-cache checks can use an isolated local directory. A vulnerable fixture returns policy exit code 1 after writing the complete report:

```bash
secure scan fixtures/phase2-js-ts --cache-dir /tmp/secure-engine-phase2-cache --clear-cache --output cold.json
secure scan fixtures/phase2-js-ts --cache-dir /tmp/secure-engine-phase2-cache --output warm.json
secure scan fixtures/phase3-rules --cache-dir /tmp/secure-engine-phase3-cache --clear-cache --output phase3-cold.json || test $? = 1
secure scan fixtures/phase3-rules --cache-dir /tmp/secure-engine-phase3-cache --output phase3-warm.json || test $? = 1
secure scan fixtures/phase5-multilang --cache-dir /tmp/secure-engine-phase5-cache --clear-cache --output phase5-cold.json || test $? = 1
secure scan fixtures/phase5-multilang --cache-dir /tmp/secure-engine-phase5-cache --output phase5-warm.json || test $? = 1
secure scan fixtures/lead-quality-vscode-go --no-cache --output lead-quality.json || test $? = 1
secure scan fixtures/trust-composition-execution-boundaries --no-cache --output trust-composition.json || test $? = 1
secure rules list
secure explain fd_FINDING_ID --report phase3-cold.json
```

CLI JSON output uses compact finding and abstention evidence neighborhoods by default. Add `--full-graph` for graph-development diagnostics; this also retains the complete normalized fact set. The report's `graph.total_nodes`, `graph.total_edges`, and `projection.total_facts` preserve complete internal counts in either mode. `--max-output-bytes` is an explicit fail-closed serialization budget and defaults to 64 MiB.

The default CLI path uses `scan_repository_compact` to count fact-only global graph evidence without
materializing data that the final projection omits. Full-graph callers use `scan_repository`
unchanged. See [the compact scan memory milestone](compact-scan-memory-milestone.md) for the
equivalence contract, repeatable measurement command, and residual limits.

The default repository-specific cache lives below `XDG_CACHE_HOME`, then `XDG_RUNTIME_DIR`, or the platform temporary directory. Reports never contain that path. Use `--no-cache` to disable reads and writes and `--clear-cache` to atomically retire the selected repository cache before scanning.

Exact project suppressions use `--suppress 'SE1001:src/handler.ts:123:reviewed fixed command allowlist'`. Rule ID, repository-relative sink path, zero-based sink byte, and reason are serialized in the configuration. Invalid rules/reasons/scopes, stale entries, and applied entries are all retained as `suppression_diagnostics`.
