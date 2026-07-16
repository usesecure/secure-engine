# Fedora Phase 6.5 verification

Verified on Fedora 44 x86_64 with Rust and Cargo 1.96.1 on 2026-07-16. Phase 6 was fast-forwarded into `main` at `3d83aaf450374b79faef4070e8a559e00da0bff2`; its published RPM checksum remained `a55928a226a1fe9b66a7d77e5e02280d5de203b97b14c79f3e3e79cce90a1bc8`. Phase 6.5 work was performed on `codex/phase-6-5-precision-calibration` without running Secure Bench or scanning an external repository.

## Quality gates

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass with all workspace lint denies active.
- `SECURE_AI_LIVE_CALLS=disabled cargo test --workspace --all-features --all-targets`: pass, 91 tests total. The seven new tests cover exact taxonomy mapping, direct/helper/near-miss detection, safe dominant controls, unresolved limitations, SARIF/baseline/legacy JSON compatibility, Phase 6 fingerprint preservation, and cold/warm cache identity.
- `cargo audit`: pass against 1,160 locally fetched RustSec advisories and 420 locked dependencies, with only the documented `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195` exceptions.
- `cargo deny check`: pass for advisories, bans, licenses, and sources.
- Official SARIF 2.1.0 schema validation, `secure-json-v1` compatibility validation, strict partial-taxonomy rejection, deterministic baseline/history, AI-disabled byte identity, malformed/adversarial AI data, cancellation, and cache corruption/invalidation checks: pass in the workspace suite.

## Taxonomy and independent precision fixtures

All seven rules and all emitted findings carry `secure-bench-taxonomy-v1` 1.0.0 coordinates, the exact primary CWE, and mapping provenance from signed DCO commit `93c0821db065de436a339c15b070e158947ad76c`. Scanner JSON, rule-list JSON, SARIF run/rule/result properties, baselines, history summaries, CLI explanations, desktop search/detail, and optional redacted AI previews expose the additive metadata.

The independent ten-file Phase 6.5 fixture produced 18 intended findings: `SE1001` 3, `SE1003` 3, `SE1004` 4, `SE1005` 4, and `SE1007` 4. Seven safe controls remained finding-free: fixed executable/argument array with `shell: false`, canonicalized root confinement, protocol/host allowlist, redirect allowlist helper, redirect fixed fallback, local authorization helper, and authorized mutation helper. Non-terminating warning checks and two inverted-blocklist adversarial cases remained findings. Five unresolved callback variants emitted no unsupported claims and retained the explicit dynamic-resolution limitation.

All 12 Phase 6 finding fingerprints in the pre-change Phase 3 fixture remain present. The calibrated handler-to-helper reachability independently adds one `SE1007` finding for a previously unreported sensitive helper path; this is a genuine evidence-path correction rather than a fingerprint change.

## Determinism and performance

Two release scans of the independent fixture were identical after removing the documented volatile timing/cache fields and shared report fingerprint `dc7e35726b7a1793c1ff37a7e1464d22a5f968dbffc8e84c0022e85f0f1b1429`. Baseline comparison reported 0 new, 0 changed, 0 resolved, and 18 unchanged findings. The cold scan recorded 10 misses, 10 writes, 13 ms parsing, and 19 ms total; the warm scan recorded 10 hits, 0 writes, 1 ms parsing, and 6 ms total. These are local fixture measurements, not a broad performance claim.

## Fedora package

Two clean package builds were byte-identical. The final RPM is `target/phase65-rpm/rpmbuild/RPMS/x86_64/secure-engine-0.1.1-1.fc44.x86_64.rpm`, 8,673,035 bytes compressed and 34,705,133 bytes installed.

- RPM SHA-256: `a06c21fc0484d2b91ccacce8c49abfce2be9f985b58f79f83f8623a04523c795`.
- `secure` SHA-256: `7d5647080dcbc58572315c7eef16463238daf5874cae54601a0ea69c93d2b346`.
- `secure-desktop` SHA-256: `1a65ae81a661c96e3fd1782d7bfb13282773182d5025704e756dc26d249e59fe`.

The verifier confirmed the exact payload, package metadata, extracted CLI rule/AI-provider commands, desktop-file and offline AppStream validation, and a five-second graphical desktop smoke on `DISPLAY=:0`. It installed nothing and changed no host configuration.

## Remaining limitations

Dynamic imports, non-unique aliases, callbacks, recursion, runtime middleware, reflection, generated code, and unresolved calls are not followed. Fixed executable calls with shell processing disabled are excluded from shell command injection only; executable-specific argument injection remains unsupported and is explicitly reported. AI remains disabled by default and requires the unchanged preview, consent, provider, transport, and budget boundary.
