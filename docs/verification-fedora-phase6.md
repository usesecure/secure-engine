# Fedora Phase 6 verification

Verified on Fedora 44 x86_64 with Rust 1.96.1 on 2026-07-16. Phase 5 was fast-forwarded into `main` only after its 70-test suite, strict gates, graphical RPM smoke, and published checksum passed. Phase 6 work was then performed on `codex/phase-6-optional-ai-validation`.

## Gates

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass.
- `CARGO_NET_OFFLINE=true SECURE_AI_LIVE_CALLS=disabled cargo test --workspace --all-features`: pass, 84 tests total after the final cost-budget and remote-scope cases. No test, CI step, packaging step, or automatic verification contacts a live provider.
- `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195`: pass with only the two existing documented eframe-chain exceptions.
- `cargo deny check`: advisories, bans, licenses, and sources pass. `CDLA-Permissive-2.0` is allowed for the pinned `webpki-roots` TLS trust data used by `ureq`/rustls.
- Desktop manual smoke: pass. The native shell rendered correctly, navigation exposed **AI Validation**, the page was disabled by default, and it stated that no provider is configured or contacted while disabled.
- `packaging/fedora/build-rpm.sh`: pass with locked, offline Cargo inputs.
- `packaging/fedora/verify-rpm.sh`: exact file list, metadata, extracted CLI `rules list` and `ai providers`, desktop metadata, AppStream `--no-net`, and five-second graphical smoke all pass.

## Phase 6 contract coverage

Committed vulnerable/safe and provider-response fixtures cover the four bounded statuses, supported/questioned/missing evidence, malformed and adversarial output, prompt-injection text as data, secret redaction, absolute-path rejection, exact/stale consent, duplicates, timeout, cancellation, cache hit/replay/corruption, history attachment/deletion, explicit SARIF enrichment, disabled-mode byte identity, and user-supplied cost-budget enforcement. Mock and recorded adapters support contract testing only; no provider-quality or vulnerability-quality claim is derived from them.

The official remote adapter has no default endpoint, model, price, or credential. It requires HTTPS, refuses redirect following, reads the credential only from the configured environment variable, sends no tools, requests strict structured output, bounds input/output/response/time/cost scope, redacts errors, and exposes that its blocking transport cannot interrupt a call already in flight. Normal scanning remains fully offline and provider-independent.

## RPM

`target/phase6-rpm/rpmbuild/RPMS/x86_64/secure-engine-0.1.0-1.fc44.x86_64.rpm` is an x86_64 MIT-licensed Fedora 44 package. Its compressed size is 8,564,090 bytes and installed payload is 34,283,049 bytes. Two consecutive clean package builds are byte-identical after binding RPM `BUILDTIME` to `SOURCE_DATE_EPOCH`.

SHA-256: `a55928a226a1fe9b66a7d77e5e02280d5de203b97b14c79f3e3e79cce90a1bc8`.

## Explicit limitations and non-goals

Assessments review only the previewed deterministic finding payload and do not establish vulnerability truth. No source snippets are sent. No automatic fixes, tools, agents, source changes, cloud accounts, telemetry, hosted service, new languages/rules, AppImage, Secure Skill changes, or public AI-quality claims are included. Remote in-flight cancellation is unavailable in the selected blocking HTTP transport; configured timeout is the hard bound and the limitation is visible in provider capability metadata and documentation.
