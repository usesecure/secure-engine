# Fedora Phase 4 verification

- Date: 2026-07-16
- Scope: committed fixtures and synthetic temporary repositories only; no Mitiquete or external project scan.
- Host: Fedora 44, x86_64, native graphical session.

## Required gates

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass.
- `cargo test --workspace --all-features`: pass, 65 tests total. The 54 Phase 0–3 tests remain green and 11 additional Phase 4 tests cover SARIF, all baseline states, malformed baselines, deterministic/atomic/cancelled exports, history retention/corruption/deletion/missing repositories, source containment/symlinks/bounds/cancellation, UI filtering/sorting/workers, CLI formats/modes/exits, and history/baseline lifecycle.
- `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195`: pass with only the two existing documented eframe build-time exceptions.
- `cargo deny check`: advisories, bans, licenses, and sources pass, including the pinned native picker dependency.
- Existing and generated Secure JSON documents validate against the additive `secure-json-v1` schema. Generated SARIF validates against the committed official OASIS SARIF 2.1.0 schema.
- Two SARIF exports from the same complete report compare exactly. Two baselines compare exactly and contain no timestamp. An unchanged baseline comparison reports 0 new, 0 changed, 0 resolved, and 12 unchanged findings.
- Privacy checks find no host-absolute root, temporary/cache path, or unrelated malformed-source contents in SARIF or baselines. Public history JSON excludes its private local repository path. Source reads reject parent paths and symlinks.
- RPM build and `%check` pass without installation. Exact content, package metadata, extracted CLI, desktop file, AppStream metadata, and isolated filesystem layout pass. The extracted native desktop remains running for the five-second graphical smoke window.

## Package artifact

`target/phase4-rpm/rpmbuild/RPMS/x86_64/secure-engine-0.1.0-1.fc44.x86_64.rpm` is an x86_64 MIT-licensed Fedora 44 package. Its compressed size is 6.1 MiB and installed file payload is 25,614,619 bytes. It contains exactly both binaries, launcher, AppStream metadata, scalable icon, README, and license (plus the two standard RPM doc/license directories).

## Fixture evaluation and performance

Only `fixtures/phase3-rules`, existing integration fixtures, and synthetic temporary repositories were scanned. Phase 3 behavior remains 12 unique findings, 99 facts, 326 nodes, 518 edges, 6/6 source-to-sink rules, 6/6 direct missing-guard handlers, 0/5 safe-control findings, and 0% duplicate rate on this corpus.

The Phase 4 release CLI cold scan records 5 ms total, 2 ms parsing/cache, 1 ms graph/rules, 0 hits/4 misses/4 writes, and 9,460 KiB peak RSS. The warm scan records 3 ms total, 0 ms parsing/cache, 2 ms graph/rules, 4 hits/0 misses/0 writes, and 8,340 KiB peak RSS. After removing only documented volatile Secure JSON fields, cold and warm reports compare exactly and retain fingerprint `fa3e6d32e048e84bd71172f7ce81e3de4de0a55b424792cea77683d4b0b8cacb`.

## Known limitations

Source preview accepts bounded UTF-8 regular files only. History is local to one host and does not relocate repositories. Baseline related-change classification deliberately uses a stable rule/exact-sink key. Desktop history comparison requires a current completed report. Dynamic imports, non-unique aliases, callbacks, recursion, unresolved calls, and framework middleware retain the explicit bounded Phase 3 limitations. There is no AI, automatic fix, extra language, cloud account, telemetry, AppImage, hosted service, or Secure Skill integration.
