# Fedora Phase 5 verification

- Date: 2026-07-16.
- Scope: committed Phase 0–5 fixtures and synthetic temporary repositories only; no Mitiquete or external project scan.
- Host: Fedora 44, x86_64, native graphical session.

## Required gates

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass.
- `cargo test --workspace --all-features` and `cargo test --workspace --all-targets`: pass, 70 tests total. The 65 Phase 0–4 tests remain green; five added interface/integration tests cover Rust/Python/Go provenance and recovery, vulnerable and safe controls, all seven shared rules, mixed repositories, same-language cross-file propagation, cross-language isolation, cold/warm cache identity, JSON/SARIF CLI output, and desktop/core parity.
- `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195`: pass with only the two existing documented eframe build-time exceptions.
- `cargo deny check`: advisories, bans, licenses, and sources pass. The pinned grammar crates add no dependency-policy exception.
- Existing JavaScript/TypeScript exact fingerprint tests pass. `secure-json-v1` accepts the additive Rust, Python, and Go parser modes, and cold/warm facts, findings, graph, and report fingerprints are identical.
- RPM build and `%check` pass without installation. Exact payload, metadata, extracted CLI, desktop/AppStream files, isolated layout, and the five-second extracted-desktop graphical smoke test pass.

## Language and fixture evaluation

The Phase 5 fixture contains isolated Rust, Python, and Go vulnerable/safe/malformed cases plus a mixed TypeScript/Rust/Python/Go repository. It exercises Axum/Flask/FastAPI/Gin-style routes, local guards and sanitizers, parameterization, process/database/filesystem/network/redirect/dynamic-code sinks, recoverable syntax, Python cross-file propagation, and blocked TypeScript-to-Rust call resolution. Rust `unsafe` without an evidence path and every `safe` file remain finding-free.

The combined cold scan selects 18 files and parses 14 supported files: 4 Go, 5 Python, 4 Rust, and 1 TypeScript. It retains 154 facts, 439 graph nodes, 679 edges, and 40 unique evidence paths across all seven rules with no configured truncation. Three malformed inputs retain useful facts and one recoverable diagnostic per new language.

## Performance and cache

The release CLI cold scan records 4 ms parsing/cache and 2 ms graph/rules, with 0 hits, 14 misses, 14 writes, 0 ignored entries, and 12,640 KiB peak RSS. The warm scan records 14 hits, 0 misses, and 10,212 KiB peak RSS. Both complete within the timer's 0.01-second resolution. The isolated cache occupies 180,035 bytes. After removing only documented volatile fields, cold and warm reports compare exactly and retain fingerprint `c32f5c7e0e2c18abec88cc468f689037d1567a5547f439126e5a8f0fc8a9ca5e`.

## Package artifact

`target/phase5-rpm/rpmbuild/RPMS/x86_64/secure-engine-0.1.0-1.fc44.x86_64.rpm` is an x86_64 MIT-licensed Fedora 44 package. Its compressed size is 6,732,277 bytes and installed payload is 29,411,633 bytes. SHA-256: `e9ed96ec6f972bc830150397aba6e96951abc26ab939a6ae568b9df40bc2c6c2`.

## Known limitations and non-goals

Rust procedural macros, generated code, and trait-object dispatch; Python monkey patching, metaclasses, runtime decorators, and dynamic attributes; and Go ambiguous interfaces, callbacks, reflection, and generated code remain explicit report limitations. Unresolved runtime middleware is not claimed as a guard. There is no Java/Kotlin/C# or other added language, AI validation, automatic fix, cloud service, telemetry, AppImage, hosted service, Secure Skill modification, or Secure Bench work in Phase 5.
