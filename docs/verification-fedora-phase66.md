# Phase 6.6 Fedora verification

Verified on Fedora 44 x86_64 with Rust/Cargo 1.96.1 and RPM 6.0.1 on 2026-07-16. All scans, tests, and packaging used Secure Engine-owned fixtures. No Secure Bench corpus, evaluator, baseline, result, manifest, ledger, holdout, or fixture was read or executed.

## Frozen taxonomy provenance

The unchanged read-only taxonomy contract is version 1.0.0 from signed DCO commit `93c0821db065de436a339c15b070e158947ad76c`. `git verify-commit` reported a good ED25519 signature by `danielcadev@users.noreply.github.com` with key `SHA256:dFNF3ps9kjbwqLKysQOi5q/SlnGq3phEQ5Js0TH0QGk`; the commit message contains the matching `Signed-off-by` trailer. Public artifact hashes were reverified exactly:

- schema: `cdecd643d338aa8ae42ec7398c6c4703cb97d60ad355340c98744fc94bcb7d6f`;
- taxonomy: `059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452`;
- methodology: `eac27e5800be35c5ae77f7804e52ae90462cbda403a5484baa8fab62f02ab562`;
- canonical content: `22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c`.

## Quality gates

- `cargo fmt --all -- --check`: pass with Fedora rustfmt 1.96.1.
- `CARGO_NET_OFFLINE=true SECURE_AI_LIVE_CALLS=disabled cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass.
- `CARGO_NET_OFFLINE=true SECURE_AI_LIVE_CALLS=disabled cargo test --workspace --all-features --all-targets`: pass, 102 tests total.
- `cargo audit --no-fetch --db target/phase65-audit/advisory-db --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195`: pass against 1,160 local advisories and 420 locked dependencies; only the two previously documented exceptions are ignored.
- `CARGO_NET_OFFLINE=true cargo deny check`: advisories, bans, licenses, and sources pass.
- `git diff --check`: pass.
- Official SARIF-schema validation, secure-json-v1 validation, additive semantic export, cold/warm cache identity, cancellation/privacy bounds, and symlink containment each pass focused regression tests.

The Phase 6.6 suite contributes eleven tests. Its generated independent corpus contains 102 isolated scenarios: 84 are the required six vulnerable plus six safe scenarios for each of seven rule families; 18 cover supported Rust, Python, and Go command semantics. Additional checks cover guard equivalence/removal, import aliases, destructuring, inter-file wrappers, exact and permissive destination policies, specific filesystem transformations, semantic-fingerprint metamorphism, safe/vulnerable mutations, candidate-path bounds, JSON/SARIF/baseline metadata, and relative fixture paths.

## Determinism and performance

An optimized scan of the ten-file Engine-owned Phase 6.5 precision fixture produced 559 nodes, 977 edges, 18 candidate paths, and 18 findings. The cold run took 0.02 seconds with 13,668 KiB maximum RSS and 10 cache misses; the warm run took 0.01 seconds with 12,232 KiB maximum RSS and 10 cache hits. Graph, findings, and report fingerprint were identical; the shared report fingerprint was `3f340db1433d8dd9b855cf54ba13a7b04e455d273246c0dfabec4d518abd0ea5`. Exit code 1 is the documented completed-scan-with-findings result.

Candidate paths are conservatively bounded by the configured finding, graph-edge, and inter-procedural limits. Exhaustion sets `analysis.truncated` and emits `candidate-path-limit-reached`. Alias resolution is limited to eight deterministic links. Dynamic dispatch, runtime middleware, filesystem runtime state, and unsupported framework behavior remain explicit limitations.

## Fedora artifacts

Two clean package trees, `target/phase66-rpm-first` and `target/phase66-rpm`, produced byte-identical 8,724,439-byte RPMs:

- RPM SHA-256: `8d6ed234ad87cd422a8c53de08117454423241972caa272a4bbb8bb7282c2276`;
- `secure` SHA-256: `e74503c800139e286d4c430c20507920707df5da4e14bc63f5b7bc83e005f11f` (13,249,456 bytes);
- `secure-desktop` SHA-256: `5476cf1fd3361961fe8287e30f43cd610c0cd80de6d4683a275cb261c13090ac` (21,654,552 bytes).

Both RPMs passed exact file-list comparison, metadata inspection, extraction, `secure rules list`, `secure ai providers`, desktop-file validation, offline AppStream validation, and a real five-second graphical smoke on the Wayland session through `DISPLAY=:0`. Verification did not install either package or modify the host configuration.
