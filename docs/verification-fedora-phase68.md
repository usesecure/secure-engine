# Phase 6.8 Fedora verification

Secure Engine 0.1.4 was verified offline on Fedora 44 x86_64 with Rust 1.96.1. AI validation
remained disabled. The verification did not execute Secure Bench or use undisclosed holdout
material.

## Quality and compatibility gates

- `cargo fmt --all -- --check`: pass.
- strict workspace Clippy with all targets/features and `-D warnings`: pass.
- complete offline workspace suite: 117 passing tests, zero failures.
- RustSec: 1,160 locally available advisories checked against 427 locked dependencies; no
  vulnerability reported.
- cargo-deny advisories, bans, licenses, and sources: pass.
- `secure-json-v1` and official SARIF 2.1.0 schema validation: pass.
- taxonomy and public evidence-contract-v2 vectors: pass and unchanged.
- malformed input, symlink escape, host-path privacy, cancellation, cache corruption, bounded
  large-repository, baseline, history, suppression, CLI, desktop, and disabled-AI compatibility:
  pass.
- pinned Phase 6.7 finding fingerprints for unchanged semantics: byte-identical.

The independent Phase 6.8 matrix passes 28/28 vulnerable scenarios and 28/28 paired safe controls.
Every vulnerable scenario has the expected taxonomy/CWE, canonical source and sink kinds,
repository-relative endpoint spans, a connected realizable path, no effective barrier or
uncertainty, and a stable repeated semantic fingerprint. Adversarial import ownership, dynamic
option spread, mutable allowlist, suffix, blocklist, authentication-only, cycle, recursion, and
ambiguous-alias checks also pass.

## Determinism and performance

A final self-scan selected 300 files and parsed 160 files into 10,778 facts, 36,355 graph nodes,
65,453 graph edges, and 77 deduplicated findings without exposing the host root. The cold scan
completed in 2.10 seconds with 280,900 KiB peak RSS and 160 cache misses. The warm scan completed in
0.96 seconds with 276,872 KiB peak RSS and 160 cache hits. Both produced report fingerprint
`ef52f0bc88c670f0ce8dd19ddf08c5d3ff366a8fe040a4b32a8eeebc39682a1d`.

These local measurements are development observations, not portable performance or coverage
claims.

## Reproducible Fedora package

Two clean package roots, `target/phase68-rpm-first` and `target/phase68-rpm`, produced byte-identical
8,809,974-byte RPMs. Both package trees passed exact file-list inspection, RPM metadata inspection,
extracted CLI rules/provider smoke tests, desktop-file validation, offline AppStream validation,
and the five-second graphical desktop smoke test.

| Artifact | SHA-256 |
| --- | --- |
| RPM | `c470f8bab478c937d6924f4d1bf7f6328da564cc392624622b4cc234130c0aef` |
| Staged `secure` | `5af3b346e68226b58294e79b5b36cd1bc36549e42d3c43de5b75ccf8c5626859` |
| Staged `secure-desktop` | `129d50b105ac04b4e023ed1d6fcd286428b010df2ab594c569d8738bedaca6c6` |
| RPM-extracted `secure` | `fe15135e878a768d452eaae2c014da4bd1e61f6ca0dca45d7ada54fd69a6c075` |
| RPM-extracted `secure-desktop` | `4ad3cee95800e4d9562c3e7231f27106c6362cd0031d8e4fd48d174c5d9ac3c5` |

Fedora build-root stripping explains the expected difference between staged and extracted ELF
hashes. The two staged copies, two extracted copies, and two RPMs are respectively byte-identical.

These gates establish release reproducibility and regression conformance only. They do not support
a public ranking, superiority, production-readiness, complete-coverage, or undisclosed-holdout
performance claim.
