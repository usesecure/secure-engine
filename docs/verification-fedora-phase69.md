# Phase 6.9 Fedora verification

Secure Engine 0.1.5 was verified offline on Fedora 44 x86_64 with Rust 1.96.1. AI validation remained
disabled. Verification does not execute or modify Secure Bench and does not access undisclosed
holdout material.

## Quality and compatibility gates

- `cargo fmt --all -- --check`: pass.
- strict workspace Clippy with all targets/features and `-D warnings`: pass.
- complete locked offline workspace suite: 129 passing tests, zero failures.
- RustSec: 1,166 locally available advisories checked against 427 locked dependencies; no
  unignored vulnerability reported. The two documented project exceptions remain unchanged.
- cargo-deny advisories, bans, licenses, and sources: pass offline.
- `secure-json-v1`, taxonomy 1.0.0, evidence contract v2, and official SARIF 2.1.0 validation:
  pass and public versions unchanged.
- malformed input, symlink escape, host-path privacy, cancellation, cache corruption, bounded
  large-repository behavior, baseline, history, suppressions, CLI/desktop parity, and disabled AI:
  pass.
- cache v5-to-v6 isolation: a v5 sentinel remains unread, the cold v6 scan records misses/writes,
  and the warm v6 scan records hits with identical facts, graph, findings, and report fingerprint.

The permitted retired handoff remains exactly 112 cases: 56 vulnerable and 56 controls. Its frozen
historical outcomes are 10 exact, 0 partial, and 46 no-match vulnerable cases, plus 40 flagged and
16 clean controls. Because source was not exported, no post-remediation benchmark rescore is
claimed. Aggregate hashes/counts pass independently of the scanner. The Engine-owned Phase 6.9
cause matrix passes 7/7 vulnerable cases and 7/7 paired controls with exact source/sink evidence and
fully connected contract paths. Additional source/span, sink-position, destructuring, scoped alias,
wrong-value/late barrier, sanitizer, reassignment, mutation, metamorphic, recursion, callback,
dynamic-import, unresolved-boundary, privacy, and cache tests pass. The independent Phase 6.8
28/28 matrix and Phase 6.7 70/70 matrix also remain green.

## Determinism and performance

A release self-scan excluded only this self-referential verification document. It selected and
scanned 311 files, parsed 163 files into 11,220 facts, 37,885 graph nodes, 68,301 graph edges, and
77 deduplicated findings without truncation. The cold scan completed in 2.51 seconds with 294,720
KiB peak RSS, 163 cache misses, and 163 writes. The warm scan completed in 1.20 seconds with 290,588
KiB peak RSS, 163 cache hits, zero misses, and zero writes. Both reports have fingerprint
`b2baac6cb686a50bce95249fcaa310f3a71e85436ef82b308642311da076a1ae`; after removal of documented
volatile fields their canonical SHA-256 is
`6afdc18f9f0a4e826dfa37271a8733b82578631fcf9893cbf0acd6ca6f0b5f53`.
The Phase 6.8 self-scan fingerprint was
`ef52f0bc88c670f0ce8dd19ddf08c5d3ff366a8fe040a4b32a8eeebc39682a1d`; the report-level change is
expected because the engine version, repository content, and corrected evidence construction all
changed. Phase 6.7 pinned fingerprints for unchanged semantics and Phase 6.9 metamorphic semantic
fingerprints remain unchanged in their compatibility tests.

These local measurements are development observations, not portable performance or coverage
claims.

## Reproducible Fedora package

Two clean package roots, `target/phase69-rpm-first` and `target/phase69-rpm`, produced byte-identical
8,846,092-byte RPMs. Both roots passed exact file-list inspection, RPM metadata inspection,
extracted CLI rule/provider smoke tests, desktop-file validation, offline AppStream validation, and
the five-second graphical desktop smoke test. The two staged copies, two extracted copies, and two
RPMs are respectively byte-identical.

| Artifact | SHA-256 |
| --- | --- |
| RPM | `b8d6a86bf9d7be7f5d8200056896189b684838e4af8818f61ec4960de4e20c64` |
| Staged `secure` | `0858be0355acd118626e625f2163f70465e84a77b13e73ac26a4024b95f96722` |
| Staged `secure-desktop` | `c53d1d62983b94ed7d05905c8373f4556daf9fe8d7c3f9a7155b384fcbf5e117` |
| RPM-extracted `secure` | `f4fd8d99e0b0068ac34a0582a1536fbcebad931ec03644c2ed1dcbb939bc9fd3` |
| RPM-extracted `secure-desktop` | `8c2d624b2263e325c18befa48e24b1533eb7ad83c90a0bd875dda6a1caac4c05` |

Fedora build-root stripping explains the expected difference between staged and extracted ELF
hashes.

These gates establish only release reproducibility and regression conformance. They do not support
a ranking, superiority, production-readiness, complete-security-coverage, or future Secure Bench
performance claim.
