# Phase 6.10 Fedora verification

The Secure Engine 0.1.6 candidate was evaluated offline on Fedora 44 x86_64 with Rust 1.96.1. AI
validation remained disabled by default. Secure Bench was not inspected or executed. Phase 6.10
met its final application exit condition and was completed in one signed DCO commit.

Formatting, strict Clippy with warnings denied, RustSec, and all `cargo-deny` checks passed after
the exceptional-control-flow completion. In total, 137 locked offline workspace tests passed;
the workspace tests include JSON Schema and official SARIF validation,
Phase 6.7--6.9 compatibility, CLI/desktop parity, disabled-AI, cache, cancellation, malformed-input,
symlink, privacy, bounds, and the independent safe/vulnerable Phase 6.10 matrices.

Two final clean Fedora RPM builds produced byte-identical 8,929,033-byte packages. RPM metadata,
file ownership, extracted CLI behavior, desktop-file validation, offline AppStream validation, and
five-second graphical desktop smoke checks passed for both builds.

| Artifact | SHA-256 |
| --- | --- |
| final `secure-engine-0.1.6-1.fc44.x86_64.rpm` (both builds) | `0f336a262d1c1cac51a73c625a7398c392feb9f3ecad2aa81f62cbc128a62a64` |
| staged `secure` | `503059b45c72d2ebdac2d40181e88cfa69b86fe122067c06c6364eeb19eb37a5` |
| staged `secure-desktop` | `0e6c7f0e8d21113a6fc52b874fc5367b5cb184a4e1f932957217201ef29727b9` |
| RPM-extracted `secure` | `ad91499f3de9918963c9189bd236f5eb99b78cb99954e30f50bbc3098f18a5e0` |
| RPM-extracted `secure-desktop` | `90c8d7773eb25efab928e6e0139b28dea32833e2d46c7bd1b9444125a60f7005` |

The final self-scan selected and scanned 320 files, parsed 165 files, emitted 12,076 facts, 40,742
nodes, 73,419 edges, and 77 findings without errors, suppression, or truncation. The cold run took
2.82 seconds wall time and 313,208 KiB peak RSS (1,575 ms parser time; 165 cache misses/writes). The
warm run took 1.34 seconds and 309,672 KiB peak RSS (113 ms parser time; 165 cache hits). Both report
fingerprints are `69cc570a522023377aac2968c8f95fb8f01cc13e46a1eff7bf1d8c13ee0798d7`;
after removing only documented volatile fields their canonical SHA-256 is
`9e64665461b290febae836144fac9bb27e42112dc8c8492a46de89c9e7fc6d57`.

The required one-time read-only application scan was run after the initial implementation freeze.
It still reported all 56 `SE1007` findings (345 files scanned, 301 parsed, 10,554 facts, 34,501
nodes, 55,627 edges, no suppressions or truncation) because the application used common TypeScript
`@/` module aliases, while that freeze resolved only explicit relative imports. The report SHA-256
is `b84112adede04942a6133b355dc9f785ed422bee2418c9d0dc431d021643b777` and its result fingerprint
is `3e0c6d3fbb9c830bea615a78373a85fc15f359a188f7fc99bf2bf0c41a50e234`.

An explicitly authorized second read-only pass was labeled iterative dogfood verification, not an
independent holdout or one-shot benchmark. It ran in a network namespace exposing only loopback,
with AI disabled, the CMS tree mounted read-only, and fresh external cache/output directories. It
scanned the same clean commit and reported one `SE1007`: 55 original fingerprints resolved, one
remained byte-identical, none changed semantically, and none were newly introduced. The report
SHA-256 is `ff60a3b0f3131139bdc77a389f1d1e3554d4f8dcaa7ec5bb9f1d96fad10523a6`, its result fingerprint
is `4f1aaee2baf4c215f6d7aa8d1a3a7dcc58400e4adffa0324a835653ce62ffca2`, wall time was 2.08 seconds,
and peak RSS was 250,568 KiB. It parsed 301/345 scanned files, produced 10,554 facts, 34,501 nodes,
55,854 edges, one candidate/finding, zero suppressions, zero bounded errors, and no truncation. The
first post-remediation report remains byte-identical at
`b84112adede04942a6133b355dc9f785ed422bee2418c9d0dc431d021643b777`.

The second-pass remaining case showed a general control-flow boundary: candidates nested in any
`try`/`catch` were rejected even when their failure branch used `return`, which exits the function
without entering `catch`. The implementation now accepts only return-terminated failure branches
in that situation. A normal, side-effect-free `finally` preserves the pending return; a `finally`
containing return, throw, redirect/call, mutation, or loop continuation invalidates the proof.
Caught throw/redirect continuation remains vulnerable. Independent paired and adversarial fixtures
cover those outcomes, plus deceptive names, comments, and paths, and the complete workspace suite
passed at that checkpoint.

The explicitly authorized third read-only CMS pass used the same network, AI, mount,
cache, and output restrictions. It reported six unchanged original `SE1007` findings: 50/56 exact
fingerprints resolved, six remained unchanged, zero changed, and zero were new. All six are in
`src/modules/content/server/slug-actions.ts`, with source/sink lines 70/77, 70/75, 37/66, 70/76,
37/67, and 37/64. Their fingerprints are:

- `3e72dde05a080108c3c8f319612cf93017c4bf33798ac36881db6e6a934aa571`
- `90aab09ca2c6d8339d98630c1916dc71f1d1aec596657bdfe932c792d9e24a9b`
- `9d45c32bf3274104dbf7d577001ef981f288bbdb87d27c6f18b7b9ef322e9c75`
- `ee4cdd66d1e0ae457344b38ed9b780bb8ee0df7b91ca013787a0177f674ff74b`
- `6941de5372f185f513682cfb0c13a16e98250d93d9c0f8a0bf366eb58c150f9d`
- `e727b66b60c56a3524e5ba56a3bd0ab45415823c803a681eff4a1fad891b9b15`

The final report SHA-256 is
`439113a3e8a2b4e124274955a06aba7d4a09f10486ae0572fe17c7ed497cbf6d`, its result fingerprint is
`98efacced9f0a73ffeb1c806c3740c7c9747da9bee50204975daed3dae4e6cf5`, wall time was 2.42 seconds,
and peak RSS was 250,680 KiB. It parsed 301/345 scanned files, produced 10,554 facts, 34,463 nodes,
55,748 edges, six candidates/findings, zero configured or applied suppressions, zero errors, and no
truncation. The 10,000-finding bound was not approached, so the 50 resolutions are attributable to
structural guard semantics rather than suppression or result filtering.

The first and second reports remain byte-identical at
`b84112adede04942a6133b355dc9f785ed422bee2418c9d0dc431d021643b777` and
`ff60a3b0f3131139bdc77a389f1d1e3554d4f8dcaa7ec5bb9f1d96fad10523a6`.
The six-finding control-flow shape was then reproduced with independent fixtures and corrected
through generic return/throw reachability across nested catches. A catch is accepted only when every
path returns, rethrows, or invokes one uniquely resolved local helper that structurally always
throws; ambiguous, recursive, unresolved, normally returning, conditionally terminating, effectful,
and outer-swallowed paths remain conservative.

The explicitly authorized fourth and final read-only CMS pass used the same clean source commit
`4c3de58838c595afb06fbea4e5bac2abc90bab01` and tree
`8c832fbff0168bec84b52be50c7cca09e1a5304d`. It ran exactly once with AI disabled, only the loopback
interface present, the source tree read-only, and fresh external cache/output directories. All 56
original exact fingerprints were absent: 56 resolved, zero unchanged, zero changed, and zero newly
introduced. The complete report contained zero configured/applied suppressions, zero errors, and no
truncation. It scanned 345 files, parsed 301, emitted 10,554 facts, 34,411 nodes, and 55,575 edges.
The internal scan duration was 8.616 seconds; isolated wall time was 12.98 seconds and peak RSS was
257,596 KiB. Its SHA-256 is
`6f03c093535c6108b9135105ae49295ed8432479e91600c6b050b20131cc87a2` and report fingerprint is
`8d8bdfcedd3b878f61be4b6e95af5f3c2f6ad13a7c5cf4610b9d23b50efaa690`. No fifth scan was performed.

After the final application pass, formatting, strict Clippy, 137 locked offline tests, RustSec, and
all `cargo-deny` checks passed again.

The public taxonomy remains 1.0.0; evidence contract v2, secure-json-v1, SARIF 2.1.0, rule IDs,
fingerprints for unaffected findings, and disabled-by-default AI behavior remain compatible. Phase
6.10 advances only the private cache envelope to `secure-parse-cache-v7`.

This verification supports no benchmark score, ranking, comparison, superiority, production-
readiness, complete-security-coverage, or future-application claim.
