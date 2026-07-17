# Phase 6.7 Fedora verification

Release 0.1.3 is verified offline from the clean Phase 6.7 branch. The release gate includes
formatting, strict Clippy, the complete workspace suite, RustSec, cargo-deny, secure-json-v1 and
official SARIF schema validation, public contract-v2 vectors, the retired disclosed development
corpus, the 140-scenario independent suite, determinism, bounds, cancellation, privacy, CLI,
desktop, AppStream, and graphical smoke checks.

The retired diagnostics are development-only input: 28/28 vulnerable cases have exact contract-v2
evidence, 28/28 controls are clean, and no duplicate/unrelated finding is emitted. The independent
suite passes 70/70 vulnerable and 70/70 safe scenarios. Neither result is an unbiased benchmark.

The complete workspace suite contains 113 passing tests. `cargo audit --no-fetch --stale` reports no
vulnerability among 427 locked dependencies; cargo-deny reports advisories, bans, licenses, and
sources all clean. Phase 6.7 removes the prior quick-xml advisory exceptions by applying the scoped
vendored `wayland-scanner` compatibility patch documented under `vendor/README.md`.

A cold self-scan of 295 selected files (159 parsed) completed in 1.58 seconds with 269,364 KiB peak
RSS; a warm scan completed in 0.78 seconds with 264,824 KiB peak RSS and 159/159 cache hits. Both
produced report fingerprint
`3413046da3ddc1b717ca44642677a9edbc5c5b80b04f8ea5d0c9944bafa04b6d`, 34,834 graph nodes,
62,372 edges, 64 deduplicated findings, and no truncation.

Two clean package roots, `target/phase67-rpm-first` and `target/phase67-rpm`, produced byte-identical
8,785,476-byte RPMs:

- RPM SHA-256: `ceb9ce77feee5df9a1a5766e72fd610504f67cdd1a2a958753c75e4001501d8d`
- staged `secure` SHA-256: `3ad6c9be8ead5c88e7a01c8ef096aae6480e58ef75d504403e269dc8c6ea0a81`
- RPM-extracted `secure` SHA-256: `8678666b532380187d38968628908363970c960078c63489d26af35d31840902`
- RPM-extracted `secure-desktop` SHA-256: `274a5a3a65793a63560a55b4aac0e18c3178a3e1bec842fda67b73bf4857c88b`

Both package trees passed file-list and metadata inspection, extracted CLI rules/AI-provider smoke,
desktop-file validation, AppStream offline validation, and the five-second graphical desktop smoke.
The staged binary differs from the extracted binary because Fedora's build-root policy strips the
packaged ELF; the two staged copies and the two extracted copies are respectively byte-identical.
