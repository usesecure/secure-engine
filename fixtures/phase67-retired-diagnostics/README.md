# Phase 6.7 retired diagnostic development corpus

This directory is an immutable, explicitly disclosed development copy of Secure Bench's retired
Phase 6 diagnostic package. It is regression input, not an unseen holdout and not an unbiased
benchmark. Results from it support only development-corpus conformance claims.

- Public diagnostic package SHA-256: `6966c507db9fb0c1efda62dd9e07ccecb80aff56962c29af27a1b0f2877cd4f4`
- Regression manifest SHA-256: `68269560554cb9f3c1d837912321e2f34a1cc1bef81602aec9994efa726a7a17`
- Imported cases: 56 (28 disclosed vulnerable cases and 28 paired safe controls)
- Import rule: byte-for-byte copies from the permitted public diagnostic directory
- Prohibited use: ranking, superiority, production-readiness, or unbiased performance claims

Secure Engine tests verify the frozen manifest hash, all declared case metadata, exact contract-v2
evidence for vulnerable cases, clean safe controls, and the absence of diagnostic identifiers and
fixture vocabulary from production scanner source.
