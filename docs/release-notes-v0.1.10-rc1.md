# Secure Engine 0.1.10-rc1 release candidate notes

Secure Engine 0.1.10-rc1 preserves the large-repository graph-indexing optimization released in
0.1.9 and incorporates the already integrated Phase 6.15 cross-language security invariants. It
adds `SE1008` for CLI option-boundary violations, `SE1009` for shared-prototype mutation, and
`SE1010` for sensitive configuration disclosure to logging or AI/LLM provider payloads.

The three rules are additive. `SE1001`–`SE1007` retain their public compatibility, and the
taxonomy 1.0.0 and Evidence Contract v2 mappings frozen for those seven rules remain unchanged.
`SE1008`–`SE1010` do not introduce or invent CWE or taxonomy mappings. The candidate preserves
`secure-json-v1`, SARIF 2.1.0, deterministic spans and fingerprints, baselines, history,
suppressions, CLI/desktop parity, privacy, bounds, cancellation, and disabled-by-default optional
AI behavior.

The private parse cache remains at v20 because this candidate changes no analyzer semantics.
Cache envelopes from earlier versions produce safe misses and are never reinterpreted. Cold and
warm scans continue to require equivalent facts, graphs, findings, evidence, ordering, spans, and
report fingerprints.

This candidate adds no dependency changes, benchmark corpus, benchmark execution, rescoring, or
new performance or security-coverage claim. Qualification requires two fresh, independent,
offline and locked Fedora 44 builds from the exact signed candidate commit. RPMs and
staged/extracted CLI and desktop binaries must be byte-identical, and no physical checkout,
target, staging, or rpmbuild path may appear in either executable.
