# Secure Engine 0.1.9-rc1 release candidate notes

Secure Engine 0.1.9 preserves the complete public and analysis semantics of 0.1.8 while replacing
repeated whole-program graph searches with deterministic indexes by file, function, and output.
The change targets large repositories without reducing facts, graph limits, inter-procedural depth,
rules, findings, or evidence.

On the controlled OpenStatus benchmark using release binaries, `--no-cache`, and default limits,
the graph-analysis phase fell from 110.033 seconds to a median 6.089 seconds across three optimized
runs. Internal scan time fell from 115.061 seconds to 11.403 seconds and end-to-end time including
JSON export fell from 118.77 seconds to 14.20 seconds. Peak resident memory increased by 1.36%.

The before/after reports retained exactly 81,306 facts, 250,000 graph nodes, 368,983 edges, and ten
findings. Finding, graph, evidence, ordering, and report fingerprints were identical. The graph node
limit remains reached and the report remains explicitly truncated. The full JSON output remains
approximately 596 MB; compact export is not part of this release.

Taxonomy 1.0.0, Evidence Contract v2, `secure-json-v1`, SARIF 2.1.0, rule IDs, fingerprints,
CLI/desktop behavior, baselines, history, suppressions, privacy, bounds, cancellation, optional AI,
and private parse cache v16 remain compatible. No dependency, rule, scanner, benchmark corpus, or
new security-coverage claim is part of this candidate.

Qualification requires two fresh, independent, offline and locked Fedora 44 builds from the exact
signed candidate commit. RPMs and staged/extracted CLI and desktop binaries must be byte-identical,
and no physical checkout, target, staging, or rpmbuild path may appear in either executable.
