# Filesystem identity and scalable reporting milestone

## Scope and claims

This milestone adds deterministic calibration and report projection. It does not establish that a
lead is a vulnerability, does not replace human validation, and makes no general human-superiority
claim. A connected static path remains only evidence. Runtime identity, platform behavior, actor
authority, boundary crossing, and observable impact must be established separately.

The implementation is repository-independent. Production logic contains no target repository,
package, filename, symbol, endpoint, commit, or campaign-specific exception.

## Neutral development matrix

`fixtures/evidence-calibration-reporting` froze the development inputs and expected semantic classes
before holdout access. It covers valid and malformed nested spreads; environment-equivalent and lower-privilege actors;
lexical and canonical path confinement; opened handles and same-handle revalidation shapes;
symlink, hard-link, nested-link, race, FIFO, device, junction/reparse, and mount uncertainty; read,
write, remove, chmod, rename, archive, and patch/update operations; wrappers, aliases, callbacks,
renames, and semantic flips. The initial nested-spread expression was present before holdout access;
the declaration-boundary variation and matching malformed twin were added afterward to isolate the
observed grammar context without importing target vocabulary or changing the expected class.

The supported subset proves exact source-to-sink reachability and value-bound lexical/canonical
controls. It does not prove live filesystem object identity. Those controls therefore retain an
explicit `filesystem-object-identity-unresolved` abstention with source, guard, sink, identity level,
and limitation evidence. Environment-controlled outbound destinations remain visible at low
confidence with `actor-authority-equivalence`; independently modeled request sources retain a
security-path disposition.

## Reporting contract

Analysis still uses the complete normalized fact set and global evidence graph. Normal CLI output
retains only finding and abstention fact/graph neighborhoods and records full internal counts in
`projection`, `graph.total_nodes`, and `graph.total_edges`. `--full-graph` explicitly retains all
facts and graph nodes. `--max-output-bytes` defaults to 64 MiB in both modes.

File output streams through a private sibling temporary file. Cancellation, serialization failure,
or `output-budget-exceeded` removes the temporary file and preserves the prior destination. Stdout
is buffered so no invalid JSON prefix is published. No finding or evidence needed for reproduction
is silently removed from a successful compact report.

## Secure Bench preregistration

Before a disjoint Secure Bench evaluation, freeze the Engine commit, compiler profile, host,
configuration, corpus manifest, exclusions, time/memory sampler, scorer, skilled-human protocol, and
all expected outcomes. Do not modify the Engine or scorer after opening the holdout.

Primary measures:

1. Precision and recall by disposition, with exact source/sink and invariant matching.
2. Abstention precision, abstention coverage of unsupported cases, and unsafe overclaim rate.
3. Parser diagnostics per valid source file and malformed-control diagnostic recall.
4. Median and tail false-positive review time and time to first human-validated lead.
5. Reproducibility across three clean scans after removing documented timing fields.
6. CPU time, wall time, peak RSS, retained report bytes, and bytes per selected source file,
   extracted fact, finding, and abstention.
7. Paired skilled-human comparison on the same frozen cases, source, time limit, evidence rubric,
   and permitted tools. Report disagreements and adjudication before aggregate metrics.

Preregister minimum acceptable engineering gates independently of comparative claims: zero false
diagnostics for the valid nested-spread family; malformed controls still diagnosed; zero silent
finding loss under a successful projection; identical semantic fingerprints and ordering across
repeats; compact output below 64 MiB for the authorized npm root; peak RSS below 1 GiB; wall time
below 120 seconds. If a gate fails, report the failure without excluding the case or changing the
threshold. Any bounded superiority statement would require a separate preregistered effect size,
confidence interval, and multiplicity policy and must clear precision and recall together.

## Verification and holdouts

Development verification, workspace measurements, the authorized npm observation, and historical
policy-regression observations are recorded only after the neutral suite and complete workspace
gates. Holdout outcomes may remain findings, hardening leads, abstentions, or misses; no result is
forced into a favorable class.

## Recorded local results

All measurements used the optimized `secure-cli` binary, `--no-cache`, no target-code execution,
and `/usr/bin/time -v` on the same Fedora host. Timing fields and `report_fingerprint` were removed
only for the repeated-output equality check.

The final neutral matrix completed three times in 0.16–0.17 seconds wall time with 10,852–11,104
KiB peak RSS. Each run analyzed 8 files, 109 facts, 422 nodes, and 786 edges; retained 51 facts, 32
nodes, and 23 edges; emitted 10 findings, 2 filesystem-identity abstentions, and only the 3 expected
malformed-control diagnostics. The 204,513-byte reports had identical normalized SHA-256
`faf379421045ac62fe6e1d002e4ab7195c455de603bfdce962e170c2738332d0`. This is 25,564.12 bytes per
selected file, 1,876.27 per extracted fact, 20,451.30 per finding, and 102,256.50 per abstention on
this deliberately small evidence-dense corpus.

The Secure Engine workspace scan completed in 6.52 seconds with 386,672 KiB peak RSS. It analyzed
423 files, 17,028 facts, 57,744 nodes, and 104,101 edges; retained 559 facts, 353 nodes, and 300
edges in a 2,481,312-byte report. It emitted 111 development-fixture findings and 6 abstentions.
The 8 parser diagnostics are confined to committed malformed controls.

The authorized npm CLI 12.0.2 checkout at
`b888cc9a9ff34a8b023ff47b784692396635397b` completed three final root scans with explicit root and
nested `node_modules` exclusions. Each analyzed 4,847 files, 57,748 facts, 208,174 nodes, and
368,722 edges without truncation or scan errors. No retained path entered `node_modules`, `.git`, or
an absolute path, and all 4,847 retained file paths were unique. The compact projection retained 21
facts, 15 nodes, and 15 edges in 2,557,337 bytes: 527.61 bytes per selected file, 44.28 per extracted
fact, and 1,278,668.50 per finding. Normalized outputs were identical with SHA-256
`afdf995e5c9521a62f94ed99890120686e92f9726efae75b110ca1fc7121ba37`.

Final npm wall times were 12.84, 16.25, and 16.00 seconds; median user and system CPU were 12.98 and
2.37 seconds. Peak RSS was 1,343,676, 1,343,028, and 1,342,916 KiB. Time and report-size gates pass,
but the initial under-1-GiB peak-RSS target does not. The narrow remaining scale blocker is peak
memory while the complete fact graph, program records, and fixed-point state coexist; streaming
serialization no longer constructs the former hundreds-of-megabytes JSON buffer. Full-graph mode
under the 64-MiB budget returned `output-budget-exceeded` after 26.87 seconds and published no file.

The valid declaration-boundary nested spread in `lib/base-cmd.js` now has zero diagnostics. The
nearby malformed neutral controls still produce syntax and missing-syntax diagnostics.

The two npm candidates remain visible but their evidence is calibrated differently for generic
reasons:

- the environment/token path to an outbound request is low confidence with disposition
  `explicit-abstention`, reason `actor-authority-equivalence`, and unresolved trust-boundary and
  impact evidence;
- the manifest-derived filesystem read is a `bounded-hardening` lead with unresolved object
  identity, actor boundary, time binding, and impact channel.

Neither is called a vulnerability. Human validation remains mandatory.

The local historical vulnerable parents for file/link install-script enforcement
(`34dbdf51c^`), registry-path validation (`bf623e0a9^`), and global link install-script enforcement
(`60d0d3d7c^`) were found only after development and npm gates. Scans of the affected production
files emitted 0 findings and 0 abstentions in all three cases, so relevant historical recall remains
0/3. This negative result is retained; no commit, filename, API, or symbol was added to production
logic.

Workspace verification passed 231 Rust tests, including compatibility, schema, cache,
determinism, inventory, CLI, desktop, SARIF, baseline, history, and all existing rule suites.
`git diff --check`, locked Cargo metadata, and JSON syntax checks passed. The installed Fedora Rust
toolchain does not provide `cargo-fmt`, `rustfmt`, `cargo-clippy`, `cargo-audit`, or `cargo-deny`, so
those commands were unavailable rather than reported as passing.

## Changed files

The local milestone commit changes exactly these 35 repository-relative files:

- `README.md`
- `apps/secure-cli/src/main.rs`
- `apps/secure-cli/tests/cli_contract.rs`
- `crates/secure-engine/src/cache.rs`
- `crates/secure-engine/src/export.rs`
- `crates/secure-engine/src/graph.rs`
- `crates/secure-engine/src/lib.rs`
- `crates/secure-engine/src/model.rs`
- `crates/secure-engine/src/parser.rs`
- `crates/secure-engine/src/scan.rs`
- `crates/secure-engine/src/semantics.rs`
- `crates/secure-engine/src/storage.rs`
- `crates/secure-engine/tests/evidence_calibration_reporting.rs`
- `crates/secure-engine/tests/generalization_phase612_tranche2.rs`
- `crates/secure-engine/tests/generalization_phase612_tranche3.rs`
- `crates/secure-engine/tests/generalization_phase612_tranche4.rs`
- `crates/secure-engine/tests/generalization_phase613_tranche1.rs`
- `crates/secure-engine/tests/generalization_phase613_tranche3.rs`
- `crates/secure-engine/tests/remediation_phase69.rs`
- `crates/secure-engine/tests/trust_composition_execution_boundaries.rs`
- `docs/adr/0026-evidence-calibration-and-bounded-reporting.md`
- `docs/development.md`
- `docs/evidence-graph-and-rules.md`
- `docs/filesystem-identity-reporting-milestone.md`
- `docs/parsing-normalized-facts.md`
- `docs/secure-json-v1.md`
- `fixtures/evidence-calibration-reporting/README.md`
- `fixtures/evidence-calibration-reporting/actor-boundaries.js`
- `fixtures/evidence-calibration-reporting/filesystem-paths.js`
- `fixtures/evidence-calibration-reporting/filesystem-workflows.js`
- `fixtures/evidence-calibration-reporting/package.json`
- `fixtures/evidence-calibration-reporting/platform-abstentions.js`
- `fixtures/evidence-calibration-reporting/syntax-malformed.js`
- `fixtures/evidence-calibration-reporting/syntax-valid.js`
- `schemas/secure-json-v1.schema.json`

## Next milestone

Before a scored benchmark, reduce peak graph-analysis memory through deterministic interning or a
compact internal graph representation without weakening full-graph availability. In parallel,
design a neutral policy-enforcement tranche for manifest authority, dependency origin, and lifecycle
execution so the observed 0/3 historical recall gap has a general semantic target. Only then freeze
a disjoint blinded Secure Bench tranche under the preregistration above and run the paired skilled-
human comparison.
