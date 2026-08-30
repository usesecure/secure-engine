# Evidence calibration, causal identity, and scalable reporting milestone

## Scope and claims

This milestone adds deterministic calibration, causal value identity, parser correction, and bounded
report projection. It does not establish that a lead is a vulnerability, replace human validation,
or make a general human-superiority claim. A connected static path proves reachability only. Actor
identity, boundary crossing, runtime filesystem identity, and observable impact require separate
evidence.

Production logic contains no target repository, package, filename, symbol, endpoint, commit, or
campaign-specific exception.

## Architecture

ADR 0027 corrects ADR 0026. Calibration prerequisites default to unresolved and are promoted only
from typed source and sink semantics. Disposition follows the evidence rather than a rule identifier.
Ordinary environment, global, user, and runtime-mutation configuration represents equivalent
authority unless a distinct lower-privilege boundary is established. Typed sensitive environment
data reaching a proven diagnostic or remote disclosure channel retains its confidentiality finding;
attacker control and actor identity are not applicable prerequisites for that path. Explicit
abstentions are structurally excluded from `findings` and retain stable identity and evidence under
top-level `abstentions`.

The full fact set and graph remain available to analysis. Normal CLI output retains only finding and
abstention neighborhoods. Copy-on-write trace state avoids cloning shared path vectors, and report
fingerprints stream the same canonical JSON bytes directly into BLAKE3 instead of allocating a
second complete serialized report. `--full-graph` remains explicit and every export is subject to a
fail-closed byte budget.

## Neutral development matrix

`fixtures/evidence-calibration-reporting` was frozen before holdout re-observation. It covers valid
and malformed nested spreads; lower-privilege and equivalent-authority actors; independently proven
and missing boundaries and impacts; lexical and canonical path confinement; opened and revalidated
object shapes; symlink, hard-link, nested-link, race, FIFO, device, junction/reparse, and mount
uncertainty; read, write, remove, permission, rename, archive, and patch/update operations; and
wrappers, callbacks, aliases, duplicate helpers, renamed variants, and semantic flips.

The correction tranche separates attacker selection among trusted declared paths from attacker
control of the path value. It preserves a tainted returned-object field separately from its predicate
input and covers sources textually after nested helpers. Its three manifest-authority/lifecycle
policy shapes are explicit abstentions, with paired controls that bind the same dependency object,
complete URL scope, and policy before the operation.

The JavaScript parser repair is source-length preserving. The valid nested-spread family produces no
diagnostic and retains the expected declaration and call facts; malformed controls remain diagnosed.

## Reporting contract

`secure-json-v1` remains additive. `SE1013` is an abstention-only rule family and one-step evidence
paths are permitted only for a top-level structural abstention. Every serialized finding has a
disposition other than `explicit-abstention`; every top-level abstention has that disposition.
Consumers must not count abstentions as findings or vulnerability verdicts.

File output streams through a private sibling temporary file. Cancellation, serialization failure,
or `output-budget-exceeded` preserves any prior destination and publishes no partial file or stdout
prefix. No evidence required for reproduction is silently removed from a successful compact report.

## Secure Bench preregistration

Before a disjoint evaluation, freeze the Engine commit, compiler profile, host, configuration,
corpus manifest, exclusions, time/memory sampler, scorer, skilled-human protocol, and expected
outcomes. Do not modify the Engine or scorer after opening the holdout.

Primary measures are precision and recall by disposition; abstention precision and coverage;
parser-diagnostic rate; false-positive review time; time to first human-validated lead;
reproducibility; CPU, wall time, peak RSS, and report bytes per file/fact/finding/abstention; and a
paired skilled-human comparison using the same cases, source, time limit, evidence rubric, and tools.
Report disagreements and adjudication before aggregate metrics. Any bounded superiority statement
requires a separately preregistered effect size, interval, and multiplicity policy and must clear
precision and recall together.

Engineering gates are zero false diagnostics for valid nested-spread fixtures, diagnostic retention
for malformed controls, no silent evidence loss, identical normalized repeated output, npm compact
output below 64 MiB, npm peak RSS below 1 GiB, and npm wall time below 120 seconds.

## Recorded local results

All measurements used the optimized `secure-cli`, `--no-cache`, no target-code execution, and
`/usr/bin/time -v` on the same Fedora host. Normalized comparisons removed only documented timing,
cache-counter, and report-fingerprint fields.

The neutral matrix completed three times in 0.25–0.39 seconds with 11,732–12,060 KiB peak RSS. Each
run analyzed 11 files, 181 facts, 688 nodes, and 1,247 edges; retained 85 facts, 50 nodes, and 33
edges; and emitted 14 findings, 7 abstentions, and the 3 expected malformed-control diagnostics.
The 309,023-byte reports had identical normalized SHA-256
`3299835946c460158658b6878244d2663b1a6c791509f2e1c9b4547a0a15866e`.

The final Secure Engine workspace scan completed in 7.42 seconds with 284,752 KiB peak RSS. It
analyzed 427 files, 17,442 facts, 59,127 nodes, and 106,340 edges; retained 624 facts, 396 nodes,
and 346 edges in 2,755,743 bytes; and emitted 125 development-fixture findings and 14 abstentions. Its 8
parser diagnostics are confined to committed malformed controls.

The authorized npm CLI 12.0.2 checkout at
`b888cc9a9ff34a8b023ff47b784692396635397b` completed three root scans with explicit root and nested
`node_modules` exclusions. Each analyzed 4,847 files, 57,748 facts, 208,157 nodes, and 368,627
edges without truncation, parser diagnostics, or scan errors. No retained path entered
`node_modules`, `.git`, or an absolute path. Compact projection retained 14 facts, 7 nodes, and 4
edges in 2,507,777–2,507,779 bytes and emitted 0 findings and 3 abstentions. Normalized output was identical:
`20cd4d90d9ae3196cdb62ec0e3fe4013e06ab6ac0fc6269cdf52bca3d6282ef0`.

Repeated npm wall times ranged from 12.81 to 14.25 seconds. Peak RSS ranged from 986,848 to 987,324
KiB, below 1 GiB. Full-graph mode under the 64-MiB budget returned
`output-budget-exceeded` after 71.20 seconds, peaked at 986,904 KiB, and published no output file or
stdout prefix.

The original npm observations changed for general causal reasons:

- The outbound-request path is a top-level SE1004 abstention from environment configuration at
  `lib/utils/oidc.js:64`, through the local value at line 75, to the request at lines 78–84. It has
  reason `actor-authority-equivalence` and unresolved boundary and impact evidence.
- The filesystem candidate disappears. Its prior source was a selector whose loop body contained
  unrelated archive vocabulary. Header-scoped archive identity and fixed-map selection no longer
  represent selection control as direct path-value taint.

Two additional npm abstentions are retained: an environment-controlled command path in a test file
(SE1001) and an independent lifecycle-policy bypass shape (SE1013). Neither is a finding or a
vulnerability verdict.

The three historical vulnerable parents each emit 0 findings and 1 SE1013 abstention. Finding
recall remains 0/3; abstention coverage is 3/3. The positive-only holdout cannot estimate precision.
In the paired neutral tranche all three vulnerable shapes abstain and all three safe controls remain
clean. This does not convert the historical cases into proven Engine findings.

Verification used the explicit Rust 1.92 toolchain at
`/home/danielcastrillon/.rustup/toolchains/1.92.0-x86_64-unknown-linux-gnu/bin`. Formatting, strict
Clippy, compatibility, schema, cache, determinism, inventory, CLI, desktop, SARIF, baseline,
history, focused calibration/parser/taint/output-budget tests, and all 235 workspace tests passed.
`cargo audit` passed with only the two documented exceptions, and `cargo deny check` passed after
updating the locked transitive `webbrowser` dependency from 1.2.1 to 1.2.2 for
RUSTSEC-2026-0257.

## SecureFlow adapter changes

SecureFlow must accept additive `SE1013`, ingest `abstentions` as a separate non-finding lane,
support one-step abstention evidence paths, display calibration reason and prerequisite resolutions,
and never count `explicit-abstention` as a candidate or vulnerability. It should continue using
`projection` totals and fail-closed budget reasons. Corrected causal paths may intentionally change
their finding identity; unrelated fingerprints remain in the existing domain.

## Next milestone

Convert policy-composition abstentions into findings only where neutral fixtures establish
dependency origin, supported lifecycle reachability, a distinct lower-privilege actor, and an
observable effect. Extend compact internal IDs beyond shared trace state only if measured graph
construction remains the dominant cost. Then freeze a disjoint blinded Secure Bench tranche and run
the paired skilled-human comparison.
