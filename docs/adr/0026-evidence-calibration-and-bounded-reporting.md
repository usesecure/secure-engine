# ADR 0026: Evidence calibration and bounded whole-repository reporting

## Status

Accepted for the parser, filesystem-identity, trust-boundary, and reporting milestone. The
evidence-default, disposition, abstention-routing, causal-identity, and fingerprint-memory decisions
are corrected by ADR 0027.

## Context

The Engine already keeps the complete graph for analysis and projects finding evidence by default,
but it retains every normalized fact and serializes an entire pretty JSON document into memory before
an atomic write. Large repositories therefore spend memory and output bytes on syntax facts that are
not required to reproduce a finding. Existing source-to-sink findings also do not separately state
actor authority, boundary crossing, filesystem identity, or demonstrated impact. Lexical path
confinement can prevent traversal while still leaving symlink, mount, replacement-race, or opened
object identity unresolved.

Tree-sitter recovery is useful for malformed input, but an authorized campaign observed a
recoverable JavaScript diagnostic near a valid nested array spread followed by a member call.
Suppressing diagnostics by source text would hide malformed programs and is not acceptable.

## Decision

1. Add a versioned, additive evidence-calibration object to findings. It records syntactic
   reachability, attacker control, actor authority, crossed trust boundary, the effective control,
   filesystem identity state, observable impact, and one of `security-path`, `bounded-hardening`, or
   `explicit-abstention`. These are static evidence dispositions, never vulnerability verdicts.
2. Add bounded abstention records for exact source/sink paths rejected because a filesystem control
   proves only lexical or canonical path confinement. Keep these outside the finding count and retain
   compact source, guard, sink, identity-state, and limitation evidence.
3. Treat process-environment control as actor-equivalent authority unless a lower-privilege boundary
   is independently proven. Preserve the path, lower confidence, and abstain on new impact. Request,
   tenant, and other external sources remain detectable under their existing rules.
4. Distinguish lexical path, canonical target, opened object, and revalidated object identity in the
   public calibration vocabulary. Static path checks never prove symlink, hard-link, mount, junction,
   device, FIFO, or replacement-race safety. A supported same-handle identity revalidation may be
   recorded only when exact value, scope, and ordering are proven; otherwise abstain.
5. Correct valid nested-spread parsing at the grammar/adapter boundary. Neutral valid and malformed
   controls must flip only on grammar validity; no filename, line, identifier, or target-specific
   exception is permitted. Advance the private parse cache for any parser or extraction change.
6. Keep all facts and the complete graph inside analysis. Default CLI output retains only finding and
   abstention evidence neighborhoods plus aggregate counts. `--full-graph` remains explicit; a
   separate output-byte budget applies to every export. Successful reports identify their fact and
   graph projection, total and retained counts, budget, and omission reason.
7. Stream file exports directly into a private temporary file through a cancelling byte-budget
   writer, then sync and atomically rename. If the budget is exceeded, remove the temporary file,
   preserve any prior destination, return the stable `output-budget-exceeded` reason, and publish no
   partial report. Stdout remains buffered so budget failure cannot publish a prefix.
8. Keep `secure-json-v1`, SARIF 2.1.0, Evidence Contract v2, taxonomy 1.0.0, and `SE1001` through
   `SE1012`. New fields are optional for older readers; existing finding identifiers remain stable.

## Failure posture

The Engine must not infer runtime filesystem identity, privilege gain, tenant crossing, delivery,
or impact from a connected path alone. Unsupported aliasing, callbacks, platform behavior, mounts,
junctions/reparse points, FIFOs/devices, archive semantics, and TOCTOU state produce explicit
abstention or limitation evidence. Output-budget failure is fail-closed and does not remove findings
from an otherwise successful report.

## Evaluation

The neutral corpus in `fixtures/evidence-calibration-reporting` is the development set. A later
Secure Bench tranche freezes disjoint parser, filesystem, actor-boundary, and scale cases before
running the npm and historical policy holdouts. It preregisters precision, recall, abstention
quality, parser-diagnostic rate, false-positive review time, time to first validated lead,
determinism, CPU, peak RSS, report bytes per source file/fact/finding, and paired skilled-human
comparison. Negative and inconclusive outcomes remain in the record.
