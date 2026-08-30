# ADR 0027: Evidence-derived calibration, causal identity, and streaming fingerprints

## Status

Accepted as the correction to ADR 0026.

## Context

ADR 0026 added calibration fields, but the first implementation treated a connected source-to-sink
path as proof of actor identity, trust-boundary crossing, and observable impact. It also selected
dispositions from rule identifiers. Those defaults exceeded the evidence: configuration authority,
filesystem reads, and outbound destinations can be reachable without proving a distinct actor,
privilege gain, or an observable confidentiality, integrity, or availability channel.

An authorized holdout also exposed a causal-identity defect. A loop selector was classified as an
archive-entry value because unrelated body text matched archive vocabulary. That converted control
over selection among declared values into direct taint of the selected value. Separately, canonical
report fingerprinting allocated a complete serialized copy of the internal report after graph
analysis, creating the final large-repository memory spike.

## Decision

1. Initialize attacker control, actor identity, boundary crossing, and impact as unresolved. Promote
   each field only from typed source/sink semantics. Configuration provenance is evaluated across
   every applicable sink family. Ordinary environment, global, user, and runtime-mutation
   configuration represents equivalent authority unless separate lower-privilege evidence exists.
   Typed sensitive environment data reaching a local-diagnostic or remote-service disclosure sink
   instead has no attacker-control prerequisite and retains the proven confidentiality boundary and
   impact.
2. Select `security-path`, `bounded-hardening`, or `explicit-abstention` only from those resolutions,
   never from a rule identifier. Proven lower-privilege integrity or availability effects can be a
   security path. Proven reachability with missing impact is bounded hardening. Equivalent authority
   or a missing actor/boundary prerequisite is an abstention.
3. Enforce report authority structurally: no object with `explicit-abstention` disposition may occur
   in `findings`. Such paths are converted to top-level `abstentions` with the same fingerprint,
   source, sink, guards, evidence path, calibration, and limitations. If that complete record cannot
   be formed, omit it conservatively.
4. Keep selector/control dependence distinct from value flow. Fixed maps of trusted literal values
   do not taint the selected value merely because an attacker selects a key. Archive-member sources
   require archive/member evidence in the binding header rather than unrelated nested text. Exact
   returned-object fields, call sites, properties, helpers, and source order remain independently
   identified.
5. Add `SE1013` as a non-finding policy-composition observation. It emits only an explicit abstention
   for structurally incomplete manifest-authority/lifecycle-policy composition. Dynamic reachability,
   dependency origin, actor control, and impact remain unresolved. Paired neutral controls are clean.
6. Preserve full internal analysis and copy-on-write trace state. Stream canonical compact JSON
   directly into the BLAKE3 report hasher. This produces the same bytes and fingerprint as the former
   `to_vec` implementation while removing the redundant whole-report byte allocation.
7. Advance only the private parse cache envelope to `secure-parse-cache-v23`. Keep the public graph
   extractor identity stable so unrelated finding identities do not migrate. Corrected causal paths
   and newly precise filesystem sink semantics may intentionally receive new deterministic evidence
   fingerprints.

## Compatibility

`secure-json-v1`, SARIF 2.1.0, Evidence Contract v2, and `SE1001` through `SE1012` remain supported.
`SE1013` and one-step abstention evidence paths are additive. Older reports still deserialize with
empty abstentions. Consumers must treat `findings` and `abstentions` as disjoint authority lanes and
must not promote calibration to a human vulnerability verdict.

## Failure posture

Ambiguous actor identity, privilege boundary, runtime filesystem object identity, platform behavior,
lifecycle reachability, or impact remains an explicit abstention or bounded hardening lead. A
connected path alone never supplies those proofs. Output budgets and full-graph mode remain
fail-closed and never publish a partial document.

## Evaluation

The correction is developed only against the neutral parser, causal-identity, actor/boundary,
filesystem, and manifest-policy matrices. The pinned package-manager checkout and three historical
regression parents are holdouts. Report finding recall, abstention coverage, false-positive review
time, parser diagnostics, determinism, CPU, peak RSS, report bytes, and any remaining miss without
retuning production logic after observation.
