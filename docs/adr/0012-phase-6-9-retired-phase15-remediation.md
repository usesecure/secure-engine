# ADR 0012: Value-associated evidence and retired Phase 15 remediation

Status: Accepted for Secure Engine 0.1.5.

## Context

The permitted retired Phase 15 handoff disclosed three separate concerns: an external adapter
projection defect, Engine source/span false negatives, and Engine barrier/propagation false
positives. Only the latter two belong in Secure Engine. The handoff source was not exported, so
case-specific repair or a benchmark rerun would be both impossible and outside the evidence
boundary.

## Decision

Represent source origin and relative field identity as immutable trace metadata, scope
JavaScript/TypeScript aliases to their qualified function, and resolve only unique aliases.
Preserve call argument positions and object property bindings when propagating into supported
helpers. Select sink inputs by API semantics, including APIs whose code or path input spans more
than the first argument.
Kill stale taint after unconditional clean reassignment while retaining conditional uncertainty.

Require guards and sanitizers to dominate and protect the propagated value identity, including
when a dominating caller barrier crosses a uniquely resolved helper argument. Keep role
authorization as an operation-level policy while binding ownership, tenant, and general
authorization to the protected value. Recompute provisional candidates until trace state reaches a
fixed point. Retain deterministic source tie-breaking by specificity, path, span, and source node.

Advance the private parse-cache envelope to v6. Keep the public graph extractor identity,
taxonomy 1.0.0, evidence contract v2, `secure-json-v1`, SARIF, CLI/desktop, baselines, history,
suppressions, privacy, bounds, cancellation, and disabled-AI contracts unchanged.

## Consequences

Independently authored cause pairs gain exact source/sink evidence and eliminate controls that only
taint nonsensitive arguments, sibling fields, stale aliases, or the wrong barrier value. Weak,
nonterminating, late, conditional, and wrong-value barriers remain findings. Evidence fingerprints
change only when evidence semantics change; metamorphic semantic fingerprints remain stable.

Dynamic resolution and runtime-only policy remain bounded. This decision does not implement the
Secure Bench adapter correction, rerun a benchmark, establish a ranking, or support superiority,
complete-coverage, production-readiness, or future-holdout claims.
