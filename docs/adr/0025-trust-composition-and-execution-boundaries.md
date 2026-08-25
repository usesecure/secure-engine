# ADR 0025: Trust composition and execution boundaries

## Status

Accepted for the trust-composition milestone.

## Context

Existing rules distinguish shell program text from ordinary argv and record workspace trust as a
platform guard, but they do not compose configuration provenance, trust scope, state freshness, and
the exact component of a process launch. That gap cannot be closed safely by treating every setting
name or process call as suspicious. Effective configuration may come from user, workspace,
workspace-folder, environment, manifest-default, runtime-mutation, or unresolved sources, and a
trust check for one value or scope must not authorize another.

## Decision

Add one bounded rule family, `SE1012`, for a proven configuration value crossing a process execution
boundary without a fresh, dominating trust proof for the same scope.

The first supported subset is intentionally narrow:

1. JavaScript and TypeScript configuration provenance is proven from a structurally owned
   `vscode.workspace.getConfiguration(...).inspect(...)` projection or an unshadowed
   `process.env.NAME` access. The public evidence distinguishes user/global, workspace,
   workspace-folder, environment, manifest-default, runtime-mutation, and unknown provenance.
2. Workspace and workspace-folder values are lead-producing provenance. User/global and manifest
   defaults are controls. Environment values are lead-producing at exact process boundaries because
   their authority is outside repository syntax. Runtime mutation and unknown effective precedence
   abstain.
3. Process ownership is proven through a stable `node:child_process` or `child_process` import. The
   exact binary, shell program, argv element, environment value, working directory, or shell-mode
   expression is the sink. Constant components are not findings.
4. A trust proof must structurally dominate the sink, describe the trusted state, bind the same
   workspace or workspace-folder scope, and occur after the last modeled invalidating transition.
   An `await` between proof and execution invalidates the proof. A workspace proof cannot authorize
   one folder in a multi-root loop, and a proof for one folder cannot authorize another.
5. Existing lexical function identities, call-site bindings, bounded argument/return propagation,
   stable imports, mutation killing, and deterministic graph ordering remain the composition
   substrate. No repository filename, symbol, setting key, fixture text, or holdout fingerprint is
   embedded in production logic.
6. Dynamic dispatch, computed configuration projections, mutable or underspecified decision-cache
   keys, callback lifecycle reachability, platform-specific process behavior, and effective
   configuration precedence outside the supported projection produce explicit limitations instead
   of proof.

## Evidence and compatibility

`secure-json-v1` remains the document version. `EvidenceSemantic` receives additive optional
configuration-provenance and execution-boundary fields, while existing fields and enum values remain
valid. `SE1001` through `SE1011`, Evidence Contract v2, taxonomy 1.0.0, SARIF 2.1.0, and unaffected
fingerprints remain compatible. `SE1012` has no frozen taxonomy mapping and therefore does not
project into Evidence Contract v2.

Private program records gain configuration, trust-scope, transition, and process-component identity,
so the parse-cache envelope advances from v20 to v21. Older cache directories remain untouched and
miss safely.

## Failure posture

An `SE1012` result is an unverified static lead, never a vulnerability verdict. Human validation must
establish supported configuration precedence, actor control, lifecycle reachability, platform
behavior, the launched executable's semantics, and actual impact. Absence of `SE1012` does not prove
that configuration-to-process behavior is safe.

## Evaluation

The neutral matrix in `fixtures/trust-composition-execution-boundaries` is the development gate. A
later Secure Bench campaign must freeze disjoint cases and preregister precision, recall, abstention
quality, false-positive review time, time to first validated lead, reproducibility, CPU time, peak
memory, serialized storage, and a blinded skilled-human comparison. Negative or inconclusive results
must remain in the record. No general human-superiority, guaranteed-discovery, or replacement claim
is permitted.
