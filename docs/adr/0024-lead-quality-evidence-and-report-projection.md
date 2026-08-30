# ADR 0024: Typed lead evidence, call-site binding, and compact report projection

## Status

Accepted for the current development milestone.

## Context

The first bounded SecureFlow campaign against the VS Code Go extension produced three SE1010 leads, and manual review rejected all three. Any exported TypeScript function was treated as an exposed request boundary, SE1010 accepted any taint class, helper return summaries were shared across unrelated call sites, and local diagnostic sinks were labeled as external disclosure. The 286-file report serialized a 47,292-node, 83,687-edge global graph and occupied about 116 MiB even though the three findings referenced only 22 unique nodes. A separately noticed transient Node listener was not represented at all.

## Decision

1. Framework request sources require request-specific member/accessor structure. Registered handlers and server actions remain the stronger reachability evidence; export alone cannot turn a generic `.get(...)` call into an HTTP-header source.
2. Sensitive data, attacker-controlled data, data class, receiver, sink, and disclosure locality are independent semantics. SE1010 accepts only a typed sensitive source.
3. Argument-derived interprocedural traces carry the exact call record that introduced them. A callee return can be consumed only by that call site; an intrinsic source created inside the callee remains reusable by genuine callers. Duplicate same-name functions in one file receive lexical-span-qualified private identities.
4. Local diagnostic and remote-service SE1010 leads retain the SE1010 ID but receive different titles, impact text, prerequisites, locality, and actor/boundary context.
5. Evidence maturity uses `secure-evidence-state-v1`. Deterministic static construction is not manual validation.
6. SE1011 is additive. It requires a stable receiver assigned directly from an unshadowed `createServer` imported from `net` or `node:net`, followed in the same lexical function by `receiver.listen(port)` or an equivalent host-omitting supported shape. Explicit loopback, dynamic host, Unix socket, ambiguous receiver, mutation, or unproven module ownership causes abstention.
7. `vscode.workspace.isTrusted` is a platform guard, not authorization proof. A manifest `capabilities.untrustedWorkspaces.supported` declaration is exported as context but does not suppress a lead.
8. The full graph remains the analysis substrate. Normal CLI JSON uses a finding-evidence projection and records full graph totals; `--full-graph` is the explicit diagnostic opt-in.

## Versioning and compatibility

- `secure-json-v1` evolves additively with graph scope/totals, semantic data class/locality, evidence state, and lead context.
- SE1001–SE1010 IDs remain unchanged; SE1011 is additive and intentionally has no frozen taxonomy mapping yet.
- Graph extraction provenance advances to `secure-evidence-graph-v2`; the graph identifier hash domain remains v1 so unchanged nodes, edges, and location-sensitive finding IDs remain stable. Semantic and report fingerprints may change when typed meaning or projection changes.
- Public Evidence Contract v2 remains frozen at semantics v2. Graph semantics v3 are projected into v2 only for already supported contract rules.
- The parse cache safely misses pre-v2 graph units.

## Consequences and residual risk

Precision improves without repository-specific suppression. Local secret logging remains a qualified SE1010 lead, while ordinary settings and extension state do not. The listener rule intentionally reports prerequisites and unresolved runtime conditions and makes no vulnerability claim.

The taint store still retains one preferred trace per function/value key. Call-site binding prevents the observed cross-call false positive, but competing contexts can cause conservative false negatives. Dynamic imports, reassignment, callbacks, runtime middleware, activation events, interface selection, port discovery, firewall behavior, timing, protocol semantics, and duplicate status remain outside this milestone.
