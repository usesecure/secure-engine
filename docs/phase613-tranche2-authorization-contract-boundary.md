# Phase 6.13 tranche 2: authorization contract boundary

## Evidence boundary

This tranche starts from Secure Engine commit
`2bc782ffd8e2978a92aab50b00eee197155b895e`. Secure Bench commit
`735149c48713ecdf42cc371860ea12809212b647` was read only as frozen causal
evidence. No holdout, runner, adapter, scanner, or scoring command was executed,
and no historical fixture text was copied into Engine tests.

The eight Phase 33 authorization observations are analyzed as contract inputs,
not as a measured recovery target. Their common operation is an in-memory
`Map.set`; that syntax does not establish persistence, cross-tenant impact, or a
protected resource.

## Exact reconciliation

| Historical case | Framework / topology | Handler evidence | Sink evidence | Exact blocking boundary |
| --- | --- | ---: | ---: | --- |
| `c-20f311b74d292918fb0c` | Node / direct | 0 | 0 | Exposure is undeclared and the map mutation has no protected-operation contract. |
| `c-6e40098b628704501619` | Express / helper | 0 | 0 | No route registration exists and the map mutation is domain-ambiguous. |
| `c-94d7338fa1f834a76a9b` | Next / inter-file | 0 | 0 | Root-file packaging proves no App Router entrypoint; the mutation is domain-ambiguous. |
| `c-9be91e17b49cd1781f56` | Server Action / control flow | 2 | 0 | Exposure is proven, but the mutation has no protected-operation contract. |
| `c-b0749f9256a964ff1c53` | Node / direct | 0 | 0 | Exposure is undeclared and the map mutation is domain-ambiguous. |
| `c-ba2030903e525843387a` | Next / inter-file | 0 | 0 | Root-file packaging proves no App Router entrypoint; the mutation is domain-ambiguous. |
| `c-cbcb0c520f2e8eb8602e` | Express / helper | 0 | 0 | No route registration exists and the map mutation is domain-ambiguous. |
| `c-f15c6e3bea1f31c4048c` | Server Action / control flow | 2 | 0 | Exposure is proven, but the mutation has no protected-operation contract. |

The disjoint Engine-state equation is
`8 = 6 entrypoint-and-sink-not-modeled + 2 sink-not-modeled`.
Independently, all eight require unavailable domain knowledge to classify the
map as protected storage. Four also contain the already documented recoverable
syntax defect; that fact is non-exclusive and does not change the equation.

## Structural contract audit

| Required proof | Demonstrated observations | Result |
| --- | ---: | --- |
| Structurally exposed handler | 2/8 | Only the two Server Actions are handlers. Arbitrary root exports and request-shaped parameters do not prove exposure. |
| Authenticated principal lineage | 0/8 | A local function returning a fixed value is not structural authentication; its name cannot supply trust. |
| Request-controlled target ID | 8/8 | Phase 33 records an untrusted source in every observation. |
| Target resource load plus canonical ID | 0/8 | No target record and canonical ID are bound to the mutation. An ignored lookup of an unrelated key is not a load proof. |
| Dominant tenant guard | 0/8 | No tenant comparison terminates the unauthorized path. |
| Dominant owner guard on the same resource | 0/8 | The only owner-shaped predicate is ignored and applied to an unrelated key. |
| Same principal, requested ID, loaded resource, and mutation resource | 0/8 | The required RC5 identity chain is absent. |
| Protected operation recognizable without nominal heuristics | 0/8 | `Map.set` alone does not distinguish persistence from a local table, memo, cache, test double, or transient index. |

Consequently none of the eight cases is safely correctable under the current
Engine contracts. Promoting `Map.set`, `Set.add`, computed/property assignment,
generic methods, arbitrary exports, or request-shaped functions would create
authorization sinks or entrypoints without evidence. It would also bypass RC5's
exact principal/resource guarantees.

## Decision and synthetic boundary

No analyzer semantic is changed. Cache v15 remains current because facts,
records, graph construction, and finding semantics are unchanged. Rule IDs,
schemas, Evidence Contract v2, secure-json-v1, SARIF, fingerprints, CLI/desktop,
privacy, bounds, cancellation, and disabled-by-default AI remain unchanged.

Independent synthetic regressions prove three boundaries: an existing
structurally exposed supported repository mutation still emits SE1007; local
maps, sets, property writes, cache-like methods, bound aliases, wrappers, and
dynamic receivers do not become sensitive-mutation nodes; and an arbitrary
export is not a graph handler until framework registration is structurally
present.

These tests contain no historical identifiers, strings, layouts, or source.

## Future opt-in contract

A future tranche may introduce a separately reviewed, versioned
`secure-protected-operation-contract-v1`. It must be explicit repository input,
not an inference from names or comments. At minimum it would declare:

- a repository-relative module and exact exported entrypoint when framework
  structure cannot prove exposure;
- uniquely resolvable principal-resolver, protected-resource-loader, and
  mutation symbols;
- exact argument positions and canonical resource-ID projection;
- required tenant and owner policies; and
- the specific receiver or symbol whose operation is protected.

The declaration may supply domain facts only. The Engine must still prove the
request-ID flow, authenticated principal lineage, resource load, canonical ID,
two terminating dominant guards, same principal/resource identity, and the
declared operation call. Ambiguous aliases/imports, mutation between proof and
operation, dynamic dispatch, ambiguous wrappers, continuing catch/finally
paths, and exhausted depth must reject the proof. A contract implementation
would require schema/version review, public compatibility review, cache
invalidation, and its own implementation tranche; this tranche does not add it.

## Verification

Rust formatting and strict workspace Clippy (`-D warnings`) passed. The complete
offline workspace suite passed 181 executed tests with zero failures; the three
retired diagnostics were excluded explicitly by test name. The run includes the
three tranche-specific boundary tests, Phase 6.11–6.13 and RC5 regressions,
schemas, Evidence Contract, SARIF, fingerprints, CLI/desktop, privacy, bounds,
cancellation, and disabled-AI behavior.

RustSec checked 427 locked dependencies against the existing 1,160-advisory
database with no fetch and only the two documented historical ignores
(`RUSTSEC-2026-0194` and `RUSTSEC-2026-0195`). Offline `cargo-deny` passed
advisories, bans, licenses, and sources. No holdout, scanner, packaging,
installation, release, tag, or push command was run.

## Limitations

Static syntax cannot determine whether an arbitrary in-memory collection is a
durable authority boundary. The eight observations remain domain-knowledge
limits, not confirmed Engine defects and not measured recoveries. No claim is
made about holdout metrics, ranking, production readiness, or complete tree
coverage.

For compatibility, current SE1007 candidate construction may use a demonstrated
request-source trace for an already supported mutation even when the graph has
no handler node. This tranche neither broadens nor changes that behavior. It
cannot serve as the entrypoint proof for a future opt-in protected-operation
contract, which must require structural framework evidence or an explicit
versioned declaration.
