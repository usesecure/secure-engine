# Trust-composition and execution-boundary milestone

## Scope and evidence boundary

This milestone began from verified Secure Engine commit
`e6001c01406fbef3327ede86a351c377c6484c47` in an isolated worktree. The neutral development matrix
was fixed before observing the external target. The final observation used the clean, read-only
vscode-go checkout at `28e27ffd3a0eca1de30b1a9656a75cbd47e94e4e`; no target code was executed and
no target-specific string, symbol, path, or fingerprint entered production logic.

`SE1012` is an unverified lead generator. A human must validate configuration precedence, actor
control, scope, lifecycle reachability, platform behavior, executable semantics, and impact before
calling any result a vulnerability. Absence of a result is not proof of safety.

## Delivered semantic subset

The implementation composes stable import ownership, lexical function and call-site identity,
bounded argument/return propagation, configuration provenance, exact trust scope, state freshness,
and exact process components. It reports proven workspace, workspace-folder, or environment values
at binary, shell-program, argv, child-environment, cwd, or shell-mode boundaries when no fresh,
dominating same-scope trust proof exists. Constants, user/global values, manifest defaults, fresh
same-scope guards, and trusted multi-root loop iterations remain controls.

Dynamic effective configuration, runtime mutation, duplicate helper dispatch, callback lifecycle,
underspecified cache keys, and unresolved platform behavior abstain explicitly. Public
`secure-json-v1` receives only optional semantic fields and one semantic role; Evidence Contract v2,
taxonomy 1.0.0, SARIF 2.1.0, and `SE1001` through `SE1011` remain compatible. The private parse cache
advances from v20 to v21 and safely misses older entries.

## Neutral release measurements

Two release, cache-disabled scans of `fixtures/trust-composition-execution-boundaries` were run on
the same machine. These are engineering observations, not a representative benchmark.

| Metric | Run 1 | Run 2 |
| --- | ---: | ---: |
| Files scanned | 15 | 15 |
| Normalized facts | 139 | 139 |
| Internal graph nodes / edges | 447 / 687 | 447 / 687 |
| Default serialized graph nodes / edges | 28 / 18 | 28 / 18 |
| Findings | 11 SE1012 | 11 SE1012 |
| Internal scan / parse / analysis | 8 / 4 / 2 ms | 7 / 4 / 2 ms |
| User + system CPU | below 0.01 + below 0.01 s | below 0.01 + below 0.01 s |
| Wall time | 0.01 s | 0.01 s |
| Peak RSS | 12,028 KiB | 12,084 KiB |
| Pretty report size | 241,546 bytes | 241,546 bytes |

Both runs produced report fingerprint
`48906ae54d3c97d487bb0ba8d59d1e90608cb720b983882ad98cde0bba36d1fe` and identical ordered
files, facts, graph, findings, and fingerprint projection with SHA-256
`9f64b01aea199a839f3a96086015e62ced6ccf55329e545abd84a2a53a9cdaf1`.

## Final vscode-go observation

The same release executable (SHA-256
`fd3ae4ebaa761db9113600f9ffd662eb46c6947e77f78892b61e489b0ae86dbe`) scanned the pinned checkout
twice with `--no-cache`.

| Metric | Run 1 | Run 2 |
| --- | ---: | ---: |
| Files scanned | 373 | 373 |
| Normalized facts | 13,494 | 13,494 |
| Internal graph nodes / edges | 49,187 / 88,353 | 49,187 / 88,353 |
| Default serialized graph nodes / edges | 2 / 1 | 2 / 1 |
| Findings | 1 SE1011, 0 SE1012 | 1 SE1011, 0 SE1012 |
| Internal scan / parse / analysis | 1,809 / 1,031 / 646 ms | 1,748 / 1,027 / 646 ms |
| User + system CPU | 1.88 + 0.16 s | 1.88 + 0.15 s |
| Wall time | 2.09 s | 2.04 s |
| Peak RSS | 334,880 KiB | 334,864 KiB |
| Pretty report size | 11,300,443 bytes | 11,300,442 bytes |

The one-byte report-size difference is volatile timing metadata. Both runs produced report
fingerprint `68a0935ff904ebf09e898e91ea533d12da76fc110414362fabf69075617105cb` and identical ordered
files, facts, finding-evidence graph, findings, and fingerprint projection with SHA-256
`1477d20f693e87d1a81ab83d583495ff7d4aaad2c8d46c69a3b4509eeb2afffc`. The retained SE1011 is the
previous bounded syntactic listener lead; it was not revalidated and is not a vulnerability claim.

## Verification and residual limits

Formatting, whitespace, all-target workspace checking, focused strict Clippy, the neutral suite,
the focused precision and lead-quality suites, schema validation, and the complete all-features
workspace test suite pass. Whole-workspace strict Clippy reaches the unchanged
`crates/secure-engine/tests/ai_phase6.rs` and reports its existing `search_is_some` lint; the changed
Engine and CLI targets are clean with `-D warnings`. `cargo audit` and `cargo deny check` both ran
and identified the pre-existing transitive desktop dependency `webbrowser 1.2.1` under
RUSTSEC-2026-0257; no dependency file changed in this engine-only milestone.

The supported subset does not resolve configuration precedence from dynamic `.get` calls, env files,
terminal/debugger/language-server lifecycle APIs, arbitrary callback reachability, general alias or
points-to analysis, runtime cache invalidation, OS executable lookup, inherited descriptors or
environment, filesystem state, permissions, or executable-specific argv interpretation.

The next Secure Bench milestone is a frozen, disjoint, blinded trust-composition tranche following
`docs/bounded-human-tool-benchmark-protocol.md`. It will preregister precision, recall, abstention
quality, false-positive review time, time to first validated lead, reproducibility, compute and
storage cost, and paired skilled-human comparison. Negative and inconclusive results remain part of
the record; no general superiority, guaranteed-discovery, or human-replacement claim is permitted.
