# VS Code Go lead-quality milestone

## Evidence boundary

Diagnosis began from the clean isolated Secure Engine worktree at
`97916e9502e1fcede0d22e4ed84b3f63188d163a`. The VS Code Go source was the clean,
read-only checkout at `28e27ffd3a0eca1de30b1a9656a75cbd47e94e4e`. The four campaign records under
SecureFlow were read as local evidence and were not modified. The qualified baseline executable
was v0.1.10-rc2 with SHA-256
`1094f6640d690586da00a5e169e5b5d172580f90b25ff471811ad1c1fbf6fb91`.

The unmodified Engine was rebuilt and its behavior reproduced before implementation. It produced
the same three SE1010 finding IDs as the campaign record. Manual campaign review had rejected all
three; this milestone treats them only as false-positive observations, not vulnerability evidence.

## Diagnosis and root causes

| Observation | Root cause |
| --- | --- |
| `go.lintTool` became an HTTP-header source | Exported functions were eligible for a generic terminal `.get` source model. The receiver and accessor structure did not have to prove an HTTP request/header API. |
| Values crossed unrelated functions and files | Calls to the same helper consumed one function-wide `@return` node. Argument-to-return traces did not retain the exact call-site binding, so equal helper identities could join unrelated invocations. |
| Local debug output became external disclosure | Console/debug logging and remote provider calls shared one disclosure sink identity and had no explicit locality. |
| Survey state became secret disclosure | Generic `.get` classification supplied a false sensitive source, while the sink-only SE1010 selector did not require a typed sensitive data class. |
| `verified-deterministic-path` overstated evidence | The label described deterministic graph construction, but could be read as manual validation or exploitability evidence. |
| The reverse DAP listener was absent | There was no receiver-aware model for a Node `net.Server` followed by `listen(port)` without an explicit host. |
| Three findings produced a 120.8 MB report | The normal report serialized the complete evidence graph. In canonical compact JSON, the graph was 73,784,608 of 81,289,236 bytes (90.77%); facts were 7,352,791 bytes (9.05%), and findings were 36,338 bytes. |

## Architecture decision

The implementation is a bounded semantic correction rather than a broad rule expansion:

- Sensitive sources now carry an explicit data class: ordinary configuration, credential, token,
  personally identifiable information, or unknown-sensitive. SE1010 requires a genuinely sensitive
  source class.
- Disclosure sinks carry locality. Local diagnostics and remote providers no longer share a
  semantic identity, while real sensitive-to-local-log and sensitive-to-remote-provider controls
  remain detectable.
- Interprocedural traces retain exact call-record bindings when entering and returning from a
  helper. A callee return can satisfy only the invocation that placed it on the trace.
- Graph symbol identities retain lexical context, including a private span suffix for duplicate
  same-name functions. Export status alone cannot turn a generic `.get` into an HTTP-header source.
- Evidence state uses the versioned `secure-evidence-state-v1` taxonomy:
  `syntactic-lead`, `semantic-path`, `guard-aware-lead`, and `manually-validated`. The Engine never
  emits `manually-validated` by itself.
- `vscode.workspace.isTrusted` and the `untrustedWorkspaces` manifest declaration are modeled as
  platform conditions, not authentication or proof that a path is safe.
- Additive SE1011 recognizes a proven Node built-in `net.Server` receiver followed in the same
  lexical function by a supported `listen` call with no host. It emits a low-severity,
  medium-confidence network-exposure lead with actor, bind behavior, activation, race/window,
  firewall, routing, runtime, and port-discovery limitations. It is not a vulnerability verdict.
- The default CLI report contains only finding path nodes, their exact edges, and relevant guards.
  Full graph totals remain visible, and `--full-graph` preserves an opt-in complete graph.

SE1001-SE1010 rule IDs and Evidence Contract v2 remain supported. SE1011 is additive. The
`secure-json-v1` version remains unchanged through optional fields and expanded semantic enums.
Graph semantics move to `secure-evidence-semantics-v3`; the contract projection remains on its
frozen v2 semantics. Existing `verification_state` consumers must accept the corrected state names,
and consumers that need the former global graph must request `--full-graph`. Stable ordering and
fingerprint algorithms remain unchanged; fingerprints change where corrected semantics or report
projection change their inputs.

## Implementation and changed files

Core model, extraction, analysis, and projection:

- `crates/secure-engine/src/model.rs`
- `crates/secure-engine/src/semantics.rs`
- `crates/secure-engine/src/evidence_contract.rs`
- `crates/secure-engine/src/framework_sources.rs`
- `crates/secure-engine/src/graph.rs`
- `crates/secure-engine/src/scan.rs`
- `crates/secure-engine/src/lib.rs`

CLI, schema, and compatibility tests:

- `apps/secure-cli/src/main.rs`
- `apps/secure-cli/tests/cli_contract.rs`
- `crates/secure-engine/tests/precision_phase65.rs`
- `schemas/secure-json-v1.schema.json`

New regression coverage:

- `crates/secure-engine/tests/lead_quality_vscode_go.rs`
- `fixtures/lead-quality-vscode-go/README.md`
- `fixtures/lead-quality-vscode-go/package.json`
- `fixtures/lead-quality-vscode-go/binary-path.ts`
- `fixtures/lead-quality-vscode-go/lint-config.ts`
- `fixtures/lead-quality-vscode-go/local-debug.ts`
- `fixtures/lead-quality-vscode-go/survey-state.ts`
- `fixtures/lead-quality-vscode-go/positive-secrets.ts`
- `fixtures/lead-quality-vscode-go/network-listener.ts`

Documentation and decisions:

- `README.md`
- `docs/development.md`
- `docs/evidence-graph-and-rules.md`
- `docs/evidence-semantics.md`
- `docs/secure-json-v1.md`
- `docs/adr/0024-lead-quality-evidence-and-report-projection.md`
- `docs/bounded-human-tool-benchmark-protocol.md`
- `docs/vscode-go-lead-quality-milestone.md`

The new fixture suite contains the three observed benign patterns, a second clean call through the
same helper, local and remote positive SE1010 controls, the DAP-shaped listener, an explicit-loopback
control, and an unproven-factory control. The tests assert semantic roles, data class, locality,
call-site separation, listener prerequisites, workspace-trust treatment, compact graph integrity,
schema validity, rule catalog order, and deterministic fingerprints.

## VS Code Go measurements

Both measurements used a release build, the same machine and target checkout, `--no-cache`, and all
286 selected files. The baseline is the locally reproduced unmodified Engine, not only the campaign
note. Times are single-run engineering observations; they are not portable performance claims.

| Metric | Reproduced v0.1.10-rc2 | This milestone |
| --- | ---: | ---: |
| Files scanned | 286 | 286 |
| Facts | 13,302 | 13,302 |
| Internal graph nodes | 47,292 | 47,293 |
| Internal graph edges | 83,687 | 83,344 |
| Graph nodes serialized by default | 47,292 | 2 |
| Graph edges serialized by default | 83,687 | 1 |
| Findings | 3 SE1010 | 1 SE1011 |
| Internal scan duration | 1,873 ms | 1,673 ms |
| Parsing duration | 1,088 ms | 1,105 ms |
| Analysis duration | 711 ms | 484 ms |
| Wall time | 2.37 s | 1.98 s |
| Peak RSS | 352,904 KiB | 314,156 KiB |
| Pretty report size | 120,804,374 bytes | 10,976,974 bytes |
| Report fingerprint | `cae9b774d72af6fdd77c15f9c6e73eb233745ff32a1156633f33cecdb7b8b651` | `fbc11d7b295b2819ff8cfdde014e632a686b363b98d79648d374e0b5316f0969` |

The default report is 90.91% smaller. The complete graph is still built internally; the one-node
increase is the new listener evidence, while call-site precision removes 343 invalid edges. In
canonical compact JSON after projection, the graph falls from 73,784,608 to 2,031 bytes. Facts stay
at 7,352,791 bytes and now account for 98.36% of the compact report, identifying the next storage
target without hiding evidence.

All three rejected SE1010 IDs are absent. The remaining SE1011 lead is at
`src/goDebugFactory.ts:482` to `src/goDebugFactory.ts:496`. It records host omission but explicitly
abstains on runtime-selected interface, activation reachability, exposure duration, peer port
discovery, connection-race outcome, firewall/routing behavior, protocol impact, and exploitability.
No manual validation was performed, so it must not be called a vulnerability.

Two independent post-change no-cache scans produced the same report fingerprint, finding ID
`fd_19192f9e6f61ce9940835b31`, finding fingerprint, semantic fingerprint, facts, findings, and
finding-evidence graph. Their internal durations were 1,673 ms and 1,592 ms. The measured release
executable SHA-256 is
`ae93a4d156e53d6af90daf8a06541ea76e9c4cb4e41de11c41ce6bd621a7e88a`.

## Verification

- `cargo fmt --all -- --check`: pass with Rust 1.92.0.
- `git diff --check`: pass.
- `cargo check --workspace --all-targets --all-features`: pass.
- `cargo test --workspace --all-features`: pass, including unit, integration, schema, Evidence
  Contract, CLI, ordering, fingerprint, and reproducibility coverage.
- `cargo test -p secure-engine --test lead_quality_vscode_go`: 6 passed, 0 failed.
- Strict Clippy for the changed Engine library/new regression target and the changed CLI binary/test:
  pass with `-D warnings`.
- Strict whole-workspace Clippy is not green on Rust 1.92.0: the unchanged
  `crates/secure-engine/tests/ai_phase6.rs:274` triggers `clippy::search_is_some` for
  `.find(...).is_none()`. That unrelated file was not changed.
- The standalone mock consumer validates the actual 286-file report against
  `schemas/secure-json-v1.schema.json`: pass.
- `secure explain` resolves the compact report's SE1011 path without the global graph: pass.
- Two release `--no-cache` scans and a structural comparison of facts, findings, graph, and report
  fingerprint: pass.
- `cargo-audit` and `cargo-deny` are not installed in the active environment, so those gates were
  not run. This milestone changes no dependency manifest or lockfile.

The work started from the isolated clean worktree supplied for the task. Post-change source is
intentionally uncommitted, so the final worktree is dirty only with the listed deliverable changes.
The target checkout remained clean and read-only.

## Limitations and next milestones

The current call binding is bounded trace context, not a general points-to or SSA engine. Ambiguous
aliases, dynamic dispatch, callbacks, closures, and multi-path return selection can still require
abstention or lose a valid path. The listener model intentionally rejects dynamic hosts, Unix
sockets, unproven factories, mutated receivers, and ambiguous overloads. Manifest and platform
guards describe declared conditions but do not prove runtime enforcement.

The next highest-value milestones are:

1. Introduce stable per-scope symbol and call identities with bounded argument/return summaries and
   multi-trace selection, then test callback, closure, alias, and same-name cross-file controls.
2. Add guard- and activation-aware listener reachability, protocol-handshake evidence, and explicit
   lifetime modeling while retaining conservative abstention for runtime network state.
3. Project finding-relevant normalized facts or offer a portable facts sidecar. Facts now dominate
   report size, so any change should be measured and preserve explainability and schema migration.

The preregistered protocol in `docs/bounded-human-tool-benchmark-protocol.md` is a future benchmark
design, not a result. It requires blind timed reviewers, planted and historical positives, negative
repositories, hard benign patterns, manual validation, and separate recall, precision, review-time,
time-to-first-lead, coverage, reproducibility, abstention, and cost measurements. This milestone
makes no human-superiority, guaranteed-discovery, or human-replacement claim.

No report or source was published or uploaded. No external action, issue, pull request,
vulnerability submission, third-party contact, commit, or push occurred.
