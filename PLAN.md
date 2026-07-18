# Secure Engine - Project Plan

## Identity

- Organization: **Secure**
- Product: **Secure Engine**
- Repository: `usesecure/secure-engine`
- Implementation language: Rust
- Interfaces: CLI and a small native desktop application
- Tagline: **Local-first security analysis for entire codebases.**

## Mission

Build an evidence-first security analyzer that can understand a repository as a system rather than as a collection of suspicious strings. Secure Engine should inventory the project, classify capabilities, construct a graph of entry points and sensitive operations, execute deterministic rules, and produce findings that can be inspected without trusting an AI model.

An optional AI layer may validate, explain, and prioritize structured evidence. It must not be the source of truth, and source code must never leave the machine without explicit user approval.

The goal is not to claim that Secure Engine detects every vulnerability. The goal is to outperform broad, noisy review workflows through measurable coverage, useful evidence, low false-positive rates, and transparent limitations.

## Current implementation status

Phases 0–6.9 are integrated. Phase 6.5 adds the frozen `secure-bench-taxonomy-v1` 1.0.0 contract to every deterministic rule family. Phase 6.6 adds explicit bounded evidence semantics. Phase 6.7 implements public evidence contract v2. Phase 6.8 uses only retired public evidence to correct framework source extraction, module-scoped helper resolution, positional propagation, exact barriers, process shell defaults, and authorization distinctions. Phase 6.9 uses only the permitted retired Phase 15 aggregate handoff to correct source identity, exact spans, property/position connectivity, value-associated barriers, and overbroad sink inputs, then proves those changes with independent regressions. Phase 6 remains a provider-neutral, disabled-by-default validation boundary with exact preview and consent. Java/Kotlin, C#, hosted services, automatic fixes, telemetry, complete runtime argument semantics, and additional package formats remain future work.

## Product boundaries

Secure Engine owns:

- repository discovery and indexing;
- language-aware parsing;
- manifest, dependency, route, and configuration extraction;
- capability and data-flow graph construction;
- deterministic rule execution;
- source-to-sink evidence paths;
- finding normalization, suppression, and export;
- scan cache and incremental analysis;
- CLI and native desktop UI;
- optional AI-provider adapters over redacted structured evidence.

Secure Engine does not own:

- the Agent Skill instructions in `usesecure/secure-skill`;
- cloud storage of private repositories;
- automatic source upload;
- silent code modification;
- unsupported claims of complete vulnerability coverage;
- a hosted SaaS platform during the initial product phases.

## Core principles

1. **Local first:** scanning works offline and keeps source code on the user's machine.
2. **Deterministic core:** the same revision, rules, and configuration should produce stable findings.
3. **Evidence before severity:** no finding without precise source evidence and an explained broken invariant.
4. **One engine:** CLI and desktop UI call the same library API and consume the same result types.
5. **Incremental by design:** unchanged files should not require a complete rescan.
6. **Safe defaults:** read-only analysis, secret redaction, bounded resource use, and explicit network consent.
7. **Measurable quality:** vulnerable fixtures and safe controls must be evaluated separately.
8. **Composable:** integrate proven parsers and scanners where they are stronger than custom replacements.

## Initial Rust workspace

Keep the first workspace small. Split crates only when ownership or compile-time boundaries justify it.

```text
secure-engine/
|- Cargo.toml
|- crates/
|  `- secure-engine/        Core library
|- apps/
|  |- secure-cli/           Command-line interface
|  `- secure-desktop/       Native egui/eframe application
|- rules/                   Versioned built-in rule definitions
|- fixtures/                Vulnerable and safe evaluation repositories
|- docs/                    Architecture and result-schema documentation
`- PLAN.md
```

The core library should begin with internal modules rather than many tiny crates:

```text
model        Stable IDs, spans, capabilities, evidence, findings, reports
workspace    File discovery, ignore rules, manifests, repository metadata
parser       Tree-sitter adapters and normalized syntax facts
extract      Routes, entry points, trust boundaries, sources, guards, sinks
graph        Capability and data-flow graph
rules        Rule registry, matching, confidence, suppression
scan         Pipeline orchestration, cancellation, progress, caching
report       JSON, SARIF, terminal, and UI projections
ai           Optional provider-neutral validation boundary
```

## Technology direction

- **Parsing:** Tree-sitter Rust bindings with language adapters.
- **Graph model:** Petgraph behind Secure-owned domain types.
- **CLI:** Clap with machine-readable output and stable exit codes.
- **Desktop UI:** egui through eframe for a native Rust application without Electron or a web frontend.
- **Serialization:** Serde with a versioned JSON schema.
- **Diagnostics:** Miette-style source spans and actionable errors.
- **Concurrency:** bounded parallel file processing; choose Rayon or Tokio only where each model is justified.
- **Cache:** local SQLite or a compact file cache after profiling the first implementation.
- **Logging:** structured tracing with sensitive values redacted.
- **Exports:** JSON first, then SARIF for GitHub and CI integrations.

Do not lock dependency versions in this plan. Select and pin compatible current versions when Phase 0 is implemented.

## Analysis pipeline

```text
Select repository
    -> discover files and manifests
    -> detect languages and frameworks
    -> parse supported source files
    -> extract normalized security facts
    -> build capability and data-flow graph
    -> execute deterministic rules
    -> validate evidence paths
    -> normalize and deduplicate findings
    -> export report to CLI, UI, JSON, or SARIF
    -> optionally request AI validation with explicit consent
```

## Finding contract

Every finding must include:

- stable rule and finding identifiers;
- title, category, severity, and confidence;
- repository-relative files and exact source spans;
- source, transformations, guards, and sink when a path exists;
- the violated security invariant;
- exploit prerequisites and realistic impact;
- remediation guidance;
- verification state and analysis limitations;
- fingerprints for deduplication and baseline comparison.

Severity and confidence are separate. An unproven high-impact possibility must not be presented as a confirmed critical vulnerability.

## Native desktop interface

The UI is a focused inspection tool, not a marketing dashboard.

### Primary layout

- Top toolbar: open repository, start/cancel scan, scan mode, export, settings.
- Left navigation: Overview, Findings, Architecture, Dependencies, Scan Log.
- Main Findings view: sortable and filterable table with severity, confidence, rule, file, and status.
- Detail pane: invariant, evidence path, source preview, remediation, suppression, and verification status.
- Architecture view: capability graph with entry points, guards, sensitive operations, and trust boundaries.
- Bottom status area: progress, files parsed, rules executed, cache hits, duration, and bounded errors.

### UI constraints

- Remain responsive while scanning; all work runs outside the render thread.
- Stream typed progress events from the engine.
- Support keyboard navigation and usable text scaling.
- Store only local preferences and recent project paths.
- Never send code to an AI provider from a single accidental click.
- Require a review screen showing exactly what structured evidence will leave the machine.
- Avoid decorative cards, neon cyber styling, and fake threat visualizations.

## CLI surface

Initial commands:

```bash
secure scan <path>
secure scan <path> --format json
secure scan <path> --format sarif
secure rules list
secure explain <finding-id>
secure baseline create <report>
secure baseline compare <report>
secure doctor
```

The CLI must support:

- stable nonzero exit codes for policy failures and execution failures;
- quiet and verbose modes;
- cancellation;
- configurable resource limits;
- include and exclude patterns;
- baseline suppression with auditable reasons;
- no-color and CI-friendly output.

## Language roadmap

Start with depth, not a shallow promise of universal support.

1. TypeScript and JavaScript: Next.js, Node.js, Express-style APIs, server actions, common ORM boundaries.
2. Rust: Axum/Actix-style handlers, unsafe boundaries, command execution, deserialization, filesystem and network sinks.
3. Python: FastAPI, Django, Flask, subprocess, templates, ORM boundaries.
4. Go: net/http and common routers, SQL, command execution, filesystem, SSRF paths.
5. Java/Kotlin and C#: web entry points, authorization, serialization, ORM, and process boundaries.

Each language is considered supported only after it has vulnerable fixtures, safe controls, parser tests, rule tests, and documented limitations.

## Rule families

- authentication trust and session creation;
- authorization dominance and missing object-level checks;
- tenant and owner boundaries;
- mass assignment and policy-field mutation;
- state-transition invariants;
- secrets and unsafe configuration;
- command execution and code injection;
- SQL, template, path, and query injection;
- SSRF and network egress;
- CORS, CSRF, and browser trust boundaries;
- uploads, archives, storage, and signed URLs;
- webhooks, payments, and replay protection;
- AI, PDF, document, and media processing;
- logging, error leakage, and sensitive telemetry;
- dependency and supply-chain evidence imported from trusted tools.

## AI boundary

AI integration is optional and disabled by default.

Allowed initial uses:

- validate whether a deterministic candidate has enough source evidence;
- explain a source-to-sink path in plain language;
- propose a remediation for explicit user review;
- cluster duplicate candidates that share the same invariant.

Required controls:

- provider-neutral adapter trait;
- explicit opt-in per project;
- visible payload preview;
- redaction of secrets and unrelated source;
- strict token and cost budgets;
- no autonomous patch application in the first release;
- reports record model, provider, prompt version, and validation status.

## Secure Skill integration contract

Secure Engine and Secure Skill integrate as separate products through a stable process boundary:

```text
Secure Skill
    -> discover `secure` or `SECURE_ENGINE_BIN`
    -> invoke local CLI with an explicit schema version
    -> validate the JSON report
    -> use evidence to drive review and verification
    -> fall back to skill-only discovery when unavailable

Secure Engine
    -> scan locally and deterministically
    -> emit repository-relative structured evidence
    -> report limitations and provenance
    -> never invoke an AI agent or modify source implicitly
```

Initial machine interface:

```bash
secure scan <path> --format secure-json-v1 --output <report.json>
secure doctor --format secure-json-v1
secure schema print secure-json-v1
```

Contract requirements:

- stdout remains machine-readable when a structured format is selected;
- diagnostics and progress use stderr or a separate typed event channel;
- reports declare schema version, engine version, completion state, and scan provenance;
- all exported source locations are repository-relative;
- findings distinguish deterministic engine evidence from later agent validation;
- unknown fields are tolerated within a schema major version;
- incompatible major versions fail clearly instead of being guessed;
- exit codes distinguish findings, invalid input, cancellation, and engine failure;
- reports contain limitations, skipped inputs, and parser errors;
- the skill validates the report before using it and preserves its standalone fallback.

The schema and representative fixtures live in Secure Engine. Secure Skill may keep generated test fixtures, but Secure Engine is the source of truth for the report contract. Compatibility tests should run against a fixture shared by release tag or copied with its schema version recorded.

Secure Engine development must not install, vendor, execute, or modify Secure Skill. Until integration work is performed explicitly in the skill repository, Engine tests use schema fixtures and a mock consumer only.

## Milestones

### Phase 0 - Foundation

- Decide license and contribution model.
- Create the Cargo workspace and three initial packages.
- Add formatting, linting, tests, dependency audit, and CI.
- Define architecture decisions and the versioned result schema.
- Build a minimal CLI and desktop window that both call one engine function.

Exit condition: `cargo test --workspace`, strict Clippy, CLI help, and the desktop shell run on Fedora.

### Phase 1 - Repository inventory

- Implement Git-aware traversal, ignore rules, language detection, manifests, and file classification.
- Add progress, cancellation, resource limits, and stable repository-relative paths.
- Produce a deterministic inventory report from CLI and UI.

Exit condition: large repositories can be inventoried without freezing the UI or reading excluded content.

### Phase 2 - Parsing and normalized facts

- Add TypeScript/JavaScript Tree-sitter adapters.
- Extract functions, imports, calls, routes, environment access, guards, and sensitive sinks.
- Cache parse results by content hash and parser version.

Exit condition: parser fixtures produce stable normalized facts with precise spans.

### Phase 3 - Graph and rules

- Construct the capability and data-flow graph.
- Implement the first evidence-backed rules.
- Add deduplication, confidence, suppression, and JSON output.

Exit condition: findings include reproducible evidence paths and safe fixtures remain clean.

### Phase 4 - Useful CLI and desktop MVP

- Complete scan controls, findings table, detail pane, source preview, filters, exports, and scan history.
- Add SARIF output and baseline comparison.
- Package the application for Fedora first.

Exit condition: a user can scan, inspect, suppress, export, and reopen a project without a terminal.

### Phase 5 - Multi-language expansion

- [Complete] Add Rust, Python, and Go adapters in that order.
- [Complete] Require fixtures and negative controls for every rule family added.
- [Complete] Profile memory, CPU, cache size, and incremental performance.

Exit condition: support claims match measured language and framework coverage.

### Phase 6 - Optional AI validation

- [Complete] Implement the provider-neutral boundary and consent UI.
- [Complete] Send only selected, redacted structured evidence.
- [Complete] Evaluate contracts with committed mock/recorded fixtures without making provider-quality claims.

Exit condition: AI can improve triage without being required for scanning or silently exporting source.

### Phase 6.5 - Precision and neutral taxonomy calibration

- [Complete] Attach exact taxonomy version, category, invariant, primary CWE, and mapping provenance to all `SE1001`–`SE1007` rules and findings.
- [Complete] Project the same metadata through JSON, SARIF, CLI, desktop, baselines, history, and optional AI previews without changing AI execution policy.
- [Complete] Improve structural dominance and uniquely resolved helper propagation for filesystem, authorization, outbound-request, redirect, and process execution semantics.
- [Complete] Preserve prior finding fingerprints and all supported-language behavior except where a newly reproduced evidence path is intentionally detected.

Exit condition: safe dominant controls suppress only their matching rule family, unsafe near misses remain findings, unresolved behavior is explicit, and release 0.1.1 passes all compatibility and Fedora gates.

### Phase 6.6 - Evidence semantics and precision hardening

- [Complete] Add explicit source, transformation, guard, sanitizer, authorization, and sink semantics without changing legacy finding identities.
- [Complete] Require realizable paths, matching values, terminating control flow, policy-specific guards, and operation authorization.
- [Complete] Resolve deterministic helpers, imports, and aliases within conservative resource bounds and expose uncertainty.
- [Complete] Exercise 102 independent scenarios, including six vulnerable and six safe cases per rule family plus multilingual and mutation/metamorphic coverage.

Exit condition: release 0.1.2 preserves Phase 6 compatibility, passes every workspace and Fedora gate, and produces reproducible RPMs.

### Phase 6.7 - Contract v2 conformance and generalized evidence remediation

- [Complete] Implement canonical contract-v2 sources, sinks, paths, span containment, compression, barriers, uncertainty, duplicates, and semantic fingerprints additively.
- [Complete] Correct source specificity, call-site identity, argument ordering, helper/import propagation, operation authorization, path confinement, exact outbound policy, constant fallback, and per-sink deduplication.
- [Complete] Freeze the 56 disclosed retired diagnostics as development-only regression inputs and pass 28 exact vulnerable cases plus 28 clean controls.
- [Complete] Exercise 140 independent scenarios (10 vulnerable and 10 safe per family), metamorphic changes, guard removal, adversarial near misses, recursion/cycles, malformed input, bounds, cancellation, and privacy.

Exit condition: release 0.1.3 passes the public synthetic contract vectors, all compatibility and Fedora gates, and two byte-identical RPM builds without Secure Bench execution or unseen holdout access.

### Phase 6.8 - Retired-evidence precision and evidence remediation

- [Complete] Analyze only the public retired Phase 7/8 reports and adjudication, preserving the distinction between the runner exit-code defect and analyzer evidence limitations.
- [Complete] Recognize destructured and aliased framework inputs, preserve multiarity call positions, and resolve JavaScript/TypeScript helpers only through same-file or explicit relative-import ownership.
- [Complete] Prove exact fixed allowlists and constant fallbacks structurally, retain unsafe suffix/blocklist/authentication-only near misses, and model fixed executable argument arrays as no-shell unless shell use is explicit.
- [Complete] Exercise an independent 56-scenario matrix across seven families, four languages, four framework forms, four topologies, paired controls, and metamorphic/adversarial boundaries.
- [Complete] Preserve public schemas, taxonomy, disabled-AI policy, unaffected fingerprints, CLI/desktop contracts, privacy, and deterministic cold/warm behavior while advancing the private cache envelope.

Exit condition: release 0.1.4 passes all compatibility, security, schema, privacy, deterministic, and Fedora gates and produces two byte-identical RPM builds without executing Secure Bench or accessing undisclosed holdout material.

### Phase 6.9 - Retired Phase 15 evidence and false-positive remediation

- [Complete] Pin only the seven permitted retired Phase 15 handoff hashes and retain aggregate reproduction accounting without importing benchmark source, case identifiers, evaluator behavior, or expected spans.
- [Complete] Preserve exact source identity and spans across scoped aliases, destructuring, wrappers, supported helpers, and explicit relative imports while preventing sibling fields, unrelated parameters, reassigned aliases, and ambiguous resolution from inheriting identity.
- [Complete] Preserve argument positions, destructured property correspondence, return flow, and stable source tie-breaking; select only semantically sensitive sink arguments.
- [Complete] Require structurally effective guards and sanitizers to dominate the sink and protect the same propagated value, while keeping role authorization distinct from ownership and rejecting weak, late, or wrong-value barriers.
- [Complete] Exercise independent cause pairs across JavaScript, JSX, TypeScript, TSX, Node.js, Express, Next.js App Router, Server Actions, direct, helper-mediated, inter-file aliased, and control-flow-sensitive paths, plus adversarial, mutation, and metamorphic variants.
- [Complete] Preserve taxonomy 1.0.0, evidence contract v2, secure-json-v1, SARIF, baselines, history, suppressions, CLI/desktop parity, privacy, bounds, cancellation, symlink protections, and disabled-by-default AI while advancing only the private parse-cache envelope.

Exit condition: release 0.1.5 passes every compatibility, quality, security, schema, privacy, determinism, performance, and Fedora packaging gate and produces two byte-identical RPMs without executing Secure Bench, changing the benchmark adapter, pushing, or accessing undisclosed material.

### Phase 7 - Distribution

- Produce RPM, AppImage, and release archives.
- Add signed checksums, SBOM, reproducible release notes, and installation documentation.
- Integrate Secure Skill through the stable JSON/CLI contract rather than internal Rust APIs.

Exit condition: clean installation, upgrade, rollback, and removal are tested on supported Fedora releases.

## Evaluation strategy

Maintain separate measurements for:

- vulnerable-case detection;
- safe-case false positives;
- evidence-path correctness;
- severity and confidence calibration;
- duplicate rate;
- scan duration and peak memory;
- incremental scan speed;
- parser and rule coverage;
- AI-assisted improvement or regression.

The benchmark must not leak expected findings into prompts or analyzer configuration. Publish fixtures, scoring logic, raw reports, and limitations.

## Initial success criteria

- CLI and desktop UI produce the same report for the same scan configuration.
- Core scanning works offline with AI disabled.
- No finding is emitted without file evidence and a violated invariant.
- Safe controls are included from the first rule release.
- A scan can be cancelled without corrupting cache or state.
- The UI remains interactive during repository indexing and analysis.
- JSON reports are schema-versioned and deterministic apart from documented timing fields.
- Source transmission requires explicit opt-in and payload confirmation.
- CI runs formatting, Clippy, tests, dependency policy, and fixture evaluations.
- Performance and supported-language claims are backed by published measurements.

## First task for the new Codex project

Read this plan fully before editing. Then:

1. inspect the local Rust and Fedora development environment;
2. validate the proposed eframe, Tree-sitter, Petgraph, CLI, diagnostics, and serialization choices against current stable releases;
3. produce a short architecture decision record for Phase 0;
4. scaffold the smallest workspace with `secure-engine`, `secure-cli`, and `secure-desktop`;
5. make the CLI and desktop shell call the same typed engine API;
6. add CI, formatting, strict Clippy, tests, and concise development instructions;
7. run everything locally and leave the repository in a clean, committable state.

Do not begin language parsing or vulnerability rules until the Phase 0 contracts and tests are complete.
