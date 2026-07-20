# Secure Engine - Implementation Goal

## Current status

Phases 0–6.12 are complete and integrated through `f627c2ab35d060cf402c5a539f062efd260111ba`, which is the exact source base for the Secure Engine 0.1.8 release candidate. Secure Engine 0.1.7 remains the published release. Phase 6.12 adds bounded arrow and `node:path` summaries, exact derived guard/resource identity, shell program-text classification, and exact object-literal property/destructuring identity. Taxonomy 1.0.0, Evidence Contract v2, secure-json-v1, SARIF, CLI/desktop parity, and disabled-by-default AI remain unchanged; the private cache is v14. RC1 remains a retired-corpus erratum outside the Engine's sound data-flow boundary. Computed dispatch/properties, reflection, ambiguous imports/calls, and unproven runtime filesystem state remain intentional limits. Version 0.1.8 has not received an independent holdout evaluation. No benchmark, ranking, superiority, production-readiness, or complete-coverage claim is supported.

Build Secure Engine as a local-first Rust security analyzer with one reusable core, a CLI, and a small native desktop interface. The first implementation must establish a reliable foundation and a stable integration contract with `usesecure/secure-skill`; it must not attempt broad vulnerability detection yet.

## Product relationship

- **Secure Engine** discovers, parses, classifies, and reports deterministic repository evidence.
- **Secure Skill** orchestrates the security-review workflow and uses an agent to validate, explain, prioritize, and remediate that evidence.
- Neither project may require the other to perform its basic job.
- The integration boundary is a versioned CLI and JSON schema, never an internal Rust API.

## Phase 0 objective

Create a Rust workspace containing:

```text
crates/secure-engine     Shared analysis library and typed report model
apps/secure-cli          `secure` command-line application
apps/secure-desktop      Small native egui/eframe application
schemas/                 Versioned integration schemas and examples
docs/                    Architecture decisions
```

Both interfaces must call the same library function and display the same deterministic inventory result for a selected repository.

## Secure Skill integration

Implement the first public contract:

```bash
secure scan <repository> --format secure-json-v1 --output <report.json>
secure doctor --format secure-json-v1
secure schema print secure-json-v1
```

The scan report must include:

- schema and engine versions;
- repository identity without absolute-path leakage;
- scan configuration and timestamps;
- detected languages, manifests, frameworks, and entry points;
- capability inventory and trust-boundary evidence;
- normalized findings, even when the list is empty;
- precise repository-relative spans;
- analysis limitations, skipped files, and bounded errors;
- deterministic fingerprints for later comparison.

Use stable stdout for machine output and stderr for human diagnostics. Define documented exit codes for success, policy findings, invalid input, unsupported schema, cancellation, and internal failure.

Secure Skill will later:

1. detect the `secure` binary or a configured `SECURE_ENGINE_BIN` path;
2. ask before running local commands when its host requires permission;
3. request `secure-json-v1` output in a temporary local file;
4. validate the schema before trusting the report;
5. use findings and capability evidence to prioritize review;
6. state clearly which conclusions came from the engine and which came from agent analysis;
7. fall back to its existing repository-scraping workflow when the engine is absent or incompatible.

Do not make Secure Engine install, import, or edit Secure Skill. Do not make Secure Skill parse terminal prose or depend on Rust crate internals.

**Do not install Secure Skill as part of this project.** Do not copy it into the workspace, modify its repository, write into the user's Codex skills directory, or add it as a build/runtime dependency. During Phase 0, implement and test only Secure Engine's side of the integration using local JSON fixtures and a mock consumer.

## Required first delivery

1. Inspect the Fedora and Rust environment.
2. Confirm current stable dependency choices before pinning them.
3. Record concise architecture decisions for workspace structure, async/concurrency, UI messaging, and schema versioning.
4. Scaffold the three packages and shared typed API.
5. Implement deterministic repository inventory with progress and cancellation.
6. Implement `secure-json-v1`, its JSON Schema, fixtures, and compatibility tests.
7. Make CLI and desktop consume the same result model.
8. Add formatting, strict Clippy, tests, dependency checks, and CI.
9. Add an integration fixture and mock consumer that demonstrate the future Secure Skill contract without installing or executing the skill.
10. Run and verify the complete workspace locally on Fedora.

## Non-goals for this delivery

- No claim of detecting every vulnerability.
- No cloud service or account system.
- No source-code upload; Phase 6 sends only the explicitly previewed, redacted structured finding payload when enabled and consented.
- No automatic fixes.
- No large rule library or shallow multi-language support.
- No direct dependency between the two repositories.
- No installation or modification of Secure Skill.

## Definition of done

- `cargo test --workspace` and strict Clippy pass.
- CLI and desktop produce equivalent inventory data.
- Repeated scans of unchanged fixtures produce stable JSON apart from documented volatile fields.
- The schema rejects malformed and incompatible reports.
- Absolute local paths and secrets do not appear in exported reports.
- Cancellation leaves no corrupt cache or partial report presented as complete.
- A fixture and mock consumer demonstrate how Secure Skill could validate and consume the engine report, without installing the skill.
- Documentation accurately separates implemented behavior from the future roadmap.

Read [PLAN.md](./PLAN.md) before editing. Keep the first pull request focused on this foundation; do not start Tree-sitter language rules until these contracts are tested.
