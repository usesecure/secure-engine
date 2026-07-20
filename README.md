# Secure Engine

Local-first security analysis for entire codebases.

[![CI](https://github.com/usesecure/secure-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/usesecure/secure-engine/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> [!IMPORTANT]
> Secure Engine is experimental pre-1.0 software. Findings require human validation, and a clean report is not proof that a codebase is secure.

Secure Engine is the local Rust analysis core of the Secure project family. Public version 0.1.8 freezes the already integrated Phase 6.12 development tranches: bounded value-preserving arrow and `node:path` summaries, exact guard/resource identity, shell program-text classification, and exact object-literal property/destructuring identity. The engine retains the Phase 6.11 generalizations and the tool-neutral taxonomy 1.0.0, Evidence Contract v2, secure-json-v1, SARIF 2.1.0, rule IDs, CLI/desktop parity, baselines/history/suppressions, and disabled-by-default AI; the private parse cache remains v14.

Version 0.1.8 has not received an independent holdout evaluation and makes no benchmark, superiority, production-readiness, or complete-coverage claim. RC1 remains a retired-corpus erratum outside the Engine's sound data-flow boundary. Computed dispatch and properties, reflection, ambiguous calls/imports, unresolved callbacks, and unproven runtime filesystem state remain conservative limits.

Start with [GOAL.md](./GOAL.md), then read the full [PLAN.md](./PLAN.md). The 0.1.8 candidate is summarized in [docs/release-notes-v0.1.8-rc1.md](./docs/release-notes-v0.1.8-rc1.md), and Phase 6.12 tranche 4 is documented in [docs/phase612-tranche4-object-literal-destructuring.md](./docs/phase612-tranche4-object-literal-destructuring.md), with the earlier tranches linked from its compatibility section. The stable public projection remains documented in [docs/evidence-contract-v2.md](./docs/evidence-contract-v2.md). Fedora operations are documented in [docs/fedora-packaging.md](./docs/fedora-packaging.md); historical release verification remains frozen in its versioned documents.

## Project family

```text
Secure
|- secure-skill    Agent workflow and review guidance
|- secure-engine   Rust analyzer, CLI, and native desktop UI
`- secure-bench    Independent, evidence-aware benchmark harness
```

The skill and engine are complementary but independent. Secure Engine must remain useful without an AI model, and Secure Skill must remain installable without the desktop application.

They integrate through a versioned CLI and JSON report contract. Secure Skill may invoke an installed Secure Engine and reason over its structured evidence, but it must keep a functional skill-only fallback when the binary is unavailable.

## Commands

```bash
cargo run -p secure-cli -- scan . --format secure-json-v1 --output report.json
cargo run -p secure-cli -- scan . --include 'src/**' --exclude 'src/generated/**' --max-files 50000
cargo run -p secure-cli -- scan . --cache-dir /tmp/secure-engine-cache --clear-cache
cargo run -p secure-cli -- scan . --format sarif --output report.sarif
cargo run -p secure-cli -- rules list
cargo run -p secure-cli -- explain fd_FINDING_ID --report report.json
cargo run -p secure-cli -- baseline create report.json --output baseline.json
cargo run -p secure-cli -- baseline compare baseline.json report.json
cargo run -p secure-cli -- history list
cargo run -p secure-cli -- ai providers
cargo run -p secure-cli -- ai preview fd_FINDING_ID --report report.json --provider recorded --config secure-ai.json
cargo run -p secure-cli -- ai validate fd_FINDING_ID --report report.json --provider recorded --config secure-ai.json --consent CONSENT_FINGERPRINT
cargo run -p secure-cli -- ai cache clear
cargo run -p secure-cli -- doctor --format secure-json-v1
cargo run -p secure-cli -- schema print secure-json-v1
cargo run -p secure-desktop -- .
```

AI validation never originates, deletes, or rewrites a finding. It requires an enabled project configuration, an exact redacted payload preview, and per-operation consent. Provider credentials are read only from the named environment variable and are never serialized. See [docs/ai-validation.md](./docs/ai-validation.md).

Licensed under the MIT License. Contributions use the Developer Certificate of Origin; see [CONTRIBUTING.md](./CONTRIBUTING.md). Report security concerns through [SECURITY.md](./SECURITY.md).
