# Secure Engine

Local-first security analysis for entire codebases.

[![CI](https://github.com/usesecure/secure-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/usesecure/secure-engine/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> [!IMPORTANT]
> Secure Engine is experimental pre-1.0 software. Findings require human validation, and a clean report is not proof that a codebase is secure.

Secure Engine is the local Rust analysis core of the Secure project family. Release 0.1.4 (Phase 6.8) applies generalized precision and evidence-path corrections derived only from retired public evidence. It improves framework input extraction, module-scoped helpers, positional flow, exact structural barriers, process shell defaults, and authorization distinctions while preserving the tool-neutral taxonomy and evidence contract v2. The CLI and native desktop product retain safe source inspection, exact suppressions, local history, deterministic baselines, JSON/SARIF export, disabled-by-default AI validation, and Fedora RPM packaging.

Start with [GOAL.md](./GOAL.md), then read the full [PLAN.md](./PLAN.md). Phase 6.8 details are in [docs/phase68-root-cause-analysis.md](./docs/phase68-root-cause-analysis.md), [docs/independent-fixture-methodology-phase68.md](./docs/independent-fixture-methodology-phase68.md), and [docs/adr/0011-phase-6-8-retired-evidence-remediation.md](./docs/adr/0011-phase-6-8-retired-evidence-remediation.md). The stable public projection remains documented in [docs/evidence-contract-v2.md](./docs/evidence-contract-v2.md). Fedora operations and verification are documented in [docs/fedora-packaging.md](./docs/fedora-packaging.md) and [docs/verification-fedora-phase68.md](./docs/verification-fedora-phase68.md).

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
