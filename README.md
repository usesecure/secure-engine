# Secure Engine

Local-first security analysis for entire codebases.

[![CI](https://github.com/usesecure/secure-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/usesecure/secure-engine/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> [!IMPORTANT]
> Secure Engine is experimental pre-1.0 software. Findings require human validation, and a clean report is not proof that a codebase is secure.

Secure Engine is the local Rust analysis core of the Secure project family. Release 0.1.6 (Phase 6.10) generalizes fail-closed authorization summaries for authenticated-principal wrappers, request-bound boolean helpers, compound server-selected identity checks, and exceptional control flow. The implementation is derived from control flow and value connectivity, not application helper names, and is verified with independently authored vulnerable/control and adversarial fixtures. The tool-neutral taxonomy, evidence contract v2, secure-json-v1, and SARIF contracts remain unchanged. The CLI and native desktop product retain safe source inspection, exact suppressions, local history, deterministic baselines, disabled-by-default AI validation, and Fedora RPM packaging.

Start with [GOAL.md](./GOAL.md), then read the full [PLAN.md](./PLAN.md). Phase 6.10 details are in [docs/phase610-root-cause-analysis.md](./docs/phase610-root-cause-analysis.md), [docs/independent-fixture-methodology-phase610.md](./docs/independent-fixture-methodology-phase610.md), and [docs/adr/0013-phase-6-10-authorization-wrapper-generalization.md](./docs/adr/0013-phase-6-10-authorization-wrapper-generalization.md). The stable public projection remains documented in [docs/evidence-contract-v2.md](./docs/evidence-contract-v2.md). Fedora operations and verification are documented in [docs/fedora-packaging.md](./docs/fedora-packaging.md) and [docs/verification-fedora-phase610.md](./docs/verification-fedora-phase610.md).

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
