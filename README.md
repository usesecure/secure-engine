# Secure Engine

Local-first security analysis for entire codebases.

Secure Engine is the local Rust analysis core of the Secure project family. Release 0.1.1 (Phase 6.5) adds frozen, tool-neutral taxonomy metadata and calibrates deterministic TypeScript precision while preserving the Phase 6 optional, disabled-by-default AI boundary and the existing JavaScript/TypeScript, Rust, Python, and Go contracts. The CLI and native desktop product retain safe source inspection, exact suppressions, local history, deterministic baselines, JSON/SARIF export, and Fedora RPM packaging.

Start with [GOAL.md](./GOAL.md), then read the full [PLAN.md](./PLAN.md). Development and contract details are in [docs/development.md](./docs/development.md), [docs/parsing-normalized-facts.md](./docs/parsing-normalized-facts.md), [docs/evidence-graph-and-rules.md](./docs/evidence-graph-and-rules.md), [docs/secure-json-v1.md](./docs/secure-json-v1.md), [docs/taxonomy-and-precision.md](./docs/taxonomy-and-precision.md), and [docs/ai-validation.md](./docs/ai-validation.md). Fedora package operations and Phase 6.5 verification are documented in [docs/fedora-packaging.md](./docs/fedora-packaging.md) and [docs/verification-fedora-phase65.md](./docs/verification-fedora-phase65.md).

## Project family

```text
Secure
|- secure-skill    Agent workflow and review guidance
`- secure-engine   Rust analyzer, CLI, and native desktop UI
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

Licensed under the MIT License. Contributions use the Developer Certificate of Origin; see [CONTRIBUTING.md](./CONTRIBUTING.md).
