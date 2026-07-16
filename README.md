# Secure Engine

Local-first security analysis for entire codebases.

Secure Engine is the local Rust analysis core of the Secure project family. Phase 2 provides bounded Git-aware inventory plus language-aware JavaScript, JSX, TypeScript, and TSX parsing. It exports deterministic normalized syntax evidence through a CLI and a small native desktop application. Semantic graphs and vulnerability rules remain roadmap work.

Start with [GOAL.md](./GOAL.md), then read the full [PLAN.md](./PLAN.md). Development and contract details are in [docs/development.md](./docs/development.md) and [docs/secure-json-v1.md](./docs/secure-json-v1.md).

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
cargo run -p secure-cli -- doctor --format secure-json-v1
cargo run -p secure-cli -- schema print secure-json-v1
cargo run -p secure-desktop -- .
```

Licensed under the MIT License. Contributions use the Developer Certificate of Origin; see [CONTRIBUTING.md](./CONTRIBUTING.md).
