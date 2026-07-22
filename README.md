# Secure Engine

Local-first static security analysis for JavaScript and TypeScript codebases.

[![CI](https://github.com/usesecure/secure-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/usesecure/secure-engine/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/usesecure/secure-engine)](https://github.com/usesecure/secure-engine/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Secure Engine follows untrusted values across files and helpers, then reports reproducible source-to-sink evidence through a CLI, native desktop UI, `secure-json-v1`, and SARIF 2.1.0. Analysis runs locally; AI validation is optional and disabled by default.

> [!IMPORTANT]
> Secure Engine is experimental pre-1.0 software. Every finding requires human validation, and a clean report is not proof that a codebase is secure.

## What it detects

Version 0.1.9 ships seven deterministic rule families:

- `SE1001`: untrusted input reaching command execution;
- `SE1002`: untrusted input reaching dynamically constructed or raw SQL;
- `SE1003`: untrusted paths reaching filesystem operations;
- `SE1004`: untrusted URLs reaching outbound requests;
- `SE1005`: untrusted URLs reaching redirects;
- `SE1006`: untrusted input reaching dynamic code execution;
- `SE1007`: exposed handlers reaching sensitive operations without a dominating authorization guard.

The analyzer supports bounded inter-file propagation, value-preserving helpers, static-property identity, shell program-text classification, exact path and URL policy projection, and principal/resource-aware authorization evidence. Ambiguous flows fail conservatively instead of inventing proof.

## Install v0.1.9

The current release provides a Fedora 44 x86_64 RPM. Download the RPM and `SHA256SUMS` from [GitHub Releases](https://github.com/usesecure/secure-engine/releases/tag/v0.1.9), then verify before installation:

```bash
sha256sum -c SHA256SUMS
sudo dnf install ./secure-engine-0.1.9-1.fc44.x86_64.rpm
```

The release was produced twice from independent clean targets; the RPM and staged/extracted CLI and desktop binaries were byte-identical.

Version 0.1.9 preserves the complete 0.1.8 analysis semantics while indexing repeated graph lookups. On the documented OpenStatus large-repository benchmark, internal scan time fell from 115.061 seconds to a median 11.403 seconds across three optimized runs, with identical facts, graph, findings, evidence, ordering, and report fingerprint. Results depend on repository and hardware; this is a bounded performance measurement, not a security-coverage claim.

## Quick start

Scan a repository with the installed CLI:

```bash
secure scan .
secure scan . --format secure-json-v1 --output report.json
secure scan . --format sarif --output report.sarif
secure scan . --include 'src/**' --exclude 'src/generated/**' --max-files 50000
secure rules list
secure explain fd_FINDING_ID --report report.json
```

Launch the native desktop UI:

```bash
secure-desktop .
```

Run from source instead:

```bash
cargo run -p secure-cli -- scan . --format secure-json-v1 --output report.json
cargo run -p secure-desktop -- .
```

Additional workflows include baselines, history, suppressions, cache control, schema export, diagnostics, cancellation, and bounded scans. Run `secure --help` or `secure <command> --help` for the complete interface.

## Independent evaluation

Secure Engine 0.1.8 was evaluated once against a newly frozen Secure Bench v4 holdout containing 28 vulnerable cases and 28 paired controls. The campaign completed all attempts without retries or operational failures. A post-open certification corrected a location-matching defect in the benchmark scorer by recomputing metrics from the immutable raw evidence without replaying scanners.

| Scanner / lane | TP | FP | TN | FN | Precision | Recall | F1 | Balanced accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Secure Engine 0.1.8 / native | 15 | 6 | 22 | 13 | 71.43% | 53.57% | 61.22% | 66.07% |
| OpenGrep 1.22.0 / capability-normalized | 4 | 4 | 24 | 24 | 50.00% | 14.29% | 22.22% | 50.00% |
| Semgrep CE 1.170.0 / capability-normalized | 4 | 4 | 24 | 24 | 50.00% | 14.29% | 22.22% | 50.00% |

These lanes use different capabilities and are not a global ranking. The figures describe one bounded holdout and do not establish superiority, production readiness, or complete coverage. Full frozen evidence and the scoring correction are scheduled for the next Secure Bench release.

## Known limits

Secure Engine deliberately remains conservative around:

- computed dispatch and computed properties;
- reflection and ambiguous calls/imports;
- unresolved callbacks and runtime-only framework behavior;
- mutation whose order or identity cannot be proven;
- application-specific protected operations without an explicit domain contract;
- unproven runtime filesystem state.

These limits can produce false negatives. Parser recovery and framework conventions can also affect results, so validate findings against the application’s actual deployment and trust boundaries.

## Structured evidence and privacy

The stable public projection includes taxonomy 1.0.0, Evidence Contract v2, `secure-json-v1`, SARIF 2.1.0, deterministic fingerprints, and private parse cache v16. Older cache envelopes produce safe misses.

AI validation never originates, deletes, or rewrites a finding. It requires project configuration, an exact redacted payload preview, and per-operation consent. Provider credentials are read only from the configured environment variable and are never serialized. See [AI validation](./docs/ai-validation.md) and [Evidence Contract v2](./docs/evidence-contract-v2.md).

## Project family

```text
Secure
|- secure-skill    Agent workflow and review guidance
|- secure-engine   Rust analyzer, CLI, and native desktop UI
`- secure-bench    Independent, evidence-aware benchmark harness
```

The components remain independently useful and communicate through versioned contracts. Secure Engine does not require an AI model, and Secure Skill retains a skill-only fallback when the binary is unavailable.

## Development

Architecture and release history are documented in [PLAN.md](./PLAN.md), the [ADR index](./docs/adr/), and the versioned Phase 6.11–6.13 documents under [`docs/`](./docs/). Fedora packaging and reproducible-build operations are documented in [docs/fedora-packaging.md](./docs/fedora-packaging.md).

Licensed under the MIT License. Contributions use the Developer Certificate of Origin; see [CONTRIBUTING.md](./CONTRIBUTING.md). Report vulnerabilities privately through [SECURITY.md](./SECURITY.md).
