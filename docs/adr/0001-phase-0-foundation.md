# ADR 0001: Phase 0 foundation

- Status: accepted
- Date: 2026-07-16

## Decisions

1. **Workspace:** one reusable `secure-engine` library plus `secure-cli` and `secure-desktop`. The process/JSON boundary is public; Rust internals are not an integration API.
2. **Concurrency:** Phase 0 uses one background scan thread in the desktop and a synchronous, bounded discovery loop in the core. `ignore` performs Git-aware traversal. Rayon/Tokio are deferred until measurements justify parallel parsing or asynchronous I/O.
3. **UI messaging:** typed progress events and a shared atomic cancellation token cross the worker/UI boundary through a bounded crossbeam channel. Completed reports are published atomically; cancellation never creates a completed report.
4. **Schema:** `secure-json-v1` is a committed JSON Schema and a versioned top-level document contract. Additive fields remain compatible inside v1; consumers must reject unknown schema identifiers. The schema file and fixtures are the integration source of truth.
5. **Dependencies:** exact direct versions are pinned in the workspace and the lock file pins the full graph. On 2026-07-16, crates.io reported eframe 0.35.0, Tree-sitter 0.26.11, Petgraph 0.8.3, Clap 4.6.2, Miette 7.6.0, Serde 1.0.228, and serde_json 1.0.150 as current stable releases. Phase 0 uses eframe, Clap, Serde, `ignore`, BLAKE3, and crossbeam-channel. Tree-sitter, Petgraph, Miette, caching, and vulnerability rules are explicitly deferred. The Fedora build selects eframe's X11/XWayland backend. Eframe's unconditional clipboard chain still compiles `wayland-scanner`, which pins `quick-xml` 0.39.4. RUSTSEC-2026-0194 and RUSTSEC-2026-0195 are narrowly excepted because this proc-macro processes dependency-owned protocol XML at build time and never repository input; the exceptions must be removed when the eframe chain accepts `quick-xml` 0.41 or newer.
6. **License/contributions:** MIT License with Developer Certificate of Origin sign-off. This keeps the initial contribution model simple while preserving reuse by the separate Secure Skill project.

## Consequences

The CLI and desktop cannot drift in analysis behavior because both call the same core function. The first implementation inventories and classifies deterministic repository evidence only; it makes no vulnerability-detection claim.
