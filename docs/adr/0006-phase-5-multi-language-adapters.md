# ADR 0006: Isolated multi-language adapters over one evidence graph

## Status

Accepted for Phase 5.

## Decision

Secure Engine pins one Tree-sitter grammar per supported language and keeps parser-specific syntax behind internal adapters. Rust 0.24.2, Python 0.25.0, and Go 0.25.0 join the existing JavaScript/TypeScript grammars. Each adapter emits the existing normalized fact and internal program-record shapes; no Tree-sitter node or language-specific AST type enters `secure-json-v1`.

The cache identity includes language/parser mode, grammar, Tree-sitter runtime, adapter, normalized-fact extractor, graph extractor, content, path, and scan configuration. Existing JavaScript/TypeScript inputs retain their Phase 2 identity values and fingerprints.

The shared graph remains responsible for local data flow, uniquely resolved interprocedural calls, guards, sanitizers, rule evaluation, deduplication, suppressions, and reporting. Language adapters only classify syntax evidence. This preserves the seven rule identifiers and prevents a sensitive call or Rust `unsafe` block from becoming a finding without a required evidence path.

## Consequences

Mixed repositories can parse all supported languages in one scan without cache collisions or parser-state leakage. CLI, desktop, history, baseline, JSON, and SARIF projections need no language-specific branch. Dynamic Rust dispatch/macros, Python runtime mutation/decorators, and Go interfaces/callbacks/reflection remain explicit bounded limitations.
