# Multi-language normalized facts

Phase 5 parses JavaScript/TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`), Rust (`.rs`), Python (`.py`, `.pyi`), and Go (`.go`) files that survive the Phase 1 inventory policy. Ignored, excluded, generated, vendor, nested-repository, binary, unreadable, and oversized files are never sent to a parser.

Each adapter uses one pinned Tree-sitter grammar in-process and produces the same Secure-owned fact shape. Parser modes, grammar versions, and extractor versions are part of cache identity. JavaScript/TypeScript adapter versions, fact fingerprints, and cache-key inputs remain unchanged from Phase 2.

## Fact families

- functions, methods, imports, exports, and calls;
- Express-style routes and Next.js App Router handlers;
- Next.js Server Action candidates marked by `use server`;
- Axum and Actix-style Rust routes and handler parameters;
- FastAPI, Flask, and Django-style Python decorators and route registration;
- `net/http`, Gin, Chi, and Echo-style Go route registration;
- environment access and authentication/authorization guard candidates;
- process execution, database, filesystem, network, redirect, template, deserialization, and dynamic-code operations.

These are conservative syntax classifications. A `database-access`, deserialization, template, or `unsafe`-adjacent construct alone does not prove a vulnerability. Findings require the shared graph/rule evidence described separately; a Rust `unsafe` block alone never creates a finding.

Every fact contains a repository-relative location with half-open bytes and one-based Unicode scalar line/column coordinates. Names and relationships are limited to relevant symbols, modules, routes, environment names, and operation names. No argument payloads or complete source snippets are exported.

## Recovery and limits

Malformed source may produce both useful facts and recoverable diagnostics. Invalid UTF-8 produces a bounded non-recoverable parser diagnostic. Parsing and extraction honor cancellation, per-file fact limits, a total fact limit, graph limits, and the report-wide parser-diagnostic limit.

## Cache lifecycle

The cache is enabled by default and repository-specific. CLI and desktop can disable it, clear it before a scan, choose a local base directory, and set its byte bound. Valid entries reproduce the exact same facts, graph, findings, and report fingerprint. Content, language/parser mode, grammar, parser adapter, extractor version, or relevant configuration changes produce a miss. Phase 6.5 advanced the cache envelope to `secure-parse-cache-v2`, Phase 6.6 to `secure-parse-cache-v3`, Phase 6.7 to `secure-parse-cache-v4`, Phase 6.8 to `secure-parse-cache-v5`, Phase 6.9 to `secure-parse-cache-v6`, Phase 6.10 to `secure-parse-cache-v7` for private authorization candidates and summaries, Phase 6.11 tranche 1 to `secure-parse-cache-v8` for corrected structural guard dominance, tranche 2 to `secure-parse-cache-v9` for structural sequence-callee and exact composed-path records, and tranche 3 to `secure-parse-cache-v10` for exact redirect-origin and field-sensitive object records. Phase 6.12 tranche 1 advances to `secure-parse-cache-v11` for private raw-callee identity and bounded arrow/`node:path` summaries; tranche 2 advances to `secure-parse-cache-v12` for typed URL projection and protected-resource identity; tranche 3 advances to `secure-parse-cache-v13` for private exact shell program-text argument identity; and tranche 4 advances to `secure-parse-cache-v14` for exact object-literal property identities and direct-destructuring evaluation order. Phase 6.13 tranche 1 advances development analysis to `secure-parse-cache-v15` for bounded forward local-value state. The public graph extractor identity stays stable so unaffected finding fingerprints do not migrate merely because of cache serialization. Older entries become safe misses and are never reinterpreted. Corrupt, cross-language, or incompatible entries are ignored without failing the scan.

## Language boundaries

- Rust extraction does not expand procedural macros, generated code, trait-object dispatch, or runtime framework layers. Axum/Actix route registration, request extractors, local guards, SQLx/raw query shapes, `Command`, filesystem, Reqwest, redirect, and deserialization calls are recognized conservatively.
- Python extraction does not execute decorators or resolve monkey patching, metaclasses, dynamic attributes, or runtime imports. FastAPI/Flask/Django routes, request objects and dependencies/decorators, subprocess and dynamic-code calls, raw SQL, filesystem, Requests/HTTPX, redirects, templates, and pickle shapes are recognized conservatively.
- Go extraction does not resolve ambiguous interfaces, callbacks, reflection, or generated code. `net/http`, Gin, Chi, and Echo routes, request/context values, local middleware/guards, `os/exec`, `database/sql`, filesystem, HTTP clients, redirects, templates, and deserialization calls are recognized conservatively.
