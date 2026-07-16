# JavaScript and TypeScript normalized facts

Phase 2 parses `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, and `.cts` files that survive the Phase 1 inventory policy. Ignored, excluded, generated, vendor, nested-repository, binary, unreadable, and oversized files are never sent to the parser.

## Fact families

- functions, methods, imports, exports, and calls;
- Express-style routes and Next.js App Router handlers;
- Next.js Server Action candidates marked by `use server`;
- environment access and authentication/authorization guard candidates;
- process execution, database, filesystem, network, redirect, template, deserialization, and dynamic-code operations.

These are conservative syntax classifications. A `database-access` fact means a recognized call shape exists; it does not prove injection or any other vulnerability. `findings` remains empty.

Every fact contains a repository-relative location with half-open bytes and one-based Unicode scalar line/column coordinates. Names and relationships are limited to relevant symbols, modules, routes, environment names, and operation names. No argument payloads or complete source snippets are exported.

## Recovery and limits

Malformed source may produce both useful facts and recoverable diagnostics. Invalid UTF-8 produces a bounded non-recoverable parser diagnostic. Parsing and extraction honor cancellation, per-file fact limits, a total fact limit, and the report-wide parser-diagnostic limit.

## Cache lifecycle

The cache is enabled by default and repository-specific. CLI and desktop can disable it, clear it before a scan, choose a local base directory, and set its byte bound. Valid cache entries reproduce the exact same facts and report fingerprint. Content, parser mode, versions, or relevant configuration changes produce a miss. Corrupt or incompatible entries are ignored without failing the scan.
