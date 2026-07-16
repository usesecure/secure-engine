# ADR 0003: JavaScript/TypeScript parsing and normalized-fact cache

- Status: accepted
- Date: 2026-07-16

## Decisions

1. **Parser boundary:** Tree-sitter `0.26.11`, tree-sitter-javascript `0.25.0`, and tree-sitter-typescript `0.23.2` are pinned. Their types remain inside `parser`; public callers receive only Secure Engine domain models.
2. **Four modes:** JavaScript, JSX, TypeScript, and TSX are selected independently by extension. JavaScript and JSX intentionally share the JavaScript grammar while retaining distinct coverage and cache identities.
3. **Evidence model:** normalized facts contain stable identifiers, exact Unicode-aware locations, bounded names and relationships, full evidence fingerprints, and parser/extractor provenance. They never contain source snippets, severity, confidence, or vulnerability claims.
4. **Recovery and cancellation:** Tree-sitter recovery trees remain useful when syntax is incomplete. Diagnostics are bounded and sanitized. The runtime progress callback cancels inside parsing; extraction also checks cancellation periodically.
5. **Cache safety:** each repository gets a hashed directory outside the repository by default. Keys include relative path, content fingerprint, parser mode, grammar/runtime/extractor versions, and serialized scan configuration. Entries contain facts and diagnostics but no source or absolute path.
6. **Atomic bounds:** cache entries are size-limited, written to private temporary files, synchronized, and renamed atomically. Cancellation removes incomplete temporary files. Old entries are pruned to the configured byte bound; incompatible, tampered, symlinked, oversized, or malformed entries are ignored and replaced.
7. **Determinism:** parse duration and cache counters are documented volatile measurements and excluded from the report fingerprint. Facts, diagnostics, parser coverage, and stable parse counts are fingerprinted.

## Consequences

Phase 2 provides deterministic syntax evidence for later graph and rule phases without implementing data flow or making security findings. Cache reuse improves repeat scans but never changes evidence. Rust, Python, Go, Java, C#, graphs, rules, AI, and automatic fixes remain deferred.
