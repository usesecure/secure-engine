# ADR 0008: Frozen neutral taxonomy and structural precision

## Status

Accepted for Secure Engine 0.1.1.

## Context

Secure Engine needs tool-neutral interoperability without coupling its rules to a benchmark implementation. Source-order guard heuristics also cannot distinguish a terminating rejection path from a warning that permits a sensitive sink.

## Decision

Embed the exact public `secure-bench-taxonomy-v1` 1.0.0 coordinates and signed provenance as additive metadata while retaining `SE1001`–`SE1007`. Keep the external contract read-only and implement the mapping inside the Engine. Use syntax-tree byte ranges for TypeScript dominance, propagate only uniquely resolved local helper summaries, and require policy-specific sanitizer semantics. Preserve legacy report deserialization and finding fingerprints. Version the parse-cache format when the extracted program representation changes.

## Consequences

JSON, SARIF, CLI, desktop, baseline, history, and optional AI preview consumers can correlate findings without scanner-native aliases. False positives from dominant filesystem, outbound, redirect, authorization, and fixed-executable controls are reduced while unsafe near misses remain visible. The analysis deliberately does not claim argument-level process safety or resolve dynamic dispatch. Independent fixtures and explicit limitations make those boundaries testable.
