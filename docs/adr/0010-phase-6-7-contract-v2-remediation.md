# ADR 0010: Public evidence contract v2 and call-site value identity

Status: Accepted for Secure Engine 0.1.3.

## Context

Phase 6.6 exposed Engine-owned evidence semantics but did not implement the public tool-neutral
contract used to compare taxonomy, endpoints, ordered paths, barriers, partial outcomes, and
duplicates. Retired diagnostics also showed that identifier-based accessor identity and sorted call
inputs could disconnect valid helper paths or select unrelated sources.

## Decision

Implement contract v2 as an additive typed projection. Assign every call expression a stable local
call-site key, retain nested markers, keep positional argument ordering, and select traces by proven
source specificity. Separate framework source classification from syntax extraction. Apply
operation-specific conservative barrier proofs and retain one best candidate per rule/sink.

The frozen taxonomy remains unchanged. Public contract files are immutable test inputs. No
benchmark-specific names, IDs, paths, or exceptions enter production code.

## Consequences

JSON and SARIF consumers gain explicit versioned contract metadata and fingerprints. Exact public
synthetic vectors and 140 independent scenarios become release gates. Corrected evidence paths and
duplicate removal intentionally migrate affected legacy finding fingerprints, requiring normal
baseline review. Analysis remains bounded and incomplete for dynamic runtime behavior; reports keep
those limitations explicit. AI policy, consent, transport, telemetry, and network defaults do not
change.
