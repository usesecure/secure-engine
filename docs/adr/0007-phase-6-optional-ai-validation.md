# ADR 0007: separate, consented AI assessment boundary

## Decision

Keep `ScanReport` and its fingerprint purely deterministic. Represent optional AI review as `secure-ai-validation-v1`, linked to the report and finding fingerprints. Use one sealed Secure-owned provider trait with typed request, response, usage, timeout, cancellation capability, and redacted errors. Ship deterministic mock/recorded adapters for evaluation and one optional OpenAI Responses adapter configured entirely by the caller.

Every operation requires an enabled project configuration and a consent fingerprint derived from the exact redacted payload, provider, model, endpoint scope, prompt/schema versions, and limits. Store replay data in a private atomic cache whose key covers all semantic inputs. History and SARIF accept explicit additive attachment; baseline and normal exports remain unchanged.

## Consequences

- Normal scans never need network access or credentials and preserve Phase 5 output.
- Provider output cannot silently alter deterministic conclusions.
- Users can inspect, cancel, delete, replay, and audit assessments independently.
- A changed payload, provider, model, endpoint, prompt, schema, or budget invalidates consent and cache reuse.
- The blocking remote transport cannot interrupt an in-flight request; capability metadata exposes that limitation and the configured timeout remains the upper bound.
