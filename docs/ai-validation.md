# Phase 6 optional AI-assisted finding validation

AI validation is a separate review layer over a completed `secure-json-v1` report. It is disabled by default and is never part of `secure scan`. An assessment cannot create, delete, suppress, reprioritize, or overwrite a deterministic finding, its severity, confidence, evidence, remediation, or fingerprints. The report fingerprint excludes every provider, timing, usage, cache, and consent field.

## Safe workflow

1. Complete a deterministic scan and select one or a bounded set of existing finding IDs.
2. Create an explicit `secure-ai-config-v1` project file with `enabled: true`, provider, model, and limits. A remote endpoint has no default and must be HTTPS without credentials, query, or fragment. The file names a credential environment variable; it never contains the credential.
3. Run `secure ai preview`. The engine builds a minimal structured finding payload, retains only repository-relative evidence locations, truncates it to configured limits, redacts common credential forms, and emits the exact provider, model, endpoint scope, token/timeout/cost caps, payload, payload fingerprint, and consent fingerprint.
4. Review the machine-readable preview. Run validation only with every exact `--consent` fingerprint from that current preview. Missing, stale, or mismatched consent is refused, including in non-interactive CI.
5. The bounded provider receives a system instruction and a structurally separate JSON payload. Repository names, finding prose, paths, and evidence are untrusted data. The provider has no filesystem, shell, Git, scanner, patch, tool-calling, or additional-network authority.
6. Strict output parsing accepts only `supported`, `questioned`, `insufficient-evidence`, or `contradicted`, with `supported`, `questioned`, or `missing` evidence status. Malformed or extra fields publish no assessment.
7. The resulting `secure-ai-validation-v1` document remains separate and records finding ID/fingerprint, provider/model, adapter/prompt/schema versions, payload and cache fingerprints, consent, timestamps, usage when supplied, cache provenance, prerequisites, explanation, remediation proposal, verification suggestions, limitations, and uncertainty.

## Providers and configuration

`secure ai providers` lists capabilities without a network call. `mock` and `recorded` are deterministic evaluation adapters; they do not support public quality claims. `openai-responses` is the optional current official adapter. It uses a caller-configured endpoint/model, reads the key only from the configured environment variable, requests strict JSON Schema output, refuses redirects, bounds response bytes and time, and redacts provider errors. Its capability metadata states that in-flight transport cancellation is unavailable; cancellation is observed before and after the bounded request, while the timeout is the hard upper bound.

The adapter follows OpenAI's official [Responses create API](https://developers.openai.com/api/reference/resources/responses/methods/create), [Structured Outputs guidance](https://developers.openai.com/api/docs/guides/structured-outputs), and [production best practices](https://developers.openai.com/api/docs/guides/production-best-practices). Secure Engine still owns the narrower request/response contract and performs its own strict validation after receipt.

Example configuration:

```json
{
  "format": "secure-ai-config-v1",
  "enabled": true,
  "provider": "recorded",
  "model": "fixture-model",
  "endpoint": null,
  "api_key_env": null,
  "recorded_response": "fixtures/phase6-ai/supported.json",
  "pricing": null,
  "limits": {
    "max_findings": 10,
    "max_payload_bytes": 32768,
    "max_output_tokens": 1200,
    "timeout_seconds": 30,
    "max_evidence_locations": 24,
    "max_string_chars": 4000,
    "max_cost_microunits": null
  }
}
```

No endpoint, model, key, price, or provider behavior is inferred. Secure Engine contains no pricing table. A project that sets `max_cost_microunits` must also supply its own nonzero input/output price per million tokens. Preview computes a conservative bound using input bytes as the token upper bound plus `max_output_tokens`, refuses a bound above the budget, and checks provider-reported usage when available.

## CLI and storage

```text
secure ai providers
secure ai preview FINDING_ID --report REPORT --provider PROVIDER --config CONFIG
secure ai preview --all --report REPORT --provider PROVIDER --config CONFIG --max-findings N
secure ai validate FINDING_ID --report REPORT --provider PROVIDER --config CONFIG --consent FINGERPRINT
secure ai validate --all --report REPORT --provider PROVIDER --config CONFIG --max-findings N --consent FINGERPRINT...
secure ai cache clear [--cache-dir DIRECTORY]
```

stdout contains only JSON; human progress uses stderr. Assessments can be emitted to stdout or atomically written with `--output`. The private local cache uses a key covering finding, provider, model, prompt, schema, and payload fingerprints. Entries are bounded, corruption-safe, and atomically written. Credentials and endpoints are not stored in cache entries. History can attach or locally delete assessment records without modifying its immutable report. Baselines remain deterministic and contain no AI state. SARIF includes assessments only through the explicit enriched export API.

## Evaluation and non-goals

Committed fixtures cover supported, questioned, insufficient, contradicted, malformed, adversarial, prompt-injection, cancellation, timeout, duplicate, redaction, and replay behavior. Verification never performs a live call and uses no real repository data. Phase 6.5 adds the deterministic finding's taxonomy coordinates, primary CWE, and mapping provenance to the redacted preview payload. Phase 6.6 additively includes the semantic fingerprint; it does not change providers, prompts, consent, transport, caching, cost limits, or assessment behavior. Phase 6 does not apply fixes, call tools, modify source, add accounts/telemetry/hosted services, add languages/rules/package formats, or claim provider quality.
