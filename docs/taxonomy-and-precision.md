# Phase 6.5 neutral taxonomy and precision

Secure Engine 0.1.1 consumes the frozen, tool-neutral `secure-bench-taxonomy-v1` contract version 1.0.0 as a read-only public interoperability contract. The implementation was derived only from its public schema, taxonomy document, and methodology. No benchmark corpus, expected result, baseline, evaluator, case identifier, scanner-specific output, or private artifact was read or executed.

## Provenance

The contract is frozen by signed DCO commit `93c0821db065de436a339c15b070e158947ad76c`. Its public artifacts are pinned by SHA-256:

- schema: `cdecd643d338aa8ae42ec7398c6c4703cb97d60ad355340c98744fc94bcb7d6f`;
- taxonomy: `059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452`;
- methodology: `eac27e5800be35c5ae77f7804e52ae90462cbda403a5484baa8fab62f02ab562`;
- canonical content: `22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c`.

The taxonomy source is CWE 4.20. Secure Engine embeds the hashes and source commit; it does not copy, rewrite, or generate the frozen artifacts.

## Exact mappings

| Rule | Neutral category | Neutral invariant | Primary CWE |
| --- | --- | --- | --- |
| `SE1001` | `secure-bench.category.command-execution` | `secure-bench.invariant.command-control-data-separation` | CWE-78 |
| `SE1002` | `secure-bench.category.sql-construction` | `secure-bench.invariant.sql-control-data-separation` | CWE-89 |
| `SE1003` | `secure-bench.category.filesystem-boundary` | `secure-bench.invariant.filesystem-path-confinement` | CWE-22 |
| `SE1004` | `secure-bench.category.outbound-request-boundary` | `secure-bench.invariant.outbound-destination-policy` | CWE-918 |
| `SE1005` | `secure-bench.category.redirect-boundary` | `secure-bench.invariant.redirect-destination-policy` | CWE-601 |
| `SE1006` | `secure-bench.category.dynamic-code-execution` | `secure-bench.invariant.dynamic-code-control-data-separation` | CWE-95 |
| `SE1007` | `secure-bench.category.authorization-dominance` | `secure-bench.invariant.authorization-before-sensitive-operation` | CWE-862 |

The mapping is one-to-one and introduces no aliases. Existing rule identifiers remain authoritative inside Secure Engine. Mapping provenance records the taxonomy name, signed source commit, canonical content hash, and the basis `secure-engine-built-in-rule-family`.

## Corrected deterministic semantics

Independent Engine-owned fixtures exercise direct vulnerable flows, uniquely resolved helper flows, safe dominant controls, unsafe non-dominating near misses, and unresolved variants. Phase 6.5 adds local helper return propagation, handler reachability, guard summaries, and sanitizer-policy summaries. It recognizes template and concatenated filesystem paths, canonicalization plus root containment, sensitive Server Action mutations, protocol/hostname outbound policies, redirect allowlists and safe fallbacks, and fixed executable/argument-array calls with shell processing explicitly disabled.

A check is not accepted merely because it occurs earlier in source order. For TypeScript, its successful region must contain the sink, or its rejecting branch must terminate. Filesystem confinement additionally requires canonicalization on the evidence path. A non-terminating warning remains a finding.

## Compatibility and limitations

Taxonomy fields are additive in `secure-json-v1`, SARIF, baselines, history, CLI, desktop, and optional AI preview payloads. Earlier JSON, baseline, and history documents deserialize with empty metadata. Existing finding fingerprints remain unchanged unless genuinely new evidence becomes reachable. The parse-cache format is versioned to invalidate pre-calibration entries safely.

Dynamic imports, ambiguous aliases, callbacks, recursion, runtime middleware, reflection, and unresolved calls remain explicit limitations. A fixed executable with an argument array and `shell: false` is excluded only from the shell-command-injection rule; executable-specific argument injection semantics are not modeled and are reported as `process-argument-semantics-not-modeled`. AI remains disabled by default and separate from deterministic evidence.
