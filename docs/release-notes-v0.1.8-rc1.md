# Secure Engine 0.1.8 release candidate notes

Version 0.1.8 freezes only the already integrated Phase 6.12 development tranches. It includes:

- bounded value-preserving summaries for supported arrow functions and unshadowed `node:path`
  composition;
- exact guard/resource identity linking authorization proof to the protected sink value;
- exact program-text classification for supported shell interpreters and command options;
- exact static-property identity through supported object literals and destructuring; and
- private parse cache v14, with v13 and older entries producing safe misses.

The release retains taxonomy 1.0.0, Evidence Contract v2, secure-json-v1, SARIF 2.1.0, existing rule
IDs, unaffected fingerprints, CLI/desktop parity, baselines, history, suppressions, privacy, bounds,
cancellation, and disabled-by-default AI validation. Structured 0.1.7 reports remain compatible
secure-json-v1 inputs. No dependency or rule update is part of this candidate.

RC1 remains an erratum in the retired corpus: its unbound cross-scope identifiers do not establish
sound data flow and are not an Engine defect that can be corrected without inventing identity.

This candidate has not received an independent holdout evaluation. It supports no benchmark,
ranking, superiority, production-readiness, or complete-coverage claim. Computed dispatch and
properties, reflection, ambiguous calls/imports, unresolved callbacks, and unproven runtime
filesystem behavior remain conservative limitations.

The first diagnostic build pair was rejected before qualification because private checkout-adjacent
Cargo target paths reached the desktop binary. The versioned Fedora build now remaps both the source
root and private Cargo target directory to stable logical prefixes. Only a fresh, independently built,
byte-identical pair produced after that correction can qualify as candidate artifacts.
