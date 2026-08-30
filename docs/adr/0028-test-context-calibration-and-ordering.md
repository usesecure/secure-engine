# ADR 0028: Test-context calibration and ordering

## Status

Accepted.

## Context

An authorized npm CLI scan retained a process-execution abstention whose complete evidence path was
inside a test harness. Human review established that the harness expected a fixed command and did
not establish production reachability, a distinct lower-privilege actor, or security impact. The
existing calibration correctly withheld a finding because the environment authority was
equivalent, but its generic reason and ordering did not expose the test-only execution context.

Test paths cannot be excluded safely. Tests run in CI, consume pull-request content, invoke build
tools, and can cross credential or process boundaries. A path under `test/` can therefore contain a
real security path when actor control, a distinct boundary, and impact are otherwise proven.

## Decision

1. Reuse the repository inventory's language-neutral test-path classification. Production analysis
   contains no repository, package, symbol, command, or campaign-specific exception.
2. Apply test context only after normal semantic calibration. A path is test-only only when every
   retained source-to-sink evidence step is in a recognized test-source path.
3. When normal calibration already produces an explicit abstention, use the stable reason
   `test-context-reachability-unresolved` and retain the original prerequisite resolutions. Test
   context never changes `security-path` or `bounded-hardening` into an abstention and never removes
   evidence.
4. Order non-test abstentions before test-only abstentions, with the existing abstention identifier
   as the deterministic tie-breaker. This is review prioritization, not a vulnerability verdict.
5. Add a test-context limitation that explicitly requires production or CI reachability and actor
   validation while warning that test paths remain analyzed.
6. Replace generic framework-middleware limitations for process-execution and outbound-request
   leads with rule-specific runtime limitations.

## Compatibility

The public schema, taxonomy, Evidence Contract v2, rule identifiers, finding fingerprints, and
abstention fingerprints do not change. A test-only abstention's reason, limitations, order, and
therefore report fingerprint can change because the reported evidence calibration is more precise.
Mixed test/production paths retain normal calibration.

## Failure posture

A path name alone never proves safety or reachability. Untrusted input reaching process execution in
a test source remains a security path when the semantic prerequisites are proven. Dynamic CI
configuration, workflow permissions, contributor trust, test selection, and runtime execution stay
outside the static proof and require human validation.

## Evaluation

A neutral generated regression pairs a production environment abstention with a test-only
environment abstention, a mixed path whose test endpoints cross a production helper, and a
test-source untrusted-command security path. It requires non-test and mixed evidence to sort before
test-only evidence, the test-only reason and limitations to be explicit, and the proven test-source
security path to remain a finding.
