# ADR 0029: Local RegExp exec call-target refinement

## Status

Implemented in an isolated local candidate; not published or installed by this change.

## Context

Review of an authorized application found two SE1001 candidates ending at
`senderPattern.exec(chatText)`. The receiver was a function-local regular-expression
literal, not a process API. Classifying all methods named `exec` as command execution
introduced an incorrect sink before source-to-sink calibration.

The correction belongs in call-target extraction, not a repository-specific ignore
list, a UI filter, or an automatic rejection of the original Security Cases.

## Decision

Use one shared bounded refinement for normalized facts and graph extraction. A
`receiver.exec(...)` call loses only its `process-execution` classification when:

- The receiver is a simple identifier initialized from a regex literal by a
  preceding direct-body `const` declaration in the same function.
- Every reference to that binding is the declaration or a direct `.exec(...)`
  receiver in that function. Mutation, escapes (including object shorthand),
  aliases, nested-function use, and conflicting declarations prevent refinement.
- The parsed function and module have no error nodes. Visible dynamic evaluation
  and recognized prototype/reflection operations prevent refinement.
- The function traversal finishes within 4,096 nodes and the module traversal
  within 16,384 nodes. Exhaustion retains the existing candidate behavior.

The generic call fact is retained. Other operations and rules still analyze the
file. Names, project paths, comments, and prior human verdicts are not inputs to
the refinement. An unrelated `new RegExp(...)` does not disable recognition of a
separate literal; a constructor-created receiver itself is not refined.

## Compatibility and limits

Public schema and rule identifiers are unchanged. Reports, findings, and graph
contents may change where a non-process call previously introduced a sink.
Private parse-cache namespace v24 prevents v23 results from retaining stale
facts or graph classifications. Historical cache directories are not deleted.

This model assumes standard JavaScript built-ins. It is not a proof against
cross-module or obfuscated prototype modification, compromised runtimes, or
arbitrary coercion side effects. It also makes no claim about regex complexity
or ReDoS. Unknown receivers and unsupported patterns retain the prior conservative
classification; their continued presence is not a validated vulnerability.

No Security Case verdict, authorization, application source, or installed Engine
is modified by this patch.

## Verification

`crates/secure-engine/tests/regexp_exec_precision.rs` uses synthetic source that is
parsed but never executed. It covers JS, JSX, TS, and TSX; real process imports
and aliases; unknown receivers; mutation, escape, shadowing and reflection;
mixed safe/unsafe calls; traversal-budget exhaustion; and cold/warm cache parity.
The safe-literal and mixed-call tests failed before the implementation and pass
after it. No hidden evaluation corpus was used to derive the change.

With Rust 1.92.0:

```sh
cargo test -p secure-engine -p secure-cli --locked --offline
cargo clippy -p secure-engine -p secure-cli --all-targets --locked --offline -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Application-specific scan receipts remain outside this repository. Any measured
before/after improvement must compare this candidate with its exact parent on
the same target snapshot, not a different released Engine version.
