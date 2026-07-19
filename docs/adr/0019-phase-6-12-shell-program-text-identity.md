# ADR 0019: bind explicit shell execution to exact program text

Status: Accepted for the Phase 6.12 tranche 3 development branch.

## Context

Node process APIs normally pass a fixed executable an argv array without shell interpretation.
That rule is incorrect when the fixed executable is itself a shell and a supported option selects
the next argument as a command string. Treating the whole array as shell code creates false
positives on positional parameters; treating the whole array as ordinary argv misses construction
inside the command string.

## Decision

Recognize a bounded explicit set of shell executable names and absolute literal paths. Resolve only
stable bounded local constants. Within a statically ordered, unambiguous argument array, accept only
fixed supported options and identify the one exact option with `-c` semantics. Mark only its
immediate successor as program text. Preserve later elements as positional argv regardless of their
taint, and preserve the existing ordinary-argv behavior for fixed non-shell executables.

Store the interpreter, command option, and exact program value as private typed record inputs. Use
only the program-value markers when selecting sensitive `SE1001` input and use the program
expression as sink evidence. Explicit `shell:false` does not override an executable shell's own
parsing; existing string-shell and `shell:true` paths remain unchanged.

Reject shell-specific proof for dynamic or ambiguous executable identity, reassignment, mutation,
spread or holes obscuring the boundary, computed options, unsupported flags, unknown order or
wrapper, relative paths with separators, and exhausted bounds. Do not infer program flow when the
exact argument is not structurally identified. Unsupported shapes retain existing conservative
process semantics and limitations rather than becoming sanitizer evidence.

Advance the private parse-cache envelope from `secure-parse-cache-v12` to
`secure-parse-cache-v13`, because serialized `ProgramRecord.inputs` and affected sink locations
change. Keep `secure-evidence-graph-v1`, public rule IDs, schemas, taxonomy 1.0.0, Evidence Contract
v2, secure-json-v1, SARIF, and public version 0.1.7 unchanged.

## Consequences

Supported explicit shell command strings receive precise source-to-program evidence through direct,
helper, unique-import, and RC3 arrow-summary flow. Untrusted values supplied only as positional
parameters do not become shell code. Weak rewriting, blocklists, and quoting do not become
sanitizers.

The model deliberately does not resolve arbitrary shell implementations, runtime PATH state,
environment wrappers, dynamic option parsing, executable-specific argv injection, or structures
beyond configured bounds. RC3 and RC5 remain compatible; RC4 remains deferred and RC1 remains
outside the Engine's sound remediation boundary.
