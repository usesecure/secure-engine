# Phase 6.12 tranche 3: shell program-text identity

## Scope

This tranche implements only RC2 from
[the Phase 6.12 prioritization](./phase612-root-cause-prioritization.md). A fixed executable and a
literal argument array were previously classified as ordinary argv even when the executable was a
shell and an option selected the following argument as program text. The result was a missing
`SE1001` path for shell code constructed from an untrusted value.

RC3 arrow and bounded unique-call summaries and RC5 derived guard/resource identity remain
compatible. RC4 object-literal destructuring remains deferred. RC1 remains outside a sound Engine
remediation because unbound identifiers across lexical or module scopes are not data flow. The six
historical false negatives assigned to RC2 describe causal diagnostic reach only: this tranche did
not access or execute a benchmark, did not rescore results, and makes no measured six-case
correction claim.

## Structural decision

For the existing Node process APIs `spawn`, `spawnSync`, `execFile`, and `execFileSync`, including a
uniquely resolved imported alias, the extractor now proves four separate facts:

1. the executable is a supported shell;
2. preceding array elements are supported fixed interpreter options;
3. one exact option has command-string (`-c`) semantics; and
4. the immediately following array element is the program-text argument.

The bounded shell set is `sh`, `bash`, `dash`, `ash`, `ksh`, and `zsh`. A shell may be a direct
resolvable name, an absolute literal path whose basename is in that set, or a stable bounded local
constant resolving to either form. Relative paths containing separators are not accepted as proof.

The exact `-c` option is supported. Combined forms are accepted only when every flag is in the
bounded set: `c`, `e`, and `x` for every supported shell, plus `l` for `bash`, `ksh`, and `zsh`.
Flags may not repeat, long options do not qualify, and every preceding option must be a fixed
supported option without `c`. Therefore `-ec` is program-selecting, while `-C`, a computed option,
or an option after a non-option does not establish program-text identity.

Only values contained in the exact program-text expression become sensitive `SE1001` inputs. For
`sh -c program arg0 arg1`, `program` is code and `arg0`/`arg1` remain positional parameters. A
constant program with untrusted positional parameters is therefore not shell construction.
Conversely, `{ shell: false }` does not neutralize an explicit `/bin/sh -c` invocation. Existing
string-taking shell APIs and explicit `{ shell: true }` behavior are unchanged. Fixed non-shell
binaries with separated arguments retain their ordinary argv classification.

The proof is represented only by private typed record-input markers for interpreter, option, and
program value. The sink evidence span is the exact program expression, not the entire process call.
No public graph kind, rule, schema, taxonomy mapping, Evidence Contract, secure-json-v1, SARIF
field, CLI/desktop behavior, or unaffected finding fingerprint changes.

## Fail-closed boundary and risk

The shell-specific proof is refused for a dynamic or ambiguous executable, reassigned binding,
mutated argument array, spread or hole that obscures the option/program boundary, computed option,
unknown ordering, unsupported flag, unknown wrapper, relative executable path, or exhausted syntax
bound. It is also refused when the program argument itself cannot be identified. Existing generic
process-execution behavior remains conservative; absence of the typed proof is never a sanitizer or
suppression.

The bounded model does not infer runtime PATH contents, arbitrary shells, option parsing after a
script operand, wrapper semantics, environment-driven execution, executable-specific argument
injection, or runtime array mutation. This avoids expanding ordinary argv into shell code, at the
cost of leaving unsupported shapes unresolved. Partial quoting, replacement, blocklists, and
ambiguous escapes remain transformations rather than sanitizers.

## Independent fixtures

The tranche suite uses new synthetic dispatch and recipe domains. Vulnerable fixtures cover direct
concatenation, template construction, derived program values, exact combined options, direct and
helper-mediated flow, a unique inter-file import, an RC3 expression-arrow summary, explicit
`shell:false`, preserved outer-`shell:true` behavior, and insufficient replacement, blocklist, and
quoting.

Controls cover a fixed non-shell binary, a fixed shell program with untrusted positional values, a
fully constant program, the similar `-C` option, a later untrusted positional argument, unresolved
executable and option selection, a shadowed process alias, reassigned or mutated argument arrays, an
unresolved spread, an unknown wrapper, and exhausted interprocedural depth. None uses benchmark
paths, identifiers, case text, aliases, fingerprints, or exceptions.

## Cache and compatibility

The private program records now serialize exact shell program-text identity, so the cache envelope
advances from `secure-parse-cache-v12` to `secure-parse-cache-v13`. V12 directories remain untouched
and miss safely; only v13 entries are reused. Cold and warm v13 runs reproduce facts, graph,
findings, spans, and report fingerprints. The public extractor identity remains
`secure-evidence-graph-v1` and the public product version remains 0.1.7.

The durable boundary is recorded in
[ADR 0019](./adr/0019-phase-6-12-shell-program-text-identity.md).

## Verification

The final offline matrix passed formatting, strict workspace Clippy, and 166 permitted tests with
the three retired-corpus tests explicitly named and filtered. The total includes the seven
tranche-specific tests, RC3/RC5 regressions, schemas, SARIF, CLI/desktop parity, evidence spans and
fingerprints, cold/warm cache identity and v12 safe miss, privacy/symlinks, bounds/cancellation, and
AI-disabled operation. RustSec passed without fetching against 1,160 local advisories and 427 locked
dependencies with only the two documented historical exceptions. Cargo-deny passed advisories,
bans, licenses, and sources with fetching disabled. No scanner, corpus, package, installation,
release, or remote mutation was part of this tranche.

This work makes no benchmark ranking, superiority, production-readiness, complete-coverage, or
measured historical correction claim.
