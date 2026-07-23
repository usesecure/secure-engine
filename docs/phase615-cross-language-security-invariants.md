# Phase 6.15 cross-language security invariants

This phase uses public vulnerability patterns only as development prompts. Its fixtures are
independent synthetic vulnerable/control pairs; no public CVE is treated as independent
evaluation data.

## Tranche 1: identity and authorization ordering

JavaScript/TypeScript analysis now refuses to count a local `async` authorization helper when its
result is neither awaited nor returned. Authorization attached to a tainted identity is also
invalidated by a later decode, normalization, canonicalization, case-folding, trim, or resolution
transformation. `SE1007` remains the public rule because both cases violate its existing
authorization-before-sensitive-operation invariant.

Static coverage requires a structurally resolved local helper and a directly represented
transformation. Dynamic callees, opaque imported wrappers, mutation through reflection, ambiguous
aliases, and analysis beyond configured depth do not earn authorization credit. General
exception-to-success recovery and semantic state-machine validity remain deferred because the
current normalized facts do not prove success semantics or legal transition graphs.

## Tranche 2: path and archive confinement

`SE1003` now treats archive member `path`, `name`, and `linkpath` values as untrusted only when the
binding is structurally introduced by iteration over an archive/tar/zip entry or member
collection. Explicit `extract`, `extractAll`, `unpack`, and `unpackIn` calls on archive-like
receivers are filesystem sinks. This detects archive traversal without repository, filename, CVE,
or fixture exceptions and avoids treating unrelated `entry.path` properties as attacker input.

Lexical joins and canonicalization names alone do not prove confinement. Safe controls must avoid
attacker-controlled destination paths or establish an already supported exact confinement proof.
Symlink-target policy, PAX parser synchronization, descriptor-relative extraction, and
check-then-use TOCTOU remain deferred: the present facts do not model filesystem object identity,
open descriptors, archive parser state, or concurrent mutation strongly enough for a
high-confidence finding.

## Tranche 3: CLI, SQL structure, and prototypes

`SE1008` is a new, deliberately separate CLI-option rule. It applies to fixed executable APIs with
shell processing disabled when a dynamic array element can reach option parsing before a literal
`--`. Literal arguments and dynamic values after `--` are controls. Whether a particular
executable supports the delimiter remains an explicit prerequisite.

`SE1002` continues to distinguish constant parameterized query text from attacker-controlled SQL
structure. Interpolation into statement options such as COPY configuration remains raw structure;
bound values remain controls.

`SE1009` is a new shared-prototype rule for tainted values reaching `Object.assign`,
`Object.defineProperty`, `Reflect.defineProperty`, or direct assignments whose target is
structurally an intrinsic prototype or `__proto__`. Dynamic deep-merge implementations, library
semantics, getters, proxies, and computed prototype aliases remain deferred.
