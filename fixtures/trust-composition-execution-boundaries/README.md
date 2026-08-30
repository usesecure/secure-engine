# Trust-composition and execution-boundary fixture matrix

This neutral development corpus was written before production `SE1012` logic. It contains no
external-project paths, symbols, setting keys, source text, fingerprints, or case identifiers.

The matrix covers:

- user/global, workspace, workspace-folder, environment, manifest-default, runtime-mutation, and
  unresolved effective configuration;
- trusted, untrusted, exact-scope, wrong-scope, fresh, and stale-after-`await` variants;
- single-root and multi-root composition;
- exact binary, shell program, argv, environment, cwd, and shell-mode process components;
- constant components, aliases, closures, callbacks, unique imports, duplicate helper names, and
  cross-call separation;
- scoped and underspecified cache keys;
- metamorphic renames and structural variations in the Rust test target;
- explicit abstention for dynamic configuration, lifecycle callbacks, ambiguous dispatch, and
  mutable cache provenance, duplicate helper identities, and runtime mutation.

Every `SE1012` result remains an unverified lead. The corpus is a deterministic development gate,
not a representative benchmark, vulnerability claim, or evidence of human replacement.
