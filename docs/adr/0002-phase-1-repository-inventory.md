# ADR 0002: Production repository inventory

- Status: accepted
- Date: 2026-07-16

## Decisions

1. **Traversal and ignores:** `ignore` remains the Git-compatible traversal implementation. Git ignore, global/exclude, nested `.gitignore`, and `.ignore` semantics are enabled independently of whether a directory has been initialized as Git. User exclude globs and safe directory policies prune entries before file opening.
2. **Deterministic bounds:** discovery retains only the lexicographically first `max_files` matching relative paths in a bounded `BTreeMap`. Processing then follows that order. Per-file and total-byte limits bound reads, error and skipped lists are bounded, and typed discovery progress is emitted periodically.
3. **Path safety:** traversal never follows symlinks. On Unix/Fedora every selected file is reopened with `O_NOFOLLOW`, closing the traversal/read race that could otherwise escape the repository. Reports contain slash-normalized relative paths only.
4. **Repository boundaries:** VCS metadata is always excluded. Generated, vendor, nested repository, worktree, and submodule roots are excluded by default and may be included only through explicit controls. A selected Git worktree may read its fixed Git metadata files outside the worktree to identify HEAD, but these paths are never exported and are never part of source traversal.
5. **Classification:** bounded bytes are classified as text or binary. Language detection is extension-based; manifests, lockfiles, tests, documentation, configuration, data, and build automation are classified without parsing source. Framework detections remain clearly labeled manifest hints.
6. **Compatibility:** Phase 1 keeps `secure-json-v1`. New configuration, repository, file, aggregate inventory, and exclusion properties are optional in the schema and have Serde defaults. Phase 0 fixtures remain compatibility tests.
7. **UI concurrency:** the native UI continues running the shared synchronous engine on a background worker with a bounded progress channel. This preserves deterministic core behavior while keeping the render thread responsive on large repositories.

## Consequences

The scanner can inventory large repositories predictably without reading ignored or pruned content. It intentionally does not cache, parse syntax, follow semantic flow, run vulnerability rules, invoke AI, or modify source.
