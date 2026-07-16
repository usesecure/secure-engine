# Repository inventory controls

Both CLI and desktop map to the same `ScanConfiguration` and shared engine function.

## Selection order

1. VCS metadata and symlinks are always excluded.
2. Hidden and Git/repository ignore policies apply.
3. User exclude globs prune matching files and directories.
4. Generated, vendor, and nested repository roots are pruned unless explicitly enabled.
5. Include globs select matching regular files; an empty include list selects all remaining files.
6. The lexicographically first `max_files` paths are retained.
7. Per-file and total-byte limits apply before bounded content reads.

Globs are slash-normalized and repository-relative. Patterns containing absolute prefixes, backslashes, NULs, or `..` components are rejected as invalid input. A basename-only pattern such as `*.rs` matches at any repository depth. Exclusions take precedence over inclusions; an include never overrides ignore rules unless ignore processing is explicitly disabled.

## Directory policies

Generated defaults include `target`, `dist`, `build`, `out`, coverage/cache folders, and common framework build folders. Vendor defaults include `node_modules`, `vendor`, `third_party`, virtual environments, and `site-packages`. These are evidence-based inventory policies, not vulnerability rules.

Nested directories containing a `.git` directory or gitfile are treated as repository boundaries. This covers ordinary nested repositories, linked worktrees, and submodules. The selected root itself may be an ordinary Git repository or worktree.

## Privacy and limitations

The report exports paths, classification, sizes, and BLAKE3 fingerprints, never source contents or host-absolute roots. Excluded inputs are summarized only by reason and count, so ignored filenames are not disclosed. Skipped included files may be named with a repository-relative path so users can audit resource and symlink decisions.

Inventory does not itself claim vulnerability detection. Parsing and graph/rule analysis run only on supported JavaScript/TypeScript, Rust, Python, and Go inputs after this boundary; binary classification and framework identification remain bounded inventory heuristics.
