# Secure Engine 0.1.10-rc2 release candidate notes

Secure Engine 0.1.10-rc2 corrects a false-positive `SE1008` finding in a fixed `printf` argv data
slot. The correction recognizes format semantics only for a statically resolved literal executable
equal to `printf`, `/usr/bin/printf`, or `/bin/printf`, with shell execution disabled, a static argv
array, a literal first-argument format containing only `%s` slots and `%%` escapes, and exact data
operand arity.

All other executables and paths remain conservative. In particular, a `%s` string does not prove
format semantics for an arbitrary program, an unrecognized `printf` path, a relative executable,
an alias, or a dynamic executable. Dynamic formats or argv arrays, spreads, incorrect arity, and
shell-enabled calls continue to retain `SE1008` when untrusted input can reach option parsing.

The public GitHub Actions matrix for the integrated correction passed in full, including the
retired public development-regression test that keeps `exam-case-05-b` clean while detecting
`exam-case-05-a`. This retired corpus is used only as a public development regression; no benchmark,
independence, comparative-performance, or security-coverage metric is claimed.

The public version remains 0.1.10 and the private parse cache remains v20. This candidate changes no
dependency, schema, fingerprint contract, Evidence Contract, taxonomy, or rule inventory beyond the
already integrated Engine correction.
