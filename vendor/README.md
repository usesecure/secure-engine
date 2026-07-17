# Scoped build-dependency patch

`wayland-scanner` 0.31.10 is vendored byte-for-byte from its crates.io release except for one
dependency constraint: `quick-xml` is advanced from `0.39` to the API-compatible fixed `0.41`
series. The upstream 0.31.10 release constrains `quick-xml` to the vulnerable 0.39 series, which is
affected by RUSTSEC-2026-0194 and RUSTSEC-2026-0195.

`wayland-scanner` is a compile-time proc macro used by the desktop Wayland dependency graph. The
patched crate retains its MIT license and upstream source. Workspace compilation, tests, strict
Clippy, RustSec, cargo-deny, and Fedora package builds verify this narrow patch. Remove it when an
upstream `wayland-scanner` release permits `quick-xml >=0.41.0`.
