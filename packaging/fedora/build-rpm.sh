#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
target="${SECURE_RPM_TARGET:-$root/target/phase610-rpm}"
topdir="$target/rpmbuild"
stage_parent="$target/stage"
stage="$stage_parent/secure-engine-0.1.6"

rm -rf -- "$target"
mkdir -p -- "$target/tmp" "$topdir/BUILD" "$topdir/BUILDROOT" "$topdir/RPMS" "$topdir/SOURCES" "$topdir/SPECS" "$topdir/SRPMS" "$stage"

cargo build --manifest-path "$root/Cargo.toml" --release --locked --offline -p secure-cli -p secure-desktop
install -m0755 "$root/target/release/secure" "$stage/secure"
install -m0755 "$root/target/release/secure-desktop" "$stage/secure-desktop"
install -m0644 "$root/packaging/fedora/dev.usesecure.SecureEngine.desktop" "$stage/dev.usesecure.SecureEngine.desktop"
install -m0644 "$root/packaging/fedora/dev.usesecure.SecureEngine.metainfo.xml" "$stage/dev.usesecure.SecureEngine.metainfo.xml"
install -m0644 "$root/packaging/fedora/dev.usesecure.SecureEngine.svg" "$stage/dev.usesecure.SecureEngine.svg"
install -m0644 "$root/LICENSE" "$stage/LICENSE"
install -m0644 "$root/README.md" "$stage/README.md"
install -m0644 "$root/packaging/fedora/secure-engine.spec" "$topdir/SPECS/secure-engine.spec"
tar --sort=name --mtime='UTC 2026-07-18' --owner=0 --group=0 --numeric-owner -C "$stage_parent" -czf "$topdir/SOURCES/secure-engine-0.1.6.tar.gz" secure-engine-0.1.6

rpmbuild \
  --define "_topdir $topdir" \
  --define "_tmppath $target/tmp" \
  --define "use_source_date_epoch_as_buildtime 1" \
  -bb "$topdir/SPECS/secure-engine.spec"
find "$topdir/RPMS" -type f -name '*.rpm' -print
