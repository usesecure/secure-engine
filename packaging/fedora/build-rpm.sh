#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
version="0.1.7"
target="${SECURE_RPM_TARGET:-$root/target/v0.1.7-rc1-rpm}"
topdir="$target/rpmbuild"
stage_parent="$target/stage"
stage="$stage_parent/secure-engine-$version"
source_date_epoch="$(git -C "$root" show -s --format=%ct HEAD)"
export SOURCE_DATE_EPOCH="$source_date_epoch"

rm -rf -- "$target"
mkdir -p -- "$target/tmp" "$topdir/BUILD" "$topdir/BUILDROOT" "$topdir/RPMS" "$topdir/SOURCES" "$topdir/SPECS" "$topdir/SRPMS" "$stage"

CARGO_TARGET_DIR="$root/target" \
  RUSTFLAGS="--remap-path-prefix=$root=/usr/src/secure-engine-$version" \
  cargo build --manifest-path "$root/Cargo.toml" --release --locked --offline -p secure-cli -p secure-desktop
install -m0755 "$root/target/release/secure" "$stage/secure"
install -m0755 "$root/target/release/secure-desktop" "$stage/secure-desktop"
install -m0644 "$root/packaging/fedora/dev.usesecure.SecureEngine.desktop" "$stage/dev.usesecure.SecureEngine.desktop"
install -m0644 "$root/packaging/fedora/dev.usesecure.SecureEngine.metainfo.xml" "$stage/dev.usesecure.SecureEngine.metainfo.xml"
install -m0644 "$root/packaging/fedora/dev.usesecure.SecureEngine.svg" "$stage/dev.usesecure.SecureEngine.svg"
install -m0644 "$root/LICENSE" "$stage/LICENSE"
install -m0644 "$root/README.md" "$stage/README.md"
install -m0644 "$root/packaging/fedora/secure-engine.spec" "$topdir/SPECS/secure-engine.spec"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  -C "$stage_parent" -cf - "secure-engine-$version" \
  | gzip -n >"$topdir/SOURCES/secure-engine-$version.tar.gz"

rpmbuild \
  --define "_topdir $topdir" \
  --define "_tmppath $target/tmp" \
  --define "source_date_epoch_from_changelog 0" \
  --define "use_source_date_epoch_as_buildtime 1" \
  --define "clamp_mtime_to_source_date_epoch 1" \
  -bb "$topdir/SPECS/secure-engine.spec"
find "$topdir/RPMS" -type f -name '*.rpm' -print
