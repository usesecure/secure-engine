#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
target="${SECURE_RPM_TARGET:-$root/target/phase65-rpm}"
rpm_path="${1:-}"
if test -z "$rpm_path"; then
  rpm_path="$(find "$target/rpmbuild/RPMS" -type f -name 'secure-engine-*.rpm' -print -quit)"
fi
test -f "$rpm_path"

actual="$target/package-files.txt"
expected="$target/expected-package-files.txt"
rpm -qpl "$rpm_path" | LC_ALL=C sort >"$actual"
printf '%s\n' \
  /usr/bin/secure \
  /usr/bin/secure-desktop \
  /usr/share/applications/dev.usesecure.SecureEngine.desktop \
  /usr/share/doc/secure-engine \
  /usr/share/doc/secure-engine/README.md \
  /usr/share/icons/hicolor/scalable/apps/dev.usesecure.SecureEngine.svg \
  /usr/share/licenses/secure-engine \
  /usr/share/licenses/secure-engine/LICENSE \
  /usr/share/metainfo/dev.usesecure.SecureEngine.metainfo.xml | LC_ALL=C sort >"$expected"
cmp "$expected" "$actual"
rpm -qpi "$rpm_path" >/dev/null

extract="$target/extracted"
rm -rf -- "$extract"
mkdir -p -- "$extract"
(cd "$extract" && rpm2cpio "$rpm_path" | cpio -idm --quiet)
"$extract/usr/bin/secure" rules list >/dev/null
"$extract/usr/bin/secure" ai providers >/dev/null
desktop-file-validate "$extract/usr/share/applications/dev.usesecure.SecureEngine.desktop"
appstreamcli validate --no-net "$extract/usr/share/metainfo/dev.usesecure.SecureEngine.metainfo.xml"

if test "${SECURE_SKIP_DESKTOP_SMOKE:-0}" != 1; then
  test -n "${DISPLAY:-}"
  set +e
  timeout 5s "$extract/usr/bin/secure-desktop" "$root/fixtures/phase5-multilang" >"$target/desktop-smoke.stdout" 2>"$target/desktop-smoke.stderr"
  status=$?
  set -e
  test "$status" -eq 124
fi

printf '%s\n' "$rpm_path"
