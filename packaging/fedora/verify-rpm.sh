#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
target="${SECURE_RPM_TARGET:-$root/target/v0.1.9-rc1-rpm}"
rpm_path="${1:-}"
if test -z "$rpm_path"; then
  rpm_path="$(find "$target/rpmbuild/RPMS" -type f -name 'secure-engine-*.rpm' -print -quit)"
fi
test -f "$rpm_path"

actual="$target/package-files.txt"
expected="$target/expected-package-files.txt"
ownership="$target/package-ownership-permissions.txt"
expected_ownership="$target/expected-package-ownership-permissions.txt"
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
rpm -qp --qf '[%{FILENAMES}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILEMODES:perms}\n]' "$rpm_path" \
  | LC_ALL=C sort >"$ownership"
printf '%s\n' \
  $'/usr/bin/secure\troot\troot\t-rwxr-xr-x' \
  $'/usr/bin/secure-desktop\troot\troot\t-rwxr-xr-x' \
  $'/usr/share/applications/dev.usesecure.SecureEngine.desktop\troot\troot\t-rw-r--r--' \
  $'/usr/share/doc/secure-engine\troot\troot\tdrwxr-xr-x' \
  $'/usr/share/doc/secure-engine/README.md\troot\troot\t-rw-r--r--' \
  $'/usr/share/icons/hicolor/scalable/apps/dev.usesecure.SecureEngine.svg\troot\troot\t-rw-r--r--' \
  $'/usr/share/licenses/secure-engine\troot\troot\tdrwxr-xr-x' \
  $'/usr/share/licenses/secure-engine/LICENSE\troot\troot\t-rw-r--r--' \
  $'/usr/share/metainfo/dev.usesecure.SecureEngine.metainfo.xml\troot\troot\t-rw-r--r--' \
  | LC_ALL=C sort >"$expected_ownership"
cmp "$expected_ownership" "$ownership"
rpm -qpi "$rpm_path" >"$target/package-metadata.txt"
rpm -qplv "$rpm_path" >"$target/package-files-detailed.txt"
test "$(rpm -qp --qf '%{NAME}' "$rpm_path")" = secure-engine
test "$(rpm -qp --qf '%{VERSION}' "$rpm_path")" = 0.1.9
test "$(rpm -qp --qf '%{RELEASE}' "$rpm_path")" = 1.fc44
test "$(rpm -qp --qf '%{ARCH}' "$rpm_path")" = x86_64
test "$(rpm -qp --qf '%{LICENSE}' "$rpm_path")" = MIT
test "$(rpm -qp --qf '%{BUILDTIME}' "$rpm_path")" = "$(git -C "$root" show -s --format=%ct HEAD)"

extract="$target/extracted"
rm -rf -- "$extract"
mkdir -p -- "$extract"
(cd "$extract" && rpm2cpio "$rpm_path" | cpio -idm --quiet)
"$extract/usr/bin/secure" --version >"$target/cli-version.txt"
test "$(cat "$target/cli-version.txt")" = "secure 0.1.9"
"$extract/usr/bin/secure" doctor --format secure-json-v1 >"$target/doctor.json"
"$extract/usr/bin/secure" rules list >"$target/rules.json"
"$extract/usr/bin/secure" ai providers >"$target/ai-providers.json"
"$extract/usr/bin/secure" schema print secure-json-v1 >"$target/secure-json-v1.schema.json"
jq -e '.schema_version == "secure-json-v1" and .engine_version == "0.1.9" and .healthy == true' "$target/doctor.json" >/dev/null
jq -e 'length == 7 and map(.rule_id) == ["SE1001", "SE1002", "SE1003", "SE1004", "SE1005", "SE1006", "SE1007"]' "$target/rules.json" >/dev/null
jq -e 'length == 3 and all(.credentials == "none" or .credentials == "environment-only")' "$target/ai-providers.json" >/dev/null
jq -e '.title == "Secure Engine secure-json-v1 document"' "$target/secure-json-v1.schema.json" >/dev/null
desktop-file-validate "$extract/usr/share/applications/dev.usesecure.SecureEngine.desktop"
appstreamcli validate --no-net "$extract/usr/share/metainfo/dev.usesecure.SecureEngine.metainfo.xml"
grep -F '<release version="0.1.9" date="2026-07-22" />' \
  "$extract/usr/share/metainfo/dev.usesecure.SecureEngine.metainfo.xml" >/dev/null

if test "${SECURE_SKIP_DESKTOP_SMOKE:-0}" != 1; then
  test -n "${DISPLAY:-}"
  set +e
  timeout 5s "$extract/usr/bin/secure-desktop" "$root/fixtures/phase5-multilang" >"$target/desktop-smoke.stdout" 2>"$target/desktop-smoke.stderr"
  status=$?
  set -e
  test "$status" -eq 124
  printf 'status=%s\nexpected_timeout_status=124\nduration_seconds=5\n' "$status" \
    >"$target/desktop-smoke-result.txt"
fi

printf '%s\n' "$rpm_path"
