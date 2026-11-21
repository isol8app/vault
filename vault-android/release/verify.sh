#!/usr/bin/env bash
# Checks that an isol8 vault APK is exactly what this source code builds, signed with isol8's release key.
#
#   release/verify.sh isol8-vault-1.2.3.apk
#
# It reads the version from the APK, builds tag vault-v<version> from source with the pinned toolchain
# (release/build.sh), removes the APK's signature (release/apk-unsign.py), and compares the two byte for byte.
# Needs: Linux x86_64, git, curl, python3, and the Android SDK (platforms;android-36 revision 2,
# build-tools;36.0.0). See release/README.md, "Verify an APK yourself".
set -euo pipefail

# isol8's release key: the SHA-256 of its certificate (release/README.md, "The release key").
RELEASE_CERT_SHA256="f1e1bfba75379ac37ce033c534370a294fd0341b10fceb0bb567fbd8b807c805"

usage() { echo "usage: $0 <isol8-vault-*.apk> [--source <repository or bundle>]" >&2; exit 2; }
[ $# -eq 1 ] || [ $# -eq 3 ] || usage
apk="$(realpath "$1")"
source_args=()
if [ $# -eq 3 ]; then [ "$2" = --source ] || usage; source_args=(--source "$3"); fi
[ -f "$apk" ] || { echo "No file $1." >&2; exit 1; }

here="$(cd "$(dirname "$0")" && pwd)"
sdk="${ANDROID_HOME:-$HOME/Android/Sdk}"
build_tools="$sdk/build-tools/36.0.0"
[ -x "$build_tools/apksigner" ] || { echo "Android SDK build-tools 36.0.0 not found in $sdk (set ANDROID_HOME)." >&2; exit 1; }

# 1. The signature: valid, and made by isol8's release key.
certs="$("$build_tools/apksigner" verify --verbose --print-certs "$apk")" || { echo "FAIL: the APK's signature doesn't verify." >&2; exit 1; }
signers="$(grep -c "^Signer #[0-9]* certificate SHA-256 digest" <<<"$certs" || true)"
cert="$(sed -n 's/^Signer #1 certificate SHA-256 digest: //p' <<<"$certs")"
[ "$signers" = 1 ] && [ "$cert" = "$RELEASE_CERT_SHA256" ] \
  || { echo "FAIL: not signed by isol8's release key (certificate SHA-256: ${cert:-none})." >&2; exit 1; }
echo "Signature: valid, isol8's release key ($cert)."

# 2. The version, so we know which tag to build.
version="$("$build_tools/aapt2" dump badging "$apk" | sed -n "s/^package: name='app.isol8.vault' .*versionName='\([^']*\)'.*/\1/p")"
[ -n "$version" ] || { echo "FAIL: this isn't the isol8 vault (package app.isol8.vault)." >&2; exit 1; }
echo "Version:   $version, building tag vault-v$version from source ..."
echo

# 3. Build that tag, and compare it with the APK minus its signature.
"$here/build.sh" "vault-v$version" "${source_args[@]}"
built="$HOME/isol8-release/out/isol8-vault-$version-unsigned.apk"
stripped="$(mktemp)"
trap 'rm -f -- "$stripped"' EXIT
python3 -I "$here/apk-unsign.py" "$apk" "$stripped"
want="$(sha256sum "$built" | cut -d' ' -f1)"
got="$(sha256sum "$stripped" | cut -d' ' -f1)"
echo
if [ "$got" = "$want" ]; then
  echo "VERIFIED: $(basename "$apk") is isol8 vault $version, built from tag vault-v$version, byte for byte"
  echo "          (unsigned SHA-256 $want), and signed by isol8's release key."
else
  echo "FAIL: the APK differs from the build of tag vault-v$version." >&2
  echo "      APK without its signature: $got" >&2
  echo "      Built from source:         $want" >&2
  exit 1
fi
