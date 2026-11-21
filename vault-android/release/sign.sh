#!/usr/bin/env bash
# Signs an unsigned release APK of the isol8 vault. Run in the offline release qube only.
#
#   sign.sh isol8-vault-1.2.3-unsigned.apk          # with the release key
#   sign.sh isol8-vault-...-DRYRUN-...apk --test    # with the throwaway test key
#
# It refuses to sign unless the APK's SHA-256 matches the hash you paste from the other, independent build,
# and it only runs the apksigner.jar whose hash is pinned below (from Google's build-tools 36.0.0).
# Read this whole file before using it: it runs next to the key.
set -euo pipefail

APKSIGNER_SHA256="3716d9311e55d2b0918a2fd9d54ba9e406c5f6abeea700b287f11259bc163dec" # build-tools_r36_linux.zip, lib/apksigner.jar

usage() { echo "usage: $0 <unsigned.apk> [--test]" >&2; exit 2; }
[ $# -ge 1 ] && [ $# -le 2 ] || usage
in="$1"
key="release"
if [ $# -eq 2 ]; then [ "$2" = --test ] || usage; key="test"; fi

# Refuse to run anywhere with a network interface up (loopback aside).
for dev in /sys/class/net/*; do
  [ "$(basename "$dev")" = lo ] && continue
  if [ "$(cat "$dev/operstate" 2>/dev/null)" != down ]; then
    echo "This qube has a network interface ($(basename "$dev")). Signing happens in the offline release qube only." >&2
    exit 1
  fi
done

base="$HOME/isol8-release"
ks="$base/keys/isol8-vault-$key.p12"
jar="$base/tools/apksigner.jar"
[ -f "$ks" ] || { echo "No key at $ks (release/new-key.sh makes it)." >&2; exit 1; }
[ "$(sha256sum "$jar" | cut -d' ' -f1)" = "$APKSIGNER_SHA256" ] || { echo "$jar isn't the pinned apksigner: refusing." >&2; exit 1; }

file="$(basename "$in")"
case "$file" in
  isol8-vault-*-unsigned.apk) ;;
  *) echo "Expected a file named isol8-vault-<version>-unsigned.apk (from release/build.sh)." >&2; exit 1 ;;
esac
case "$file" in
  *DRYRUN*) [ "$key" = test ] || { echo "Dry-run builds are signed with the test key only (add --test)." >&2; exit 1; } ;;
  *) [ "$key" = release ] || { echo "Use --test only for dry-run builds." >&2; exit 1; } ;;
esac

hash="$(sha256sum "$in" | cut -d' ' -f1)"
echo "This APK:  $hash"
read -r -p "Paste the SHA-256 the other build printed: " other
other="$(tr -d '[:space:]' <<<"$other" | tr 'A-F' 'a-f')"
[ "$other" = "$hash" ] || { echo "The hashes differ: the two builds don't match. Not signing." >&2; exit 1; }

mkdir -p "$base/signed"
name="${file%-unsigned.apk}"
[ "$key" = release ] || name="$name-TESTKEY"
out="$base/signed/$name.apk"
[ ! -e "$out" ] || { echo "$out already exists." >&2; exit 1; }

# No v1 (the vault needs Android 10+). apksigner writes v3, and v2 only if some supported Android needs it
# (with minSdk 29 none does). --alignment-preserved: the build is already aligned, and apksigner then only
# inserts the signing block, so anyone can strip it and get back the exact build (release/verify.sh).
# It asks for the password itself.
java -jar "$jar" sign --ks "$ks" --ks-key-alias isol8-vault --alignment-preserved \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false \
  --out "$out" "$in"

# The signed APK minus its signing block must be the unsigned build, byte for byte.
here="$(cd "$(dirname "$0")" && pwd)"
check="$(mktemp)"
python3 -I "$here/apk-unsign.py" "$out" "$check"
[ "$(sha256sum "$check" | cut -d' ' -f1)" = "$hash" ] || { rm -f -- "$check" "$out"; echo "Stripping the signature doesn't give back the build: not publishing this." >&2; exit 1; }
rm -f -- "$check"

certs="$(java -jar "$jar" verify --verbose --print-certs "$out")"
grep -E "Verified using v[23]|SHA-256 digest" <<<"$certs"
signed_hash="$(sha256sum "$out" | cut -d' ' -f1)"
echo "$signed_hash  $name.apk" > "$out.sha256"

cat <<EOF

Signed  $out
SHA-256 $signed_hash

Check the certificate's SHA-256 digest above is the one you recorded when the key was made.
Copy out only the signed APK and its .sha256 (qvm-copy). Never copy the key out of this qube.
EOF
