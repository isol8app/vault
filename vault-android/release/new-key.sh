#!/usr/bin/env bash
# Creates the vault's app-signing key. Run once, in the offline release qube only.
#
#   new-key.sh          # the real release key (isol8-vault-release.p12)
#   new-key.sh --test   # a throwaway key, for trying the pipeline (isol8-vault-test.p12)
#
# keytool asks for the password; it never appears on a command line. See release/README.md for backups:
# if this key is lost, no update to the vault can ever be installed over the existing app.
set -euo pipefail

case "${1:-}" in
  "") key="release" ;;
  --test) key="test" ;;
  *) echo "usage: $0 [--test]" >&2; exit 2 ;;
esac

# Refuse to run anywhere with a network interface up (loopback aside).
for dev in /sys/class/net/*; do
  [ "$(basename "$dev")" = lo ] && continue
  if [ "$(cat "$dev/operstate" 2>/dev/null)" != down ]; then
    echo "This qube has a network interface ($(basename "$dev")). Keys are made in the offline release qube only." >&2
    exit 1
  fi
done

dir="$HOME/isol8-release/keys"
ks="$dir/isol8-vault-$key.p12"
mkdir -p "$dir"
chmod 700 "$dir"
[ ! -e "$ks" ] || { echo "$ks already exists. Never replace the release key: the app could no longer be updated." >&2; exit 1; }

# The certificate is public (anyone can read it from the APK), so it names isol8 only, never a person.
cn="isol8"
[ "$key" = test ] && cn="isol8 TEST key - not for release"
keytool -genkeypair -keystore "$ks" -storetype PKCS12 -alias isol8-vault \
  -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=$cn"
chmod 600 "$ks"

echo
keytool -list -v -keystore "$ks" -alias isol8-vault | grep -E "Owner|Valid|SHA256:"
echo
echo "Created $ks"
[ "$key" = test ] || echo "Back it up now (release/README.md, 'Back up the key'), and record the SHA256 fingerprint above."
