#!/usr/bin/env bash
# Builds the unsigned release APK of the isol8 vault from a git tag, in a clean clone.
#
#   release/build.sh vault-v0.1.0                         # in the dev qube, from this repository
#   release/build.sh vault-v0.1.0 --source <file.bundle>  # in a build disposable, from a git bundle
#   release/build.sh main --dry-run                       # any branch or commit, for testing the pipeline
#
# Run it twice, in two different qubes (the dev qube and a fresh build disposable). Both must print the same
# SHA-256 before the release qube signs the APK (release/sign.sh asks for the other build's hash).
# Never signs anything: no key exists where this runs. See release/README.md.
set -euo pipefail

usage() { echo "usage: $0 <tag> [--source <repository or bundle>] [--dry-run]   or   $0 --fetch-jdk" >&2; exit 2; }

# The pinned toolchain. Changing any of these can change the APK's bytes, so it's a release decision.
JDK_NAME="jdk-21.0.13.1+2" # Eclipse Temurin 21.0.13.1, Linux x64
JDK_URL="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13.1%2B2/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13.1_2.tar.gz"
JDK_SHA256="bb8a93f9ae6e7a693b2b721e85dbeff26ae1a77447985a8d7afcdd9c7cf6222e" # checked with Adoptium's signature, 2026-11-20
ANDROID_JAR_SHA256="d9eb9da824d9e247a352f570f01e1169e725b2954bca9e283a71786c59b59f9a" # platforms;android-36, revision 2

ref="" source="" dry_run=0 fetch_jdk=0
while [ $# -gt 0 ]; do
  case "$1" in
    --source) [ $# -ge 2 ] || usage; source="$2"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --fetch-jdk) fetch_jdk=1; shift ;;
    -*) usage ;;
    *) [ -z "$ref" ] || usage; ref="$1"; shift ;;
  esac
done
[ "$(uname -m)" = x86_64 ] || { echo "Builds are pinned to Linux x86_64 (got $(uname -m))." >&2; exit 1; }

# A fixed place, so every build of a release runs from the same path.
base="$HOME/isol8-release"

# The JDK: downloaded once, checked against the pinned SHA-256, kept in ~/isol8-release/jdk.
jdk="$base/jdk/$JDK_NAME"
if [ ! -x "$jdk/bin/java" ]; then
  echo "Downloading $JDK_NAME ..."
  mkdir -p "$base/jdk"
  tarball="$base/jdk/$JDK_NAME.tar.gz"
  curl -fsSL -o "$tarball" "$JDK_URL"
  [ "$(sha256sum "$tarball" | cut -d' ' -f1)" = "$JDK_SHA256" ] || { rm -f -- "$tarball"; echo "The JDK download doesn't match its pinned SHA-256: refusing." >&2; exit 1; }
  tar -xzf "$tarball" -C "$base/jdk"
  rm -f -- "$tarball"
fi
export JAVA_HOME="$jdk" PATH="$jdk/bin:$PATH"
if [ "$fetch_jdk" -eq 1 ]; then [ -z "$ref" ] || usage; echo "JDK ready: $jdk"; exit 0; fi
[ -n "$ref" ] || usage

here="$(cd "$(dirname "$0")" && pwd)"
[ -n "$source" ] || source="$(git -C "$here" rev-parse --show-toplevel)"
sdk="${ANDROID_HOME:-$HOME/Android/Sdk}"
build_tools="$sdk/build-tools/36.0.0"
[ -x "$build_tools/aapt2" ] || { echo "Android SDK build-tools 36.0.0 not found in $sdk (set ANDROID_HOME)." >&2; exit 1; }
[ "$(sha256sum "$sdk/platforms/android-36/android.jar" 2>/dev/null | cut -d' ' -f1)" = "$ANDROID_JAR_SHA256" ] \
  || { echo "$sdk/platforms/android-36 isn't revision 2 (android.jar doesn't match its pinned SHA-256)." >&2; exit 1; }

work="$base/build"
out="$base/out"
mkdir -p "$out"
rm -rf -- "${work:?}"

echo "Cloning $source ..."
git -c init.defaultBranch=main clone --quiet --no-checkout -- "$source" "$work"
if [ "$dry_run" -eq 1 ]; then
  commit="$(git -C "$work" rev-parse --verify --quiet "$ref^{commit}" || git -C "$work" rev-parse --verify "origin/$ref^{commit}")"
else
  case "$ref" in vault-v*) ;; *) echo "Release tags look like vault-v1.2.3 (got '$ref'). For a test, add --dry-run." >&2; exit 1 ;; esac
  commit="$(git -C "$work" rev-parse --verify "refs/tags/$ref^{commit}")" \
    || { echo "No tag '$ref' in $source." >&2; exit 1; }
fi
git -C "$work" -c advice.detachedHead=false checkout --quiet --detach "$commit"

gradle="$work/vault-android/app/build.gradle.kts"
version_name="$(sed -n 's/^ *versionName = "\(.*\)".*/\1/p' "$gradle")"
version_code="$(sed -n 's/^ *versionCode = \([0-9]*\).*/\1/p' "$gradle")"
if [ "$dry_run" -eq 0 ]; then
  [ "$ref" = "vault-v$version_name" ] || { echo "Tag $ref doesn't match versionName $version_name in app/build.gradle.kts." >&2; exit 1; }
  case "$version_name" in *-*) echo "versionName $version_name is a pre-release (has a '-'); release versions are plain, like 1.2.3." >&2; exit 1 ;; esac
fi

echo "sdk.dir=$sdk" > "$work/vault-android/local.properties"
echo "Building $version_name ($version_code) from $commit ..."
# assembleRelease runs the permission and forbidden-API checks first (app/build.gradle.kts); the unit tests too.
if ! (cd "$work/vault-android" && ./gradlew --no-daemon --no-build-cache --quiet \
  :core:test :crypto:test :qr:test :app:assembleRelease) 2>&1 | { grep -v "only understands SDK XML versions up to 3" || true; }; then
  echo "Build failed." >&2; exit 1
fi
apk="$work/vault-android/app/build/outputs/apk/release/app-release-unsigned.apk"
[ -f "$apk" ] || { echo "Build failed: no APK." >&2; exit 1; }

# The APK must be the vault, not debuggable, and ask for the camera only.
badging="$("$build_tools/aapt2" dump badging "$apk")"
grep -q "^package: name='app.isol8.vault' versionCode='$version_code' versionName='$version_name'" <<<"$badging" \
  || { echo "Unexpected package line: $(head -1 <<<"$badging")" >&2; exit 1; }
if grep -q "application-debuggable" <<<"$badging"; then echo "The APK is debuggable: refusing." >&2; exit 1; fi
perms="$(grep "^uses-permission:" <<<"$badging" || true)"
[ "$perms" = "uses-permission: name='android.permission.CAMERA'" ] || { echo "Unexpected permissions: $perms" >&2; exit 1; }

name="isol8-vault-$version_name"
[ "$dry_run" -eq 0 ] || name="$name-DRYRUN-${commit:0:12}"
cp -- "$apk" "$out/$name-unsigned.apk"
hash="$(sha256sum "$out/$name-unsigned.apk" | cut -d' ' -f1)"
echo "$hash  $name-unsigned.apk" > "$out/$name-unsigned.apk.sha256"

cat <<EOF

Built   $out/$name-unsigned.apk
Commit  $commit
Version $version_name ($version_code)
Java    $(java -version 2>&1 | head -1)
SHA-256 $hash

Compare this SHA-256 with the other build's. Sign only if they're identical.
EOF
