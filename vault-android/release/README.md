# Release builds and signing

The vault's app-signing key decides who can update the vault on every user's phone. A leaked key lets someone push a fake vault update; a lost key means no update can ever install over the existing app. So the key lives in one offline qube, and nothing there signs an APK unless two separate builds of it match exactly.

| Qube | Network | Holds | Does |
|---|---|---|---|
| `dev` (existing) | yes | the code | build 1, from the tag |
| `isol8-build-dvm` (disposable template) | yes, for Gradle downloads (all checked against `gradle/verification-metadata.xml`) | the Android SDK and the pinned JDK only | build 2, in a fresh disposable each time, from a git bundle of the tag |
| `isol8-release` | **none** | the key, `apksigner.jar`, `sign.sh`, `apk-unsign.py`, `new-key.sh` | checks build 2's SHA-256 equals build 1's, then signs |

Builds are reproducible, by us and by anyone: `build.sh` pins the toolchain (Eclipse Temurin JDK 21.0.13.1, downloaded and checked against its SHA-256; Android platform 36 revision 2; build-tools 36.0.0; Gradle and every dependency by checksum), and two clean builds of the same commit give byte-identical unsigned APKs, even from different folders and qubes (checked 2026-11-20). If one build environment were tampered with, the hashes would differ and `sign.sh` refuses. Signing only adds the signature, so anyone can remove it again and compare the published APK with their own build ("Verify an APK yourself" below).

Scripts:
- `build.sh <tag>`: the pinned JDK (downloaded once into `~/isol8-release/jdk`), clean clone at `~/isol8-release/build`, unit tests, `assembleRelease` (with the permission and forbidden-API checks), then checks the APK: package `app.isol8.vault`, version matching the tag, not debuggable, camera the only permission. Prints the SHA-256. Release builds skip lint, so they download fewer tools; lint stays a dev check.
- `new-key.sh`: makes the key (RSA 4096, PKCS12, valid ~27 years; the certificate says `CN=isol8`, no personal name, since anyone can read it from the APK). Refuses to run with a network interface up.
- `sign.sh <unsigned.apk>`: asks for the other build's hash, refuses on mismatch, runs only the pinned `apksigner.jar`, signs (v3 signature; no v1 needed for Android 10+; the build's alignment preserved, so signing only adds a signing block), checks that removing the signature gives back the build byte for byte, verifies, prints the certificate digest and the signed APK's SHA-256. Refuses to run with a network interface up.
- `apk-unsign.py`: removes the signing block (and the zero padding apksigner puts before it), giving back the unsigned build. Used by `sign.sh` and `verify.sh`.
- `verify.sh <apk>`: for anyone. Checks the signature is isol8's release key, builds the tag matching the APK's version, and compares it with the APK minus its signature.

## The release key

Made 2026-11-20. Its certificate's SHA-256 fingerprint, which every official vault APK is signed with:

```
F1:E1:BF:BA:75:37:9A:C3:7C:E0:33:C5:34:37:0A:29:4F:D0:34:1B:10:FC:EB:0B:B5:67:FB:D8:B8:07:C8:05
```

(`apksigner verify --print-certs` shows it as `f1e1bfba75379ac37ce033c534370a294fd0341b10fceb0bb567fbd8b807c805`.) Anyone can check an APK against it; publish it on the site and in each release's notes. Any other fingerprint is not an official isol8 vault.

## One-time setup

**1. Create the qubes (dom0 terminal):**

```bash
qvm-create --class AppVM --template debian-13-xfce --label black isol8-release
```

```bash
qvm-prefs isol8-release netvm ''
```

```bash
qvm-prefs isol8-release default_dispvm ''
```

```bash
qvm-create --class AppVM --template debian-13-xfce --label orange isol8-build-dvm
```

```bash
qvm-prefs isol8-build-dvm template_for_dispvms True
```

```bash
qvm-volume resize isol8-build-dvm:private 6GiB
```

(A build needs about 2 GB on top of the SDK and JDK; each disposable gets the template's size.)

Check `qvm-prefs isol8-release netvm` prints nothing. Never give `isol8-release` a network, and never attach USB devices to it.

**2. Android SDK in `isol8-build-dvm`** (a terminal in that qube; changes to its home carry into every disposable made from it). The same pinned versions as the dev qube, downloaded fresh rather than copied from dev, so build 2 doesn't share dev's toolchain files:

```bash
mkdir -p ~/Android/downloads ~/Android/tmp ~/Android/Sdk/cmdline-tools && cd ~/Android/downloads && curl -fO https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip && echo "4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583  commandlinetools-linux-15859902_latest.zip" | sha256sum -c
```

Only if it prints `OK`:

```bash
unzip -q ~/Android/downloads/commandlinetools-linux-15859902_latest.zip -d ~/Android/tmp && mv ~/Android/tmp/cmdline-tools ~/Android/Sdk/cmdline-tools/latest && export SDKMANAGER_OPTS="-Djava.io.tmpdir=$HOME/Android/tmp" && ~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=$HOME/Android/Sdk --licenses
```

(accept the Android SDK License only), then:

```bash
~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=$HOME/Android/Sdk "platforms;android-36" "build-tools;36.0.0"
```

And the pinned JDK, so each disposable doesn't download it again:

```bash
mkdir -p ~/isol8-release/jdk && cd ~/isol8-release/jdk && curl -fLO https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13.1%2B2/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13.1_2.tar.gz && echo "bb8a93f9ae6e7a693b2b721e85dbeff26ae1a77447985a8d7afcdd9c7cf6222e  OpenJDK21U-jdk_x64_linux_hotspot_21.0.13.1_2.tar.gz" | sha256sum -c && tar -xzf OpenJDK21U-*.tar.gz && rm OpenJDK21U-*.tar.gz
```

Then shut it down (dom0: `qvm-shutdown --wait isol8-build-dvm`): disposables start from its last saved state, so until it shuts down they don't see the SDK.

**3. Tools into `isol8-release`.** From `dev`, in the repository:

```bash
qvm-copy vault-android/release/sign.sh vault-android/release/apk-unsign.py vault-android/release/new-key.sh ~/Android/Sdk/build-tools/36.0.0/lib/apksigner.jar
```

Pick `isol8-release` in the dialog. Then in `isol8-release`:

```bash
mkdir -p ~/isol8-release/tools && mv ~/QubesIncoming/dev/{sign.sh,apk-unsign.py,new-key.sh,apksigner.jar} ~/isol8-release/tools/ && chmod +x ~/isol8-release/tools/*.sh
```

**Read `sign.sh`, `apk-unsign.py` and `new-key.sh` in full there** (they're short): they run next to the key, and they came from the networked dev qube. `apksigner.jar` doesn't need reading: `sign.sh` refuses any copy whose SHA-256 isn't the one pinned in it, from Google's build-tools 36.0.0 zip (checked against Google's published checksum, 2026-11-20). Whenever these scripts change in the repository, copy them again and re-read the diff.

**4. Dry run first**, to test the qubes without the real key: follow "Each release" below with `build.sh main --dry-run` in both builds, `new-key.sh --test` once, and `sign.sh <file> --test`. The test key is a throwaway; never publish its fingerprint.

**5. The release key** (in `isol8-release`):

```bash
~/isol8-release/tools/new-key.sh
```

Use a long, random passphrase, stored offline. Write down the **SHA256 fingerprint** it prints: it's public, and goes on the site, in each release's notes and in Google's developer verification.

**6. Back up the key** before signing anything with it, in encrypted offline backups, and check a backup restores. The keystore is passphrase-protected on its own too, but treat every copy as the key. If both the key and its backups are lost, users have to uninstall the vault and restore from their recovery phrase to take any update.

## Each release

1. **dev:** set `versionCode` (one higher) and `versionName` (`1.2.3`, no `-dev`) in `app/build.gradle.kts` and commit. Releases are built from the **public repository**, so the tag outsiders verify is exactly what was signed: export the vault to it, commit there, tag `vault-v1.2.3`, and push the commit and tag. Commit and tag in UTC there (`TZ=UTC git commit`, `TZ=UTC git tag -a vault-v1.2.3 -m "isol8 vault 1.2.3"`), so no local timezone gets published.
2. **dev, build 1:** in the public repository's checkout, `vault-android/release/build.sh vault-v1.2.3` (≈ 2 minutes). Note the SHA-256 and commit.
3. **dev:** `git bundle create ~/isol8-release/out/vault-v1.2.3.bundle vault-v1.2.3`, open a terminal in a new **isol8-build-dvm disposable** (app menu), and `qvm-copy ~/isol8-release/out/vault-v1.2.3.bundle` to it.
4. **disposable, build 2:**

   ```bash
   B=~/QubesIncoming/dev/vault-v1.2.3.bundle && git clone -q -b vault-v1.2.3 $B ~/src && ~/src/vault-android/release/build.sh vault-v1.2.3 --source $B
   ```

   Its SHA-256 must equal build 1's. Then `qvm-copy ~/isol8-release/out/isol8-vault-1.2.3-unsigned.apk` to `isol8-release`, and close the disposable.
5. **isol8-release:** `~/isol8-release/tools/sign.sh ~/QubesIncoming/disp*/isol8-vault-1.2.3-unsigned.apk`, paste build 1's SHA-256 (Qubes clipboard from dev), type the key passphrase. Check the certificate digest is the one recorded at step 5 of setup.
6. **isol8-release:** `qvm-copy ~/isol8-release/signed/isol8-vault-1.2.3.apk ~/isol8-release/signed/isol8-vault-1.2.3.apk.sha256` to dev. Install it on a test phone before publishing.
7. **dev:** `vault-android/release/verify.sh ~/QubesIncoming/isol8-release/isol8-vault-1.2.3.apk`: the same check anyone can run. Publish the APK, its SHA-256, the release key's fingerprint and the tag together.

Phones with a dev or test-key build installed must uninstall it first: Android won't update an app across signing keys (and uninstalling deletes that phone's test vault).

## What this does and doesn't cover

- **Covers:** the key never on a networked qube; a tampered build environment (dev's or the disposable's) shows up as a hash mismatch; a tampered `apksigner.jar` is refused; a debuggable or over-permissioned APK is refused.
- **Doesn't cover:** malicious code committed in dev. Both builds faithfully build the same source, so the defence there is review and the audit; compare the commit `build.sh` prints with the published tag.
- **Anyone can check a published APK** (below): a release that doesn't match its tagged source, or isn't signed by the release key, fails `verify.sh`.

## Verify an APK yourself

Anyone can check that an isol8 vault APK was built from this source code, unchanged, and signed by isol8's release key. On Linux x86_64, with `git`, `curl`, `unzip` and `python3`:

1. Get the source: clone isol8's public vault repository (linked from [isol8.app/security](https://isol8.app/security/)).
2. Get the pinned JDK (Eclipse Temurin 21.0.13.1; `build.sh` checks its SHA-256):

   ```bash
   vault-android/release/build.sh --fetch-jdk && export JAVA_HOME=~/isol8-release/jdk/jdk-21.0.13.1+2 PATH=~/isol8-release/jdk/jdk-21.0.13.1+2/bin:$PATH
   ```

3. Get the Android SDK parts the build uses (Google's command-line tools, checked against their SHA-256, then `sdkmanager`, which checks each package against Google's repository):

   ```bash
   mkdir -p ~/Android/downloads ~/Android/Sdk/cmdline-tools && cd ~/Android/downloads && curl -fO https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip && echo "4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583  commandlinetools-linux-15859902_latest.zip" | sha256sum -c && unzip -q commandlinetools-linux-15859902_latest.zip -d ~/Android/Sdk/cmdline-tools && mv ~/Android/Sdk/cmdline-tools/cmdline-tools ~/Android/Sdk/cmdline-tools/latest && cd -
   ```

   ```bash
   ~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=$HOME/Android/Sdk "platforms;android-36" "build-tools;36.0.0"
   ```

   (It asks you to accept the Android SDK License.)
4. Verify:

   ```bash
   vault-android/release/verify.sh ~/Downloads/isol8-vault-1.2.3.apk
   ```

It checks the signature is isol8's release key (the fingerprint above), builds the tag `vault-v<version>` read from the APK (a few minutes the first time: Gradle downloads every dependency and checks each against `vault-android/gradle/verification-metadata.xml`), removes the APK's signature and compares the two. `VERIFIED` means the APK is exactly that tag's code; anything else prints `FAIL` and why. Read `verify.sh`, `build.sh` and `apk-unsign.py` first if you like: they're short, and they never touch your phone.
