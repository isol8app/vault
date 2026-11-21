# isol8 vault (Android)

The offline signing app of [isol8](https://isol8.app), a Solana cold wallet. It runs on an Android phone that stays offline for good, holds the key, and signs only what it has decoded and shown you. It talks to the isol8.app dashboard through QR codes only ([docs/PROTOCOL.md](../docs/PROTOCOL.md)). The security model is in [docs/SECURITY.md](../docs/SECURITY.md).

Native Kotlin, Android 10 (API 29) or newer, target Android 16 (API 36). Licensed under the GNU GPL v3 ([LICENSE](LICENSE)).

**Public beta, not yet independently audited.**

## Modules

| Module | What it holds |
|---|---|
| `core/` | Pure Kotlin, no runtime dependencies. Base45, QR framing and reassembly, payloads, pairing, signing responses, a strict Solana message parser (legacy and v1) and the acceptance rules (`Acceptance.kt`). Also BIP39 phrases (English) and SLIP-0010 Ed25519 derivation, the settings format and the wrong-passphrase counter. |
| `crypto/` | Ed25519 signing via BouncyCastle, Solana key derivation (`m/44'/501'/i'/0'`), and the passphrase envelope (Argon2id + AES-256-GCM). |
| `qr/` | QR codes for isol8 frames via ZXing core: alphanumeric mode, level M. Every displayed code is test-read first, switching masks if needed. |
| `app/` | The Android app: offline checks, create, restore, unlock and delete, encrypted storage, pairing, reviewing and signing, the address book, the fee-warning setting, Check my backup, the device report and diagnostics. |

`core` and `crypto` mirror the TypeScript reference in [`../protocol/`](../protocol/) file for file, and every rule change is checked by the same shared test vectors.

## The app

- **One permission: `CAMERA`**, for scanning QR codes. There's no `INTERNET` permission, so Android blocks the app from opening any network connection.
- **No AndroidX, Compose or other UI library.** The only third-party runtime libraries are BouncyCastle (in `crypto`) and ZXing core (in `qr`). The UI uses plain framework views; the camera uses Android's Camera2 API, and frames are decoded in memory, never saved.
- **`FLAG_SECURE`:** no screenshots, screen recording or recent-apps previews.
- **No backups:** `allowBackup="false"`, and the data extraction rules exclude everything from cloud backup and device transfer.

### Screens

| Screen | What it does |
|---|---|
| Home | Live offline status: airplane mode on, Wi-Fi, Bluetooth and NFC off, no SIM, USB and wireless debugging off. Vault actions stay disabled until every check passes, and the checks run again before showing words, saving, unlocking and signing. A screen lock is required. Debug builds only: a development override for networked test devices, off at every launch. |
| Create | 24 words from `SecureRandom` (12 if chosen on a screen that explains the choice), shown once. Then a check of 3 random words against your paper, then the vault passphrase. |
| Restore | The word count, then each word through the app's own letter keys and word picker, never the system keyboard. Then a review with tap-to-fix, and an address preview to confirm it's the expected wallet. |
| Check my backup | Type the words from your paper. The vault answers only "matches" or "doesn't match", never which word is wrong, and never shows its own words. |
| Pair | Scans the dashboard's pairing request and shows which site is asking. Release builds pair only with `isol8.app`. The answer is shown as a QR code. |
| Sign | Passphrase first, then scan the request. The review is built only from an accepted decision: warnings first, exact amounts, addresses in groups of four, unknown tokens by mint address. Then **hold to sign** (1.5 s; a tap does nothing). Declining shows a code that tells the dashboard nothing was signed. |
| Address book, fee warning | Saved addresses (names: printable ASCII, 1–32 characters) label recipients and trigger lookalike and near-miss warnings. The fee-warning threshold defaults to 0.01 SOL. Editing either needs the passphrase. |
| Delete | Removes the vault and its Keystore key, after confirming you have your recovery phrase. |
| Device report, diagnostics | Where the key lives (StrongBox, TEE or software), bootloader and verified-boot state from key attestation, OS and patch level, and a tier. Diagnostics shows the app's permissions. |

The vault never shows its recovery phrase again after creation and never exports the private key.

## Storage

The recovery phrase is stored as its BIP39 entropy (16–32 bytes), plus an optional BIP39 passphrase. Two layers, both needed to read it:

| Layer | Code | Protection |
|---|---|---|
| Inner: passphrase envelope | `crypto/VaultEnvelope.kt` | The vault passphrase (at least 8 characters, NFKD-normalized) → **Argon2id**, 64 MiB, 3 passes, 1 lane → **AES-256-GCM**. The 43-byte header (format version, Argon2 parameters, salt, nonce) is authenticated, and stored parameters must stay within safe bounds, so a modified file can't force weak settings. |
| Outer: Keystore wrap | `app/VaultStore.kt` | **AES-256-GCM under an Android Keystore key** in secure hardware (StrongBox if present, otherwise the TEE), usable **only while the device is unlocked**. Written atomically to `noBackupFilesDir`. |

Formats:
- Envelope: `"I8PV" | 1 | 1 | memKiB u32 | iterations u32 | lanes u8 | salt[16] | nonce[12] | ciphertext+tag`.
- Record: `1 | 1 | len | entropy | bip39PassLen u16 | bip39 passphrase`.
- File: `"I8KS" | 1 | ivLen | iv | ciphertext+tag`.

The same Keystore key protects two small files, each with its own purpose in the authenticated data, so neither can be swapped for the other or for the vault:
- **`settings.bin`** (`core/Settings.kt`): `"I8ST" | 1 | threshold u64 | count u16 | entries (address[32] | len u8 | label)`, decoded strictly. A damaged settings file stops signing rather than dropping the address book's checks.
- **`attempts.bin`** (`core/Attempts.kt`): `1 | failures u32 | waitSeconds u32`. Five wrong passphrases are free; after that each one earns a wait of 1, 5 and 30 minutes, then an hour. The wait counts down only while its screen is open, and a right passphrase resets the count.

Removing the screen lock, a factory reset, or Android invalidating the Keystore key makes the vault unreadable by design. Recovery is always from the written-down phrase.

## Enforcement checks

Both run automatically before every APK is packaged, and on `check`, for every build variant:

| Task | Fails the build if |
|---|---|
| `verify<Variant>Permissions` | The **merged** manifest (including anything a library adds) requests a permission outside the allowlist in `app/build.gradle.kts`, or any never-allowed permission such as `INTERNET` |
| `verify<Variant>ForbiddenApis` | Our compiled classes (app, core, crypto and qr) reference network, link-opening, app-launching, broadcast or clipboard APIs (`java/net/`, `android/net/Uri`, `startActivity`, `ACTION_SEND`, `ClipboardManager`, …) |

Limitation: the API scan covers our own code only. The Kotlin standard library, BouncyCastle and ZXing inside the APK may contain `java.net` references that are never called.

## Building and testing

Requirements: **JDK 21**, and for the `app` module the Android SDK (`platforms;android-36` revision 2, `build-tools;36.0.0`) with `sdk.dir` in `local.properties`. The Gradle wrapper downloads Gradle 8.14.3 and checks it against a pinned SHA-256.

```bash
./gradlew :core:test :crypto:test :qr:test
./gradlew :app:assembleDebug
```

The tests read the shared vectors in [`../protocol/vectors/`](../protocol/vectors/), generated by the TypeScript reference. The Kotlin core must match it byte for byte: frames, payloads, pairing and transaction signatures, and the vault's decision (accept summary or decline reason) for every transaction and swap case. They also fuzz the evaluator with corrupted and random messages. Test-vector sources are recorded in `core/src/test/resources/PROVENANCE.md`.

Release builds are reproducible and are signed offline: see [release/README.md](release/README.md), which also explains how to check a published APK against your own build.

### Trying it on a test device

Use a **test device only**, with test keys. A device that's been connected to a computer with debugging on should never become a real vault.

1. Developer options → **Wireless debugging** on → **Pair device with pairing code**, then `adb pair <ip>:<pairing-port>` and type the code. It authorizes control of the device: treat it like a password.
2. `adb connect <ip>:<port>`, with the port from the main Wireless debugging screen.
3. `./gradlew :app:installDebug`.

Debug builds warn that they're for test keys only, accept other pairing origins with a warning, and have the development override. `FLAG_SECURE` makes the app's window black in screenshots; `adb shell uiautomator dump` reports on-screen text.

## Design rules

- **`core` has no runtime dependencies:** only the Kotlin standard library and JDK APIs that Android also has. Test-only libraries (JUnit, org.json) never ship.
- **Ed25519 is an interface** (`Ed25519Signer`). `crypto` implements it with BouncyCastle; the `core` tests use the JDK's built-in Ed25519.
- **BIP39 uses its own PBKDF2-HMAC-SHA512 over exact UTF-8 bytes,** not the platform's `PBKDF2WithHmacSHA512`, whose character-to-byte conversion isn't guaranteed to match across JDK and Android versions.
- **The BIP39 wordlist** ships as a resource and is checked against its published SHA-256 when first loaded.
- **BouncyCastle (`bcprov-jdk18on` 1.80) through its lightweight API only,** never registered as a JCA provider, so it can't clash with Android's internal copy.
- **Key material is wiped where the code controls it** (entropy, seeds, SLIP-0010 nodes). BouncyCastle keeps its own copy of a private key, and Kotlin `String`s can't be wiped reliably, so signers are short-lived and secrets are dropped on every screen change.
- **Cross-checks:**
  - RFC 8032 vectors;
  - random keys signed by both BouncyCastle and the JDK's Ed25519;
  - SLIP-0010 public keys;
  - full derivation (phrase → seed → path → address → signature) against `protocol/vectors/keys.json`, generated with Node's own crypto;
  - Argon2id against RFC 9106, and envelopes against `protocol/vectors/envelopes.json`.

## Supply chain

- `gradle/wrapper/gradle-wrapper.properties` pins the Gradle distribution's SHA-256, which matches Gradle's published checksum, as does the wrapper jar.
- `gradle/verification-metadata.xml` pins the SHA-256 of every build and test dependency, so a swapped artifact fails the build. These checksums were recorded on first download. Review changes to this file like code.
- To update a dependency: change the version, run `./gradlew --write-verification-metadata sha256 :core:test`, and review the diff.
