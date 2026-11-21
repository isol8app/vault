# isol8 vault

[isol8](https://isol8.app) is a Solana cold wallet built from an old Android phone. This repository holds the part you have to trust: the **vault**, an Android app that runs on a phone kept offline for good, holds your key, and signs only what it has decoded and shown you. It talks to the isol8.app dashboard through QR codes only.

**Public beta, not yet independently audited.** Keep only amounts you could afford to lose in a vault until it is.

| Path | What | Licence |
|---|---|---|
| [`vault-android/`](vault-android/) | The vault app (Kotlin, Android 10+) and its reproducible release process | [GPL-3.0](vault-android/LICENSE) |
| [`protocol/`](protocol/) | The QR protocol's TypeScript reference: framing, payloads, the vault's acceptance rules, and the shared test vectors every implementation must match | [Apache-2.0](protocol/LICENSE) |
| [`docs/`](docs/) | [PROTOCOL.md](docs/PROTOCOL.md) (the spec), [SECURITY.md](docs/SECURITY.md) (the security model), [SWAPS.md](docs/SWAPS.md) (signing Jupiter swaps) | Apache-2.0 |

The isol8.app dashboard and server aren't here. They don't need to be trusted: they hold no keys, and the vault decodes every transaction itself before you sign.

## Verify a release

Every vault release is built twice, independently, and signed offline only if the two builds match byte for byte. You can rebuild any release tag and check that a published APK is exactly that code plus isol8's signature: see [vault-android/release/README.md](vault-android/release/README.md#verify-an-apk-yourself). Release certificate SHA-256:

```
F1:E1:BF:BA:75:37:9A:C3:7C:E0:33:C5:34:37:0A:29:4F:D0:34:1B:10:FC:EB:0B:B5:67:FB:D8:B8:07:C8:05
```

## Build and test

```bash
cd protocol && npm test                          # the reference rules and vectors (Node 24, no dependencies)
cd ../vault-android && ./gradlew :core:test      # the vault core against the same vectors (JDK 21)
```

Details: [vault-android/README.md](vault-android/README.md).

## Security

Report vulnerabilities to **security@isol8.app**, not in a public issue. Official accounts and downloads are listed on [isol8.app](https://isol8.app).
