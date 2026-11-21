# Test vector provenance

Downloaded 2026-11-13 from the upstream repositories' `master` branches, then converted to JSON (English BIP39 cases; SLIP-0010 Ed25519 sets only). The conversion keeps the values unchanged.

| File | Source | Notes |
|---|---|---|
| `bip39-vectors.json` | https://github.com/trezor/python-mnemonic/blob/master/vectors.json | The 24 English cases. Passphrase `TREZOR`, as in the source. |
| `slip10-ed25519.json` | https://github.com/satoshilabs/slips/blob/master/slip-0010.md | Test vectors 1 and 2 for ed25519, 6 paths each. |
| `../../main/resources/app/isol8/vault/core/bip39-english.txt` | https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt | SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`, checked at download and again by the app at runtime. |
