# isol8 vault: security model

How the isol8 vault protects a Solana key, what it relies on, and what it can't protect against. This repository holds the vault app (`vault-android/`) and the protocol it speaks (`protocol/`, [PROTOCOL.md](PROTOCOL.md)). The isol8.app dashboard and server are not in it, and they don't need to be trusted.

**Status: public beta, not yet independently audited.** Until it is, keep only amounts you could afford to lose in a vault.

## The one thing you trust

isol8 splits a wallet in two:
- **The vault:** this app, on an Android phone that stays offline for good. It holds the key.
- **The dashboard:** isol8.app, on any phone or computer. It shows balances and prepares transactions.

The two meet only through QR codes. The dashboard shows a transaction as a QR code; the vault scans it, decodes it itself, shows what it will do, and signs only after you hold to sign. Its answer goes back as another QR code.

Everything except the vault is treated as untrusted: the dashboard, isol8's servers, your computer, your browser, and the QR channel. None of them holds the key, and none of them can get a transaction past the vault without you seeing what it really does. So the question this design must answer is: **what happens if everything except the vault lies?** The sections below answer it.

## The vault phone, in layers

Anything networked on a phone is attack surface, whatever an app does. So the vault is protected in layers, outermost first, each assuming the one before it failed.

| Layer | Protection | Enforced by |
|---|---|---|
| 1. The phone is offline, permanently | Airplane mode on, no SIM or eSIM, Wi-Fi, Bluetooth and NFC off, never online again after setup | You, with the vault's checks: it refuses to create, restore, unlock or sign while any of these is wrong |
| 2. The phone is clean | Factory reset, no accounts, no other apps, USB debugging off | You, guided by setup; the device report shows what it can measure |
| 3. The app can't open network connections | No `INTERNET` permission, so Android blocks its sockets | Android; the build fails if any permission outside the allowlist (`CAMERA` only) appears |
| 4. The app never hands data to other apps | No links, sharing, or launching other apps | The build scans compiled classes for network, link and inter-app APIs |
| 5. The key is encrypted at rest | Two layers: your vault passphrase, and a key in the phone's secure hardware | The app (below) |
| 6. Clear signing | The vault shows exactly what each transaction does | The app's acceptance rules ([PROTOCOL.md §6](PROTOCOL.md)) |

The vault's offline checks read the phone's own settings, so a compromised operating system could lie to them. They catch mistakes, not malware. Malware is addressed by layers 2 to 5: a factory reset, Android's app sandbox, and the device report's check that the system wasn't modified.

## Device tiers

Any Android 10 or newer with a camera works. The vault's **device report** measures, offline, where a phone stands:
- **Key storage:** a secure element (StrongBox), the TEE, or software only.
- **Boot:** whether the bootloader is locked and verified boot passed, from Android key attestation where the phone supports it.
- **OS:** version, security patch level, and whether it's GrapheneOS.

| Tier | Setup | What it adds |
|---|---|---|
| Best | A Pixel running GrapheneOS, never online | A secure element for the vault's key, verified boot with GrapheneOS's own key, exploit hardening |
| Good | A dedicated Android with a locked bootloader and recent updates | A TEE-backed key and verified boot |
| Budget | An older phone on LineageOS | A current OS, but usually an unlocked bootloader: someone holding the phone can tamper with the OS |
| Minimum | Anything that passes the offline checks | It works; the device report states the phone's weaknesses |

Malware built into a phone's system image by its maker survives a factory reset and passes verified boot, because the maker signed it. Nothing on the phone can detect that. The defence is choosing the phone: a Pixel with GrapheneOS, or a brand you trust.

## The key

- **Recovery phrase:** standard BIP39, 24 words by default or 12 by choice, from `SecureRandom`. The address uses Solana's standard path `m/44'/501'/0'/0'`, so the phrase restores the same address in any standard Solana wallet, without isol8.
- **Backup check at creation:** the vault shows the words once and checks three of them before it will save anything. **Check my backup** later compares typed words with the vault, answering only match or no match.
- **The phrase never meets the system keyboard.** Restoring and checking use the vault's own letter keys. Passphrase fields disable the keyboard's learning, suggestions and autofill.
- **Storage, two layers:**
  - AES-256-GCM under your vault passphrase, with the key derived by Argon2id at 64 MiB and 3 passes. The parameters are authenticated and bounded, so a tampered file can't weaken them.
  - That, sealed again with AES-256-GCM under an Android Keystore key: in StrongBox where the phone has one, else the TEE, and usable only while the phone is unlocked.

  A copied file is useless without this phone's Keystore, and the phone is useless without the passphrase. Nothing is ever backed up: Android backup and device transfer are off for the app.
- **Wrong passphrases:** five free tries, then a wait of 1, 5 and 30 minutes, then an hour after each wrong one. The wait counts down only while its screen is open, so changing the clock or restarting doesn't skip it. There's no auto-wipe: wiping only helps someone who wants to destroy, and the phrase is the real backup.
- **Secrets are short-lived.** Leaving the app or turning the screen off wipes them and locks the vault, including when an unlock finishes in the background. Screenshots, screen recording and recent-apps previews are blocked.
- **Deleting the vault** removes its file and its Keystore key. It needs no passphrase, since a forgotten passphrase is the usual reason to delete. It asks you to confirm you have your recovery phrase first.

## What the vault checks before signing

The full rules are in [PROTOCOL.md §6](PROTOCOL.md). In short:
- **Only a short list of programs and instructions can be signed.** Anything else is refused, including the usual ways to drain a wallet: changing a token account's authority, approving a delegate, changing the account's owner.
- **The vault sees every account.** Address lookup tables are refused.
- **Amounts are true.** Token decimals are checked by the token program on chain, or come from the vault's own list. Token names come only from that list; any other token is shown by its mint address.
- **Recipients are proven.** A token send must name its recipient's owner, and the vault re-derives the account from it.
- **At most one send per transaction,** so a second one can't hide below the one you asked for.
- **Swaps can only pay the vault.** Source and destination are the vault's own token accounts, re-derived, and the output can't be redirected. isol8's fee is capped at 0.5% and can only go to isol8's fee account (below).
- **Closing an account and withdrawing from a nonce account only pay the vault.**
- **The network fee is shown as a maximum,** with a warning above 0.01 SOL.
- **Saved addresses:** a destination a few characters off a saved one, or with the same first and last four characters, gets a warning, and declining becomes the default button.

A signature covers exactly the transaction that was checked. The vault's pairing statement is a Solana off-chain message whose prefix can never be a transaction, so a pairing signature can never be replayed as one.

## Swaps and Jupiter

Swaps go through Jupiter's on-chain program (`JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`). The vault reads the fixed part of Jupiter's instruction (amounts, slippage, fee, the vault's own source and destination) and refuses any other Jupiter instruction. It can't simulate the route offline, so it relies on Jupiter's program to deliver at least the minimum it shows into the vault's own account, or fail. That's a real dependency: Jupiter's program is upgradeable by Jupiter.

**A hostile route can't reach the vault's other tokens.** This was tested on 2026-11-21 by simulating spliced routes on mainnet. Jupiter tracks each step's amount from the amount paid, and checks each step's token accounts. A step re-spending the source was refused, and so was a step spending another of the signer's token accounts. So a dishonest dashboard can't take more than the amount the vault shows, or anything else. The most it could divert is output above the minimum shown, which your slippage setting already allows.

[SWAPS.md](SWAPS.md) has the details.

**isol8's fee account:** `oEGXn2LVvr43XTGtdh1JZzD3e8FAutjFzyBgCa7R7iw`, built into the app. Swap fees may only go to its token accounts.

## The bridge

- **QR framing is strict:** a fixed format, at most 16 parts of 256 bytes, and a SHA-256 fingerprint over the reassembled payload. Malformed or mixed codes are refused.
- **Pairing is one-use.** The dashboard's challenge is random, tied to one browser session, valid for 10 minutes, and used up by the first answer. Release builds pair only with `isol8.app`.
- **The dashboard checks the vault's answer** before sending anything: the request id, the signer, the hash of the message, and the signature itself.
- **Durable nonces:** a signed transaction stays valid until it's sent or cancelled, so you can sign at your own pace. **Cancel** signs a transaction that only uses up the nonce, so nothing else signed with it can ever go through.

## What isol8 can't protect you from

- Someone who finds your recovery phrase.
- Signing without reading what your vault shows.
- Malware built into the phone by its maker.
- Someone with your vault phone and your vault passphrase.
- Losing both the phone and the phrase.
- Prices moving, or tokens losing value.
- Bugs in isol8: it hasn't been independently audited yet.

## Things the vault can't verify offline

- **Mint properties** such as Token-2022 extensions (transfer fees, permanent delegates) and freeze authorities. They live in the mint account, not in the transaction. With a transfer-fee token, "Send 100" is what leaves the vault; the recipient may get less.
- **Accounts a swap route opens.** The vault reads the transaction, not its effects; the dashboard simulates swaps and shows these before you sign.
- **Whether a destination is safe.** The vault can only compare it with your saved addresses.

## Reviews

- **November 2026, internal review** of all five areas:
  - the vault's acceptance rules;
  - the key;
  - the bridge;
  - the dashboard and server;
  - releases.

  Changes from it:
  - at most one send per transaction;
  - token accounts for someone else only for that send;
  - memos limited to 256 bytes with no control or formatting characters;
  - the lock when an unlock finishes in the background;
  - the wait after wrong passphrases;
  - a pairing-screen warning against relayed codes.

  The Jupiter route experiment above was part of it.
- **Independent audit:** not yet.

## Verifying a release

Releases are reproducible. Two independent builds must match before the offline release key signs, and anyone can check a published APK against their own build of the tag: see [vault-android/release/README.md](../vault-android/release/README.md). The release certificate's SHA-256 is:

```
F1:E1:BF:BA:75:37:9A:C3:7C:E0:33:C5:34:37:0A:29:4F:D0:34:1B:10:FC:EB:0B:B5:67:FB:D8:B8:07:C8:05
```

## Reporting a vulnerability

Email **security@isol8.app**. Please don't open a public issue for a vulnerability.
