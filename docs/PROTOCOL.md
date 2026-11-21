# isol8 QR protocol

**Status: draft v0.1.** A TypeScript reference implementation and test vectors exist in [`protocol/`](../protocol/) (§11). Decisions marked *open* need settling before the vault is built.

This is how the hot side (the isol8.app dashboard) and the cold side (the Android vault app, later the Qubes signer) talk. They are separate implementations in different languages (TypeScript and Kotlin), so this document and its test vectors are the contract between them. See [SECURITY.md](SECURITY.md) for the security model.

---

## 1. Goals

1. **The vault trusts nothing it receives.** Everything the vault shows the user comes from the transaction bytes or the vault's own state. Anything else is labelled as unverified.
2. **Small parsing surface.** The vault's QR parser is the main remaining attack surface on an offline device. Fixed-size fields, strict lengths, no recursion, no general-purpose formats (no JSON, CBOR or protobuf).
3. **Fast loop.** Target 10–15 seconds from tap to broadcast. Responses from the vault are tiny, so they scan instantly.
4. **Easy to scan on cheap phones.** Low-density QR codes, with longer payloads split across an animated sequence.
5. **Versioned** from the first byte, so later changes don't break deployed vaults.

**Non-goals:** secrecy and authentication of the QR channel. Nothing in it is secret. Transactions and signatures become public on-chain anyway, and a vault's public key is public. Integrity comes from the QR code's own error correction plus a hash over each reassembled payload. Authenticity of what gets signed comes from the vault decoding and displaying it, not from the channel.

## 2. Messages

| Type | Name | Direction | Purpose |
|---|---|---|---|
| `0x01` | `PAIR_REQUEST` | hot → vault | Challenge to prove key ownership |
| `0x02` | `PAIR_RESPONSE` | vault → hot | Public key plus signature over the challenge |
| `0x03` | `SIGN_TX_REQUEST` | hot → vault | A transaction message to review and sign |
| `0x04` | `SIGN_TX_RESPONSE` | vault → hot | The signature only |
| `0x05` | `SIGN_TX_DECLINED` | vault → hot | The user declined, or the vault refused, with a reason |
| `0x06`–`0x07` | reserved | | Off-chain message signing (sign-in with the vault for Pro) |
| `0x08`–`0x0F` | reserved | | Future use |

### Flows

**Pair**
1. Hot shows `PAIR_REQUEST` with a fresh random 32-byte challenge.
2. Vault scans it, the user picks which account to pair, and the vault shows `PAIR_RESPONSE`.
3. Hot scans it, checks the signature, and registers the vault's public key.

**Sign**
1. Hot builds the transaction and shows `SIGN_TX_REQUEST`.
2. Vault scans it, applies the acceptance rules (§6), and decodes and displays it.
3. The user holds to sign → vault shows `SIGN_TX_RESPONSE`. The user declines, or the vault refuses → vault shows `SIGN_TX_DECLINED`.
4. Hot scans the response, verifies the signature against the message it sent, attaches it, and the user swipes to broadcast.

The vault returns **only the signature**, never the full transaction. The hot side already has the message, so the response is about 130 bytes and fits one small QR code.

## 3. Transport: QR frames

### 3.1 Encoding

Each QR code holds one **frame**, as text:

```
ISOL8:<base45 of frame bytes>
```

- QR **alphanumeric mode**, uppercase. The prefix `ISOL8:` and the whole [Base45 (RFC 9285)](https://www.rfc-editor.org/rfc/rfc9285) alphabet fit alphanumeric mode, which stores about 5.5 bits per character. Base45 in alphanumeric mode costs only about 3% over raw bytes, and avoids the inconsistent handling of binary byte-mode QR codes across scanning libraries. The same approach is used by EU digital COVID certificates.
- Error correction level **M**.
- Scanners reject any QR code whose text doesn't start with exactly `ISOL8:`.

### 3.2 Frame layout

All integers are little-endian.

| Offset | Size | Field | Rules |
|---|---|---|---|
| 0 | 1 | `version` | `0x01` for this spec. Any other value: reject |
| 1 | 1 | `part_index` | 0-based. Must be `< part_count` |
| 2 | 1 | `part_count` | 1–16 |
| 3 | 8 | `payload_id` | First 8 bytes of SHA-256 of the full reassembled payload |
| 11 | 1–256 | `chunk` | This part's bytes |

Header: 11 bytes. **Maximum chunk: 256 bytes** (*open:* tune after testing on cheap phones). A full frame is then at most 267 bytes: 401 Base45 characters plus the 6-character prefix, which fits a version 12 QR code (65 × 65 modules) at level M.

### 3.3 Splitting and reassembly

- The sender splits the payload into chunks of at most 256 bytes. Every part except the last is exactly 256 bytes.
- **One part:** show a static QR code. **Several parts:** loop through them at about 4 frames per second until the user moves on.
- The receiver collects parts **in any order**, keyed by `payload_id`. Duplicates are ignored. A part with the same `payload_id` but a different `part_count` resets collection.
- When all parts are present: concatenate in index order, compute SHA-256, and compare the first 8 bytes with `payload_id`. If they differ, discard everything and start again.
- The receiver shows progress ("3 of 5"), and after 30 seconds without a new part it resets.
- Maximum reassembled payload: `16 × 256 = 4096` bytes.

A durable-nonce SOL send is a 277-byte payload (2 frames). A Pump.fun AMM swap as a v1 transaction is about 1,250 bytes (6 frames). The largest possible request (a 4043-byte message, filling all 16 frames) takes about 4 seconds of scanning. See §12 on chunk size.

## 4. Payloads

Every payload starts with a 1-byte `type`. All integers are little-endian. **Trailing bytes after the last field are an error.** Public keys and signatures are raw bytes, not Base58.

### 4.1 `PAIR_REQUEST` (`0x01`), hot → vault

| Field | Size | Notes |
|---|---|---|
| `type` | 1 | `0x01` |
| `challenge` | 32 | Fresh random bytes from the hot side |
| `origin_len` | 1 | 1–64 |
| `origin` | `origin_len` | ASCII hostname, e.g. `isol8.app`. Lowercase letters, digits, `.` and `-` only |

### 4.2 `PAIR_RESPONSE` (`0x02`), vault → hot

| Field | Size | Notes |
|---|---|---|
| `type` | 1 | `0x02` |
| `pubkey` | 32 | The vault account's ed25519 public key |
| `account_index` | 4 | `u32`. The `i` in derivation path `m/44'/501'/i'/0'` |
| `app_version` | 4 | `u16` major, `u16` minor |
| `signature` | 64 | ed25519 signature by `pubkey` over the pairing statement (§5) |

### 4.3 `SIGN_TX_REQUEST` (`0x03`), hot → vault

| Field | Size | Notes |
|---|---|---|
| `type` | 1 | `0x03` |
| `request_id` | 16 | Random. Echoed in the response so the hot side can match it |
| `signer` | 32 | Which vault key should sign. The vault refuses if it doesn't hold this key |
| `message_len` | 2 | `u16`, 1–4043 (what fits 16 frames; legacy messages are at most 1232, v1 messages up to 4032) |
| `message` | `message_len` | Serialized Solana transaction **message** (not a full transaction: no signatures) |
| `hints_len` | 2 | `u16`. **Must be 0 in version 1.** Reserved for unverified display hints (§8) |

### 4.4 `SIGN_TX_RESPONSE` (`0x04`), vault → hot

| Field | Size | Notes |
|---|---|---|
| `type` | 1 | `0x04` |
| `request_id` | 16 | From the request |
| `signer` | 32 | The key that signed |
| `message_hash` | 32 | SHA-256 of the exact message bytes signed |
| `signature` | 64 | ed25519 signature over the message bytes |

Total: 145 bytes, always one frame.

### 4.5 `SIGN_TX_DECLINED` (`0x05`), vault → hot

| Field | Size | Notes |
|---|---|---|
| `type` | 1 | `0x05` |
| `request_id` | 16 | From the request |
| `reason` | 1 | See table |

| Reason | Meaning |
|---|---|
| `0x01` | The user declined |
| `0x02` | Unsupported program or instruction |
| `0x03` | Address lookup tables present |
| `0x04` | The vault doesn't hold `signer` |
| `0x05` | Malformed message |
| `0x06` | Breaks another acceptance rule (§6) |
| `0x07` | The device isn't offline ([SECURITY.md](SECURITY.md#the-vault-phone-in-layers)) |

The vault shows the user the specific reason. The code exists so the dashboard can explain what went wrong and fix it, for example by rebuilding the transaction without lookup tables.

## 5. Pairing statement

The vault signs the pairing statement as a **Solana off-chain message, version 0**. Because of the signing-domain prefix, the bytes can never be a valid transaction message, so a pairing signature can never be replayed as a transaction signature. The layout below matches `@solana/kit`'s `getOffchainMessageV0Encoder`, and the reference implementation is cross-checked against it.

| Field | Size | Value |
|---|---|---|
| Signing domain | 16 | `0xff` + ASCII `solana offchain` |
| Version | 1 | `0x00` |
| Application domain | 32 | SHA-256 of ASCII `isol8.app` |
| Message format | 1 | `0x00` (restricted ASCII: bytes `0x20`–`0x7e` only) |
| Signer count | 1 | `0x01` |
| Signer | 32 | The vault's public key |
| Message length | 2 | `u16`, little-endian |
| Message | length | The statement below |

Restricted ASCII doesn't allow newlines, so the statement is one line:

```
isol8 pairing; origin: <origin>; account: <pubkey, base58>; challenge: <challenge, lowercase hex>
```

The hot side rebuilds this exact text from the challenge it issued and the `pubkey` it received, then verifies the signature. A phishing site that tricks a user into pairing gains only a public key and a signature over a pairing statement. Neither can move funds.

### 5.1 Origin check on the vault

The `origin` in `PAIR_REQUEST` is chosen by whoever made the QR code, and the offline vault can't verify it. Even so:

- **Release builds pair only with `isol8.app`.** Any other origin is refused with a "Pairing refused" screen. The dashboard's other domains only redirect to `isol8.app`, so they never appear as origins.
- **Development builds** show a warning for other origins and allow them, so test and staging dashboards work.

This stops only requests that name another site. A phishing page can copy `isol8.app` into its request. The real binding is the signed statement: it includes the origin, so a response made for one site doesn't verify on another. Adding an origin needs an app update.

## 6. Vault acceptance rules (version 1)

The vault applies these before showing anything as signable. Any failure means `SIGN_TX_DECLINED`. The reference implementation is [`protocol/src/acceptance.ts`](../protocol/src/acceptance.ts); the **dashboard runs the same rules** before showing a request, so the vault rarely has to decline. Every rule below has a test vector (§11).

Checks run in this order, and the first failure decides the reason.

**1. Signer.** The vault must hold `signer`. Otherwise `0x04`.

**2. Message format.**
- The message must parse strictly (§9). Otherwise `0x05`.
- v0 with any address table lookup: `0x03`. v0 without lookups: `0x06`. **Legacy and v1 messages only.**
- **v1 (SIMD-0385, version byte `0x81`):** fixed-width, little-endian fields and no lookup tables, so the vault still sees every account. Its compute unit limit, loaded-accounts data size and priority fee are header fields; a v1 message with ComputeBudget instructions is refused (`0x06`), and its maximum fee is 5000 × signatures + the header's priority fee in lamports. Used for swaps, whose routes don't fit a legacy transaction (docs/SWAPS.md).
- Exactly **one required signature, equal to `signer`**, which is therefore also the fee payer. Otherwise `0x06`. Later versions (Streamflow locks) will allow extra signers, shown to the user.

**3. Supported programs and instructions.** Anything else is refused with `0x02`. Wrong usage of a supported instruction is refused with `0x06`.

| Program | Instruction | Requirements |
|---|---|---|
| System | `Transfer` | From the vault |
| System | `AdvanceNonceAccount` | **First instruction only**; RecentBlockhashes sysvar; authority = the vault |
| System | `CreateAccountWithSeed` | Funder and base = the vault; owner = System program; space = 80; seed `isol8-nonce-<n>` (`n` from 0 to 999999); created address = `createWithSeed(vault, seed, System)`; **immediately followed by** `InitializeNonceAccount` for the same account |
| System | `InitializeNonceAccount` | Only right after the matching `CreateAccountWithSeed`; RecentBlockhashes and Rent sysvars; authority = the vault |
| Compute Budget | `SetComputeUnitLimit`, `SetComputeUnitPrice` | No accounts; at most one of each |
| Token, Token-2022 | `TransferChecked` | Exactly 4 accounts; authority = the vault; source = **the vault's own associated token account** for that mint and token program; destination named by an earlier ATA instruction (below) |
| Token, Token-2022 | `CloseAccount` | Exactly 3 accounts; destination (where the rent goes) = the vault; authority = the vault. The vault can't see balances offline and doesn't need to: the token program refuses to close an account that still holds tokens. Shown as `close_token_account`, or as `unwrap_sol` when it closes the vault's own wSOL account in a swap |
| System | `WithdrawNonceAccount` | Exactly 5 accounts; recipient = the vault; authority = the vault; the RecentBlockhashes and Rent sysvars. Withdrawing everything closes the nonce account (only possible in a transaction that doesn't use it, so with a recent blockhash). Shown as `withdraw_nonce_account` |
| Associated Token Account | `Create` (data empty or `0`), `CreateIdempotent` (`1`) | Exactly 6 accounts; payer = the vault; System program; Token or Token-2022; account address = the associated token address of the named owner and mint |
| Memo (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`) | Memo | No accounts; valid UTF-8; at most 256 bytes; no control or formatting characters (Unicode Cc, Cf, Zl, Zp: line breaks, direction overrides, zero-width characters), which could make a memo look like more of the review screen |

Consequences worth knowing:
- **Plain token `Transfer` is refused.** It carries no mint or decimals, so the vault couldn't show a correct amount.
- **Every token destination must be named.** A `TransferChecked` destination is a token account, and its owner isn't in the transaction. So an earlier ATA `Create`/`CreateIdempotent` must name its owner and mint, and the vault checks the address derives from them. It then shows the **owner** as the recipient. `CreateIdempotent` costs nothing when the account already exists.
- **Token-2022 tokens with transfer hooks can't be sent in version 1.** Their `TransferChecked` needs extra accounts, which the 4-account rule refuses. So do multisig token authorities.
- **At most one send per transaction.** One SOL `Transfer` or token `TransferChecked`, so a second send can't hide below the one the user asked for. (Wrapping SOL for a swap isn't a send.)
- **A token account for someone else only for this transaction's send.** Its rent doesn't come back, so an ATA instruction naming an owner other than the vault must create this transaction's send destination.
- **Activation without extra signers.** Seed-derived nonce accounts mean the vault is the only signer and every nonce address can be re-derived from the vault's key. `<n>` starts at 0; v2's per-order nonce accounts use the next numbers.

**4. Freshness.**
- First instruction is `AdvanceNonceAccount`: a durable-nonce transaction. Show "valid until broadcast."
- Otherwise: a recent-blockhash transaction. Allowed, because activation needs one. Show "must be broadcast within about a minute."

**5. Maximum fee.** A compromised hot side could set an enormous priority fee and drain SOL as fees. The vault computes an upper bound:

```
max_fee = 5000 × signatures + ceil(unit_limit × unit_price_micro_lamports / 1,000,000)
```

`unit_limit` is the `SetComputeUnitLimit` value capped at 1,400,000, or **1,400,000 when absent** (the runtime maximum, so the bound is never too low). `unit_price` is 0 when absent. Above the threshold (default **0.01 SOL**, adjustable only on the vault) the vault shows a `HIGH_FEE` warning.

**6. Destinations.** For each SOL transfer destination and token recipient owner:
- If it equals an address-book entry or one of the vault's own keys, show that entry's label (the vault's own keys are labelled "this vault"). Only the user can edit the address book, on the vault.
- If it's a different address **1 to 4 character edits** (Levenshtein: changed, missing or extra characters) from an entry, show a `NEAR_MISS_ADDRESS` warning naming the entry and the number of `differences`: almost always a typo, since Solana addresses have no checksum. Unrelated addresses differ in about 43 of 44 characters, so this never fires by chance.
- Otherwise, if its **first 4 and last 4 Base58 characters** match an entry with a different middle, show a `LOOKALIKE_ADDRESS` warning naming the entry it resembles (address poisoning).

Instructions of the same kind (for example, two token-account creations) are each shown separately, never summed.

### 6.1 Decision format

The evaluator's output, which is also the `expected` field of each transaction vector:

```jsonc
// accept
{
  "decision": "accept",
  "lifetime": "durable_nonce",            // or "recent_blockhash"
  "nonce_account": "<base58>",            // durable nonce only
  "max_fee_lamports": "8000",             // decimal string
  "actions": [ ... ],                     // in instruction order; nonce and compute budget aren't actions
  "warnings": [ ... ]
}
// decline
{ "decision": "decline", "reason": 6, "why": "<human-readable>" }
```

| Action `kind` | Fields |
|---|---|
| `sol_transfer` | `to`, `lamports`, optional `to_label` |
| `create_token_account` | `owner`, `mint`, `account`, `rent_payer`, optional `mint_symbol` |
| `token_transfer` | `mint`, `amount` (base units), `decimals`, `to_owner`, `to_account`, optional `mint_symbol`, `to_label` |
| `memo` | `text` |
| `create_nonce_account` | `account`, `seed`, `lamports`, `authority` |
| `close_token_account` | `account` (rent back to the vault) |
| `withdraw_nonce_account` | `account`, `lamports` (back to the vault) |

| Warning `code` | Fields |
|---|---|
| `HIGH_FEE` | `max_fee_lamports`, `threshold_lamports` |
| `LOOKALIKE_ADDRESS` | `address`, `resembles`, `label` |
| `NEAR_MISS_ADDRESS` | `address`, `resembles`, `label`, `differences` (1 to 4) |
| `HIGH_SLIPPAGE` | `slippage_bps`, `threshold_bps` (a swap's slippage above 3%) |

Amounts are decimal strings, because they can exceed what a JSON number holds exactly. `mint_symbol` comes only from the vault's built-in list: wSOL, USDC, USDT, JUP. `why` is for people; implementations needn't match its wording.

## 7. Hot-side checks on responses

The hot side treats everything from the vault as untrusted input too:
- `request_id` matches an open request. Otherwise ignore.
- `signer` equals the requested signer.
- `message_hash` equals SHA-256 of the message the hot side sent.
- The ed25519 signature verifies against that message and `signer`.
- Only then attach the signature and offer broadcast.

## 8. Things the vault can't verify

Being offline, the vault can't look up on-chain state. In particular:
- **Token names and symbols.** The vault shows a built-in list of major mints by name. Every other mint is shown as an address, with a note that it can't be verified offline.
- **Mint properties** such as Token-2022 extensions (permanent delegate, transfer hook, transfer fee) and freeze or mint authorities. These live in the mint account, not in the transaction. The hot side checks them and warns in the dashboard. A later protocol version may pass them to the vault as **hints**, always displayed as "reported by dashboard, not verified."
- **Whether a destination is safe.** The vault can only compare it with its own address book.

## 9. Parser hardening

Applies to both sides, and most of all to the vault.
- Check `ISOL8:` prefix, strict Base45 (reject characters outside the alphabet, invalid triples, and values above the allowed range), then the frame header.
- Check every length field against the remaining bytes **before** reading. No out-of-range reads.
- Reject unknown `version`, unknown `type`, out-of-range values and trailing bytes.
- Fixed limits: 16 parts, 4096-byte payload, 4043-byte message (v1 at most 64 accounts and 64 instructions). No allocation is sized by an unchecked field.
- The Solana message parser ([`protocol/src/message.ts`](../protocol/src/message.ts)) parses legacy and v0 messages so it can give the right decline reason, but only legacy ones can be accepted. It rejects: non-canonical or over-long compact-u16 values, more than 256 accounts, duplicate account keys, inconsistent header counts, a read-only fee payer, program indexes of 0 or outside the static keys, account indexes out of range, and trailing bytes. Every count is checked against the remaining bytes before anything is read.
- Fuzz both parsers against these test vectors and random input in CI.

## 10. Versioning

- `version` in the frame header changes only for incompatible changes to framing or payload layout.
- New message types and new decline reasons can be added within version 1. Old vaults refuse unknown types.
- A vault shows "update the vault app" when it sees a newer `version`, never a partial parse.

## 11. Test vectors

The reference implementation is [`protocol/`](../protocol/): TypeScript with no dependencies, using Node's built-in SHA-256 and ed25519 (Node 24+). The vectors are in [`protocol/vectors/`](../protocol/vectors/). **The seeds in them are public test keys: never use them for real funds.**

| File | Contents |
|---|---|
| `common.json` | Test seeds, addresses, nonce account and nonce value used by the other files, plus the **vault state** (held signers, address book, fee threshold) the transaction vectors are evaluated against |
| `base45.json` | Valid encodings, including the RFC 9285 examples, and invalid inputs with error codes |
| `pairing.json` | `PAIR_REQUEST` and `PAIR_RESPONSE` payloads and frames, the statement, the off-chain message bytes and the signature |
| `transactions.json` | 21 `SIGN_TX_REQUEST` cases (7 accepts, including both warnings and an address-book label; 14 declines, one per rule) with compiled messages, the vault's **expected decision** (§6.1), and the matching `SIGN_TX_RESPONSE` or `SIGN_TX_DECLINED` |
| `invalid.json` | 22 frame and payload inputs that must be rejected, each with its error code |
| `keys.json` | Not protocol, but shared the same way: 36 Solana key derivations (recovery phrase → BIP39 seed → `m/44'/501'/i'/0'` → address → signature), computed with Node's own crypto, including a non-ASCII passphrase. The vault's Kotlin derivation must match all of them. |
| `envelopes.json` | Also not protocol: the vault's passphrase-envelope storage format, built with Node's own Argon2id and AES-GCM. 3 envelopes the vault must reproduce byte for byte and open, and 11 it must reject with the given reason. |

Error codes, which both implementations must use: `BAD_PREFIX`, `BAD_BASE45`, `BAD_FRAME`, `BAD_VERSION`, `BAD_PART`, `BAD_LENGTH`, `PAYLOAD_ID_MISMATCH`, `INCOMPLETE`, `UNKNOWN_TYPE`, `TRUNCATED`, `TRAILING_BYTES`, `BAD_FIELD`, and `MALFORMED_MESSAGE` from the Solana message parser.

The expected decisions in `transactions.json` are written by hand in the generator, from how each case was built, and **not** computed by the evaluator. The tests then check the evaluator against them, so the two are independent. Accepts must match exactly; declines must match the reason code.

Commands, from `protocol/`:
- `npm test` runs the tests: every vector, the evaluator against every transaction case, a fuzz pass of corrupted and random messages (the evaluator must never crash, and random bytes must always be declined), and a check that the committed vectors match the generator.
- `npm run vectors` regenerates the vectors after a deliberate change.
- `npm run crosscheck` compares against `@solana/kit`, an independent implementation (installed with `npm install --no-save @solana/kit`): the off-chain message bytes, every compiled message (decode and re-encode byte for byte), the associated token addresses and the nonce account address.

Limit of the reference implementation: it uses `node:crypto`. The dashboard in a browser needs WebCrypto or `@noble/curves` instead.

**Second implementation.** The vault's Kotlin core ([`vault-android/core/`](../vault-android/core/)) passes every vector byte for byte: frames, payloads, signatures, and decisions for all transaction cases. Run it with `./gradlew :core:test` from `vault-android/`. Any change to the protocol or the rules must keep every implementation passing.

**Third implementation (hot side, partial).** The dashboard's Python module ([`vault/protocol.py`](../vault/protocol.py)) decodes and checks everything the vault sends, on the server: Base45, frames, every payload type and the pairing statement, verified with PyNaCl. It passes the Base45, pairing and invalid vectors and parses every transaction case. It doesn't evaluate the acceptance rules. Run it with `python manage.py test vault`.

## 12. Open decisions

- **Custom format vs Uniform Resources (UR).** Keystone defines Solana UR types (`sol-sign-request`, `sol-signature`) used by its QR wallets. Adopting them could someday let isol8's vault sign for other wallets that support Keystone, but it means a CBOR parser on the vault, a larger attack surface. Draft choice: the custom minimal format above. Revisit if that interoperability becomes valuable.
- **Chunk size.** With 256-byte chunks, even a plain durable-nonce SOL send (277-byte payload) needs 2 frames. A 300-byte chunk makes it a single static QR code. The resulting frame (311 bytes, 473 characters with the prefix) fits a version 13 QR code (69 × 69) at level M. Recommended, pending a test on cheap Android cameras. Frame rate is also untested.
- Fee warning threshold: defaulted to 0.01 SOL (§6). Revisit if normal priority fees during congestion trigger it too often.
- Whether to support transfer-hook tokens and multisig token authorities, which version 1 refuses.
- Whether to require token sources to be the vault's associated token account, which rules out tokens held in other token accounts the vault owns.
- Allowing v0 messages without lookup tables.
- Sign-in message format (`0x06`/`0x07`): Sign In With Solana or a plain off-chain message.
