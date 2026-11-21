# Swaps from the vault

How the isol8 vault signs Jupiter swaps from cold storage, and what it checks. Facts about Jupiter were checked against its docs, its on-chain IDL and live `/swap/v2/build` responses (anonymous quotes, the public test-vector address as taker), November 2026. The rules below are implemented in `protocol/src/acceptance.ts` and `vault-android/core/.../Acceptance.kt`, and both pass every case in `protocol/vectors/swaps.json`, built from recorded live builds (`protocol/fixtures/jupiter/`).

## Goal

Swap any token the vault holds, straight from cold storage, with the vault showing exactly what it signs: what goes in, the **minimum** that comes out, and isol8's fee. A swap is signed with the durable nonce like a send, so the user signs at their own pace; the on-chain minimum makes a late send fail rather than fill at a bad price.

## Jupiter, as it is now

- **API:** Swap API V2, `GET https://api.jup.ag/swap/v2/build`. It returns individual instructions (setup, swap, cleanup), so we compose the transaction ourselves with the nonce advance first. The old Metis v1 endpoints are unmaintained and `lite-api.jup.ag` is being retired.
- **No lookup tables:** `transactionVersion=1` returns instructions with no address lookup tables, so the vault sees every account. The dashboard composes them into a **v1** transaction (SIMD-0385: up to 4,096 bytes and 64 accounts, still no lookup tables), with the nonce advance first. Large routes such as Pump.fun AMM need about 29 accounts and 1,250 bytes, more than a legacy transaction holds; QR requests carry messages of up to 4,043 bytes (16 frames).
- **Fees:** `platformFeeBps` + `feeAccount`, where the fee account is **any token account we control** of the input or output mint (no referral program). Jupiter charges no swap fee of its own on `/build`.
- **Builds go through the isol8 server**, not the browser, so Jupiter sees the server rather than the user's IP. The server refuses any build with lookup tables, another Jupiter instruction, or extra instructions.

## The transaction (SOL → USDC example, live)

| # | Program | What | Vault shows |
|---|---|---|---|
| 1 | System | AdvanceNonceAccount (ours, first) | "valid until sent" |
| 2 | Associated Token | CreateIdempotent: the vault's wSOL account | part of "wrap SOL" |
| 3 | System | Transfer SOL from the vault to its own wSOL account | "wrap 0.01 SOL" |
| 4 | Token | SyncNative on the vault's wSOL account | part of "wrap SOL" |
| 5 | Associated Token | CreateIdempotent: the vault's USDC account | "open a USDC account (rent from this vault, stays yours)" |
| 6 | Jupiter `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` | `route_v2` | **"Swap 0.01 SOL for at least 0.710061 USDC"**, isol8 fee 0.5% |
| 7 | Token | CloseAccount: the vault's wSOL account, back to the vault | "unwrap leftover SOL" |

Token → token swaps skip the wrap and unwrap steps.

## Reading `route_v2` without understanding routes

The route plan (which DEXes, in what split) has many variants and changes as Jupiter adds DEXes. The vault doesn't need it: the fields it must show sit at **fixed positions before the route plan**. Confirmed by building the same swap with and without a fee:

| Bytes | Field | Example |
|---|---|---|
| 0–7 | Discriminator (`route_v2`) | `bb64facc31c4af14` |
| 8–15 | `in_amount` (u64) | 10,000,000 (0.01 SOL) |
| 16–23 | `quoted_out_amount` (u64), **after** the platform fee | 713,629 (0.713629 USDC) |
| 24–25 | `slippage_bps` (u16) | 50 |
| 26–27 | `platform_fee_bps` (u16) | 0 or 50 |
| 28–29 | `positive_slippage_bps` (u16): the share of any better-than-quoted output paid to the fee account | 0, always |
| 30– | route plan (Vec: u32 count, then steps) | |

**Minimum received** = `quoted_out_amount × (10000 − slippage_bps) / 10000`, rounded up, which matched Jupiter's `otherAmountThreshold` exactly in every build. Jupiter's program enforces it on-chain: if the swap would deliver less, the whole transaction fails.

Accounts (first ten are fixed): 0 the vault (signer), 1 source token account, 2 destination token account, 3 source mint, 4 destination mint, 5–6 token programs, 7 the optional `destination_token_account` (Jupiter's own address when unused, which is always), 8 event authority, 9 Jupiter; with a fee, **10 is the fee account**; then the route's accounts.

Slot 7 and `positive_slippage_bps` both matter: an account in slot 7 receives the output **instead of** the vault's destination, and a non-zero `positive_slippage_bps` sends part of any surplus to the fee account. Jupiter never sets either, so the vault requires slot 7 to be Jupiter's address and the field to be 0. (Found 2026-11-17, before this check existed: a compromised dashboard could have put its own account in slot 7.)

**`shared_accounts_route_v2`** (`d19853937cfed8e9`) is the same swap routed through Jupiter's own token accounts. Jupiter now returns it for many multi-hop routes (SOL → JUP every time, at any route size). The data is route_v2's with an `id` byte first, so every field sits one byte later. The accounts are: 0 Jupiter's program authority, 1 the vault (signer), 2 source, 3 Jupiter's source token account, 4 Jupiter's destination token account, 5 destination, 6–7 mints, 8–9 token programs, 10 event authority, 11 Jupiter; with a fee, **12 is the fee account**. The vault pins every account the tokens pass through: account 0 must be the program address `["authority", id]` of Jupiter, accounts 3 and 4 must be that authority's associated token accounts for the two mints, and 2 and 5 the vault's own. There's no optional destination.

Both layouts come from Jupiter's IDL, read from its on-chain IDL account, and are pinned by recorded live builds in the test vectors. The vault refuses every other Jupiter instruction.

## Decimals: checked on-chain, never taken on trust

`route_v2` carries amounts in base units but no decimals. The vault knows decimals only for its named mints (wSOL 9, USDC 6, USDT 6, JUP 6). For any other mint, the dashboard adds a **decimals check**: a `TransferChecked` of **0 tokens from the vault's token account to itself**, stating the decimals. The token program compares them with the mint and fails the whole transaction if they're wrong (error 0x12, "decimals different from the Mint decimals": verified by simulation with 6 and 9 decimals on a 6-decimal mint). So a dashboard that lies about decimals can't get a swap with false amounts through. The vault takes decimals only from its list or such a check; a swap with an unknown mint and no check is declined.

## Compute budget

With `transactionVersion=1` Jupiter returns no compute budget instructions, only a suggested `computeUnitPrice`. The dashboard sets the compute limit from a simulation: it first runs the swap with the most a transaction may use (1,400,000 units) to measure it, then reserves a quarter more than it used. Swaps measured so far use 107,000–230,000 units, so the reserve is about 135,000–290,000 instead of a fixed 600,000. v1's priority fee is a total for the whole limit, so the fee drops with it: about 0.0000065 SOL instead of 0.000019 for a typical swap. The vault turns the header's limit and fee into its maximum-fee figure.

## Vault rules (PROTOCOL.md §6)

A swap is accepted only if all of these hold, otherwise declined:

1. **Jupiter:** exactly one `route_v2` or `shared_accounts_route_v2` instruction to `JUP6Lkb…aV4`, authorized by the vault; source and destination are **the vault's own** associated token accounts for the source and destination mints (re-derived, as for token sends); no output redirect (route_v2's slot 7 is Jupiter's address); no positive slippage given away; for the shared form, Jupiter's program authority and its two token accounts re-derived.
2. **Fee:** `platform_fee_bps` ≤ the vault's cap (50 = 0.5%); if it's above 0, the fee account (10, or 12 in the shared form) must be the associated token account of **isol8's fee owner** (built into the vault) for the input or output mint. A compromised dashboard can't raise the fee or redirect it.
3. **Wrapping SOL:** a System Transfer from the vault to the vault's own wSOL account, SyncNative on that account, and CloseAccount of that account with the vault as destination and authority are allowed, shown as "wrap" and "unwrap", never as a send.
4. **Decimals:** each mint the vault can't name needs a decimals check in the same transaction (above). A 0-token `TransferChecked` from a vault token account to itself is read as that check and shown as nothing.
5. **High slippage:** above 3% (300 basis points), a `HIGH_SLIPPAGE` warning.
6. **Everything else** follows the general rules: durable nonce first, legacy or v1 message, no lookup tables, no unknown programs, compute budget limits and the high-fee warning.

**What the vault shows:** "Swap **0.01 SOL** for at least **0.710061 USDC**", the quoted amount, "isol8 fee 0.5%", that it's valid until sent, and that a worse price makes it fail. Token names follow the vault's existing rule: its built-in names for wSOL, USDC, USDT and JUP, the mint address for everything else.

**The trust boundary, stated plainly:** the vault can't simulate the route offline. It relies on Jupiter's program to deliver at least the minimum to the vault's own account, or fail. Jupiter's program is upgradeable by Jupiter, so this is a real dependency, the same one every Jupiter user has. Our part is making sure the instruction can only pay the vault, can only charge isol8's capped fee, and shows true amounts.

**The route plan can't reach the vault's other tokens** (tested 2026-11-21 by simulation on mainnet; see SECURITY.md). Jupiter tracks each step's amount from `in_amount`: a step can only spend what an earlier step produced, from the token account that holds it, and Jupiter checks those accounts after each step. A spliced-in step that spent another token account of the signer was refused (Anchor `RequireKeysEqViolated`, 2502), and so was a second step re-spending the source (its amount was already used up). So a hostile route can't take more than the shown `in_amount`, and can only take output beyond the minimum shown: the same limit slippage already sets.

## Fees

isol8's fee is 0.5%, taken by Jupiter's platform fee into a token account of isol8's fee owner, for the output mint or else the input mint. The fee owner, `oEGXn2LVvr43XTGtdh1JZzD3e8FAutjFzyBgCa7R7iw`, is built into the vault app (`Acceptance.ISOL8_FEE_OWNER`). Its key was generated offline and is kept cold. The vault signs a fee of at most 0.5%, only to that owner's associated token account for one of the swap's two mints, and refuses any other fee.

## Known limits

- **Accounts a route opens are invisible to the vault.** It reads the transaction, not its effects. Some routes open accounts inside the route and pay their rent from the signer. The isol8 dashboard simulates every swap before it goes to the vault and shows these accounts with their rent.
- **The route depends on Jupiter's program**, as described under "The trust boundary" above.
