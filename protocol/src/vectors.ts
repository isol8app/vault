// Deterministic test vectors (PROTOCOL.md §11). `npm run vectors` writes them to vectors/*.json;
// the tests rebuild them and fail if the committed files are stale.
import { base45Encode } from "./base45.ts";
import { DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS, type VaultState } from "./acceptance.ts";
import { base58Decode, base58Encode } from "./base58.ts";
import { concat, toHex, u16le, u8, utf8 } from "./bytes.ts";
import { publicKeyFromSeed, sha256 } from "./crypto.ts";
import { encodeFrames, frameText, payloadId, PROTOCOL_VERSION, MAX_CHUNK } from "./frame.ts";
import { envelopeVectors } from "./envelope.ts";
import { keyVectors } from "./keys.ts";
import { swapVectors } from "./swapVectors.ts";
import { createPairResponse, offchainMessageV0, pairingStatement } from "./pairing.ts";
import {
  DECLINE_LOOKUP_TABLES,
  DECLINE_MALFORMED,
  DECLINE_RULE,
  DECLINE_UNKNOWN_SIGNER,
  DECLINE_UNSUPPORTED,
  encodePayload,
  type PairRequest,
  type SignTxRequest,
} from "./payload.ts";
import { createDeclined, createSignTxResponse } from "./signing.ts";
import {
  TOKEN_2022_PROGRAM,
  TOKEN_PROGRAM,
  NONCE_ACCOUNT_RENT_LAMPORTS,
  NONCE_ACCOUNT_SPACE,
  SYSTEM_PROGRAM,
  associatedTokenAddress,
  compileMessage,
  createWithSeed,
  ix,
  maxFeeLamports,
  type Instruction,
  type MessageSpec,
} from "./solana.ts";

const label = (s: string) => sha256(utf8(`isol8 test vector: ${s}`));
const b58 = base58Encode;

// ---- fixed test material (TEST ONLY) ----
export const VAULT_SEED = label("vault seed");
export const VAULT = publicKeyFromSeed(VAULT_SEED);
const OTHER_SEED = label("other seed");
const OTHER = publicKeyFromSeed(OTHER_SEED);
const RECIPIENT = publicKeyFromSeed(label("recipient seed"));
const MINT = publicKeyFromSeed(label("mint seed"));
const MINT_2022 = publicKeyFromSeed(label("token-2022 mint seed"));
const UNKNOWN_PROGRAM = publicKeyFromSeed(label("unknown program seed"));
const LOOKUP_TABLE = publicKeyFromSeed(label("lookup table seed"));
const NONCE_SEED = "isol8-nonce-0";
const NONCE_ACCOUNT = createWithSeed(VAULT, NONCE_SEED, SYSTEM_PROGRAM);
const NONCE_VALUE = label("nonce value");
const RECENT_BLOCKHASH = label("recent blockhash");

const requestId = (name: string) => sha256(utf8(`request:${name}`)).slice(0, 16);

function framesOf(payload: Uint8Array) {
  return { payload_hex: toHex(payload), frames: encodeFrames(payload) };
}

// ---- Base45 ----

function base45Vectors() {
  const inputs: Uint8Array[] = [
    new Uint8Array(0),
    Uint8Array.of(0x00),
    Uint8Array.of(0xff),
    Uint8Array.of(0x00, 0x00),
    Uint8Array.of(0xff, 0xff),
    utf8("AB"),
    utf8("Hello!!"),
    utf8("base-45"),
    utf8("ietf!"),
    sha256(utf8("base45 32 bytes")),
    concat(sha256(utf8("base45 33 bytes")), Uint8Array.of(0x42)),
  ];
  return {
    valid: inputs.map((b) => ({ bytes_hex: toHex(b), text: base45Encode(b) })),
    invalid: [
      { text: "A", error: "BAD_BASE45", why: "length mod 3 is 1" },
      { text: "ABCD", error: "BAD_BASE45", why: "length mod 3 is 1" },
      { text: "aBC", error: "BAD_BASE45", why: "lowercase is outside the alphabet" },
      { text: "GGW", error: "BAD_BASE45", why: "triple value 65536 exceeds 65535 (RFC 9285 example)" },
      { text: ":::", error: "BAD_BASE45", why: "triple value 91124 exceeds 65535" },
      { text: "::", error: "BAD_BASE45", why: "pair value 2024 exceeds 255" },
    ],
  };
}

// ---- Pairing ----

function pairingVectors() {
  const request: PairRequest = { type: "pair_request", challenge: label("pairing challenge"), origin: "isol8.app" };
  const appVersion = { major: 1, minor: 0 };
  const response = createPairResponse(VAULT_SEED, request, 0, appVersion);
  const statement = pairingStatement(request.origin, VAULT, request.challenge);
  return {
    origin: request.origin,
    challenge_hex: toHex(request.challenge),
    request: framesOf(encodePayload(request)),
    account_index: 0,
    app_version: appVersion,
    statement,
    offchain_message_hex: toHex(offchainMessageV0(statement, VAULT)),
    response: {
      pubkey_hex: toHex(response.pubkey),
      signature_hex: toHex(response.signature),
      ...framesOf(encodePayload(response)),
    },
  };
}

// ---- Transactions ----

type Expected =
  | {
      decision: "accept";
      lifetime: "durable_nonce" | "recent_blockhash";
      nonce_account?: string;
      max_fee_lamports: string;
      actions: Record<string, string | number>[];
      warnings?: Record<string, string>[];
    }
  | { decision: "decline"; reason: number; why: string };

type TxCase = {
  name: string;
  description: string;
  signer: Uint8Array;
  spec: MessageSpec;
  /** Corrupt the compiled message (for malformed-message cases). */
  mutate?: (message: Uint8Array) => Uint8Array;
  expected: Expected;
};

/** The vault state every transaction vector is evaluated against. */
const DESK = publicKeyFromSeed(label("desk wallet seed"));
export const VAULT_STATE: VaultState = {
  heldSigners: [VAULT],
  addressBook: [{ label: "Desk wallet", address: DESK }],
  highFeeThresholdLamports: DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS,
};

/**
 * An address whose first 4 and last 4 Base58 characters match `addr` with an unrelated middle (simulated address
 * poisoning: a vanity address ground to match the ends). A middle a few characters off would be a typo instead.
 */
function lookalikeOf(addr: Uint8Array): Uint8Array {
  const text = b58(addr);
  for (let i = 0; i < 10_000; i++) {
    const other = b58(sha256(new TextEncoder().encode(`isol8 lookalike ${i}`)));
    if (other.length !== text.length) continue;
    const candidate = text.slice(0, 4) + other.slice(4, -4) + text.slice(-4);
    const bytes = base58Decode(candidate);
    if (bytes.length === 32 && b58(bytes) === candidate) return bytes;
  }
  throw new Error("no lookalike found");
}
const LOOKALIKE = lookalikeOf(DESK);

/** Valid addresses a typo away from `addr`: the last character changed, and two neighbouring characters swapped. */
function nearMissesOf(addr: Uint8Array): { lastChanged: Uint8Array; swapped: Uint8Array } {
  const text = b58(addr);
  const valid = (candidate: string) => {
    const bytes = base58Decode(candidate);
    return bytes.length === 32 && b58(bytes) === candidate ? bytes : null;
  };
  let lastChanged: Uint8Array | null = null;
  for (const c of "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") {
    if (c !== text.at(-1)) lastChanged ??= valid(text.slice(0, -1) + c);
  }
  let swapped: Uint8Array | null = null;
  for (let pos = 20; pos < text.length - 6 && !swapped; pos++) {
    if (text[pos] !== text[pos + 1]) swapped = valid(text.slice(0, pos) + text[pos + 1] + text[pos] + text.slice(pos + 2));
  }
  if (!lastChanged || !swapped) throw new Error("no near miss found");
  return { lastChanged, swapped };
}
const NEAR_MISS = nearMissesOf(DESK);

function txCases(): TxCase[] {
  const advance = ix.advanceNonce(NONCE_ACCOUNT, VAULT);
  const nonceLifetime = { lifetime: "durable_nonce" as const, nonce_account: b58(NONCE_ACCOUNT) };
  const srcAta = associatedTokenAddress(VAULT, MINT, TOKEN_PROGRAM);
  const dstAta = associatedTokenAddress(RECIPIENT, MINT, TOKEN_PROGRAM);
  const srcAta22 = associatedTokenAddress(VAULT, MINT_2022, TOKEN_2022_PROGRAM);
  const dstAta22 = associatedTokenAddress(RECIPIENT, MINT_2022, TOKEN_2022_PROGRAM);
  const wsolAta = associatedTokenAddress(VAULT, base58Decode("So11111111111111111111111111111111111111112"), TOKEN_PROGRAM);
  const durable = (instructions: Instruction[], feePayer = VAULT): MessageSpec => ({ feePayer, lifetime: NONCE_VALUE, instructions });

  return [
    {
      name: "sol_transfer_durable_nonce",
      description: "Send 1,250 SOL with a durable nonce. Fits in one frame.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, RECIPIENT, 1_250_000_000_000n)]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: maxFeeLamports(1).toString(),
        actions: [{ kind: "sol_transfer", to: b58(RECIPIENT), lamports: "1250000000000" }],
      },
    },
    {
      name: "token_transfer_with_ata_and_priority_fee",
      description: "Send 40,000,000 tokens (6 decimals) with ATA creation for the recipient, a compute budget and a memo. Several frames.",
      signer: VAULT,
      spec: durable([
        advance,
        ix.setComputeUnitLimit(60_000),
        ix.setComputeUnitPrice(50_000n),
        ix.createAtaIdempotent(VAULT, dstAta, RECIPIENT, MINT, TOKEN_PROGRAM),
        ix.tokenTransferChecked(srcAta, MINT, dstAta, VAULT, 40_000_000_000_000n, 6, TOKEN_PROGRAM),
        ix.memo("isol8 test transfer"),
      ]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: maxFeeLamports(1, 60_000, 50_000n).toString(),
        actions: [
          { kind: "create_token_account", owner: b58(RECIPIENT), mint: b58(MINT), account: b58(dstAta), rent_payer: b58(VAULT) },
          { kind: "token_transfer", mint: b58(MINT), amount: "40000000000000", decimals: 6, to_owner: b58(RECIPIENT), to_account: b58(dstAta) },
          { kind: "memo", text: "isol8 test transfer" },
        ],
      },
    },
    {
      name: "token_2022_transfer",
      description: "Token-2022 TransferChecked with ATA creation, no compute budget.",
      signer: VAULT,
      spec: durable([
        advance,
        ix.createAtaIdempotent(VAULT, dstAta22, RECIPIENT, MINT_2022, TOKEN_2022_PROGRAM),
        ix.tokenTransferChecked(srcAta22, MINT_2022, dstAta22, VAULT, 123_456_789n, 9, TOKEN_2022_PROGRAM),
      ]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: maxFeeLamports(1).toString(),
        actions: [
          { kind: "create_token_account", owner: b58(RECIPIENT), mint: b58(MINT_2022), account: b58(dstAta22), rent_payer: b58(VAULT) },
          { kind: "token_transfer", mint: b58(MINT_2022), amount: "123456789", decimals: 9, to_owner: b58(RECIPIENT), to_account: b58(dstAta22) },
        ],
      },
    },
    {
      name: "activate_create_nonce_account",
      description: "Activation: create the vault's nonce account with a seed (no extra signer) and a recent blockhash.",
      signer: VAULT,
      spec: {
        feePayer: VAULT,
        lifetime: RECENT_BLOCKHASH,
        instructions: [
          ix.createAccountWithSeed(VAULT, NONCE_ACCOUNT, VAULT, NONCE_SEED, BigInt(NONCE_ACCOUNT_RENT_LAMPORTS), BigInt(NONCE_ACCOUNT_SPACE), SYSTEM_PROGRAM),
          ix.initializeNonce(NONCE_ACCOUNT, VAULT),
        ],
      },
      expected: {
        decision: "accept",
        lifetime: "recent_blockhash",
        max_fee_lamports: maxFeeLamports(1).toString(),
        actions: [
          { kind: "create_nonce_account", account: b58(NONCE_ACCOUNT), seed: NONCE_SEED, lamports: String(NONCE_ACCOUNT_RENT_LAMPORTS), authority: b58(VAULT) },
        ],
      },
    },
    {
      name: "close_empty_token_accounts",
      description: "Reclaim rent: close two empty token accounts (Token, Token-2022) and unwrap the vault's wSOL account outside a swap, all back to the vault.",
      signer: VAULT,
      spec: durable([
        advance,
        ix.setComputeUnitLimit(20_000),
        ix.setComputeUnitPrice(50_000n),
        ix.closeAccount(srcAta, VAULT, VAULT, TOKEN_PROGRAM),
        ix.closeAccount(srcAta22, VAULT, VAULT, TOKEN_2022_PROGRAM),
        ix.closeAccount(wsolAta, VAULT, VAULT, TOKEN_PROGRAM),
      ]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: maxFeeLamports(1, 20_000, 50_000n).toString(),
        actions: [
          { kind: "close_token_account", account: b58(srcAta) },
          { kind: "close_token_account", account: b58(srcAta22) },
          { kind: "unwrap_sol" },
        ],
      },
    },
    {
      name: "unwrap_wsol",
      description: "Unwrap: close the vault's own wSOL account, which may hold a balance; its wrapped SOL and rent come back to the vault as SOL. The dashboard files it as a reclaim.",
      signer: VAULT,
      spec: durable([advance, ix.setComputeUnitLimit(8_000), ix.setComputeUnitPrice(50_000n), ix.closeAccount(wsolAta, VAULT, VAULT, TOKEN_PROGRAM)]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: maxFeeLamports(1, 8_000, 50_000n).toString(),
        actions: [{ kind: "unwrap_sol" }],
      },
    },
    {
      name: "close_nonce_account_and_send_all_sol",
      description: "Leaving: with a recent blockhash, close an empty token account, withdraw the nonce account's whole balance to the vault, and send all SOL to the recipient.",
      signer: VAULT,
      spec: {
        feePayer: VAULT,
        lifetime: RECENT_BLOCKHASH,
        instructions: [
          ix.setComputeUnitLimit(20_000),
          ix.setComputeUnitPrice(10_000n),
          ix.closeAccount(srcAta, VAULT, VAULT, TOKEN_PROGRAM),
          ix.withdrawNonce(NONCE_ACCOUNT, VAULT, VAULT, BigInt(NONCE_ACCOUNT_RENT_LAMPORTS)),
          ix.systemTransfer(VAULT, RECIPIENT, 20_000_000n),
        ],
      },
      expected: {
        decision: "accept",
        lifetime: "recent_blockhash",
        max_fee_lamports: maxFeeLamports(1, 20_000, 10_000n).toString(),
        actions: [
          { kind: "close_token_account", account: b58(srcAta) },
          { kind: "withdraw_nonce_account", account: b58(NONCE_ACCOUNT), lamports: String(NONCE_ACCOUNT_RENT_LAMPORTS) },
          { kind: "sol_transfer", to: b58(RECIPIENT), lamports: "20000000" },
        ],
      },
    },
    {
      name: "close_nonce_account_only",
      description: "Leaving isol8 but keeping the wallet: with a recent blockhash, withdraw the nonce account's whole balance to the vault, nothing else.",
      signer: VAULT,
      spec: {
        feePayer: VAULT,
        lifetime: RECENT_BLOCKHASH,
        instructions: [ix.setComputeUnitLimit(10_000), ix.setComputeUnitPrice(10_000n), ix.withdrawNonce(NONCE_ACCOUNT, VAULT, VAULT, BigInt(NONCE_ACCOUNT_RENT_LAMPORTS))],
      },
      expected: {
        decision: "accept",
        lifetime: "recent_blockhash",
        max_fee_lamports: maxFeeLamports(1, 10_000, 10_000n).toString(),
        actions: [{ kind: "withdraw_nonce_account", account: b58(NONCE_ACCOUNT), lamports: String(NONCE_ACCOUNT_RENT_LAMPORTS) }],
      },
    },
    {
      name: "decline_withdraw_nonce_to_someone_else",
      description: "WithdrawNonceAccount paying the recipient instead of the vault.",
      signer: VAULT,
      spec: durable([advance, ix.withdrawNonce(NONCE_ACCOUNT, RECIPIENT, VAULT, 1_000_000n)]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "a nonce account may only be withdrawn to the vault, by the vault" },
    },
    {
      name: "decline_close_rent_to_someone_else",
      description: "CloseAccount sending the rent to the recipient instead of the vault.",
      signer: VAULT,
      spec: durable([advance, ix.closeAccount(srcAta, VAULT, VAULT, TOKEN_PROGRAM), ix.closeAccount(srcAta22, RECIPIENT, VAULT, TOKEN_2022_PROGRAM)]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "a closed token account must pay back to the vault, by the vault" },
    },
    {
      name: "decline_lookup_tables",
      description: "v0 message loading the destination from an address lookup table.",
      signer: VAULT,
      spec: {
        feePayer: VAULT,
        lifetime: NONCE_VALUE,
        instructions: [advance, ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n)],
        lookup: { table: LOOKUP_TABLE, writable: [{ index: 7, address: RECIPIENT }] },
      },
      expected: { decision: "decline", reason: DECLINE_LOOKUP_TABLES, why: "address lookup tables present" },
    },
    {
      name: "decline_plain_token_transfer",
      description: "Token Transfer (not TransferChecked): no mint or decimals, so the amount can't be shown.",
      signer: VAULT,
      spec: durable([advance, ix.tokenTransfer(srcAta, dstAta, VAULT, 1_000_000n)]),
      expected: { decision: "decline", reason: DECLINE_UNSUPPORTED, why: "plain token Transfer is not supported" },
    },
    {
      name: "decline_advance_nonce_not_first",
      description: "AdvanceNonceAccount present but not the first instruction.",
      signer: VAULT,
      spec: durable([ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n), advance]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "AdvanceNonceAccount must be the first instruction" },
    },
    {
      name: "decline_two_signers",
      description: "A second required signer besides the vault.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n), ix.systemTransfer(OTHER, VAULT, 1n)]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "exactly one required signer (the vault) in version 1" },
    },
    {
      name: "decline_unsupported_program",
      description: "An instruction for a program the vault can't decode.",
      signer: VAULT,
      spec: durable([advance, { programId: UNKNOWN_PROGRAM, accounts: [{ pubkey: VAULT, isSigner: true, isWritable: true }], data: Uint8Array.of(1, 2, 3) }]),
      expected: { decision: "decline", reason: DECLINE_UNSUPPORTED, why: "unknown program" },
    },
    {
      name: "decline_signer_not_held",
      description: "The request asks for a signer the vault doesn't hold.",
      signer: OTHER,
      spec: durable([ix.advanceNonce(NONCE_ACCOUNT, OTHER), ix.systemTransfer(OTHER, RECIPIENT, 1_000_000n)], OTHER),
      expected: { decision: "decline", reason: DECLINE_UNKNOWN_SIGNER, why: "the vault doesn't hold this key" },
    },
    {
      name: "decline_transfer_checked_without_ata_create",
      description: "TransferChecked whose destination owner can't be shown: no CreateIdempotent naming owner and mint.",
      signer: VAULT,
      spec: durable([advance, ix.tokenTransferChecked(srcAta, MINT, dstAta, VAULT, 1_000_000n, 6, TOKEN_PROGRAM)]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "every token destination needs a CreateIdempotent naming its owner" },
    },
    {
      name: "accept_high_fee_warning",
      description: "Priority fee of 0.02 SOL, above the 0.01 SOL warning threshold.",
      signer: VAULT,
      spec: durable([advance, ix.setComputeUnitLimit(200_000), ix.setComputeUnitPrice(100_000_000n), ix.systemTransfer(VAULT, RECIPIENT, 1_000_000_000n)]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: "20005000",
        actions: [{ kind: "sol_transfer", to: b58(RECIPIENT), lamports: "1000000000" }],
        warnings: [{ code: "HIGH_FEE", max_fee_lamports: "20005000", threshold_lamports: "10000000" }],
      },
    },
    {
      name: "accept_price_without_limit",
      description: "Unit price without a unit limit: the maximum fee assumes the runtime maximum of 1,400,000 units.",
      signer: VAULT,
      spec: durable([advance, ix.setComputeUnitPrice(1_000n), ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n)]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: "6400",
        actions: [{ kind: "sol_transfer", to: b58(RECIPIENT), lamports: "1000000" }],
      },
    },
    {
      name: "accept_address_book_label",
      description: "Destination is in the vault's address book, so its label is shown.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, DESK, 5_000_000_000n)]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: "5000",
        actions: [{ kind: "sol_transfer", to: b58(DESK), lamports: "5000000000", to_label: "Desk wallet" }],
      },
    },
    {
      name: "accept_lookalike_warning",
      description: "Destination shares its first and last 4 characters with an address-book entry but differs (address poisoning).",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, LOOKALIKE, 5_000_000_000n)]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: "5000",
        actions: [{ kind: "sol_transfer", to: b58(LOOKALIKE), lamports: "5000000000" }],
        warnings: [{ code: "LOOKALIKE_ADDRESS", address: b58(LOOKALIKE), resembles: b58(DESK), label: "Desk wallet" }],
      },
    },
    {
      name: "accept_near_miss_warning",
      description: "Destination is the address-book entry with its last character changed (a typo): no checksum catches it on Solana.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, NEAR_MISS.lastChanged, 5_000_000_000n)]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: "5000",
        actions: [{ kind: "sol_transfer", to: b58(NEAR_MISS.lastChanged), lamports: "5000000000" }],
        warnings: [{ code: "NEAR_MISS_ADDRESS", address: b58(NEAR_MISS.lastChanged), resembles: b58(DESK), label: "Desk wallet", differences: 1 }],
      },
    },
    {
      name: "accept_near_miss_swapped_characters",
      description: "Destination is the address-book entry with two neighbouring characters swapped: two edits away.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, NEAR_MISS.swapped, 5_000_000_000n)]),
      expected: {
        decision: "accept",
        ...nonceLifetime,
        max_fee_lamports: "5000",
        actions: [{ kind: "sol_transfer", to: b58(NEAR_MISS.swapped), lamports: "5000000000" }],
        warnings: [{ code: "NEAR_MISS_ADDRESS", address: b58(NEAR_MISS.swapped), resembles: b58(DESK), label: "Desk wallet", differences: 2 }],
      },
    },
    {
      name: "decline_v0_without_lookups",
      description: "A v0 message with no lookup tables. Only legacy messages are accepted in version 1.",
      signer: VAULT,
      spec: { ...durable([advance, ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n)]), v0: true },
      expected: { decision: "decline", reason: DECLINE_RULE, why: "only legacy messages are accepted in version 1" },
    },
    {
      name: "decline_malformed_truncated",
      description: "A valid message with its last byte removed.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n)]),
      mutate: (m) => m.slice(0, -1),
      expected: { decision: "decline", reason: DECLINE_MALFORMED, why: "message is truncated" },
    },
    {
      name: "decline_duplicate_compute_limit",
      description: "Two SetComputeUnitLimit instructions.",
      signer: VAULT,
      spec: durable([advance, ix.setComputeUnitLimit(10_000), ix.setComputeUnitLimit(20_000), ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n)]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "duplicate compute budget instruction" },
    },
    {
      name: "decline_transfer_hook_extra_accounts",
      description: "Token-2022 TransferChecked with an extra account, as transfer hooks require.",
      signer: VAULT,
      spec: durable([
        advance,
        ix.createAtaIdempotent(VAULT, dstAta22, RECIPIENT, MINT_2022, TOKEN_2022_PROGRAM),
        (() => {
          const t = ix.tokenTransferChecked(srcAta22, MINT_2022, dstAta22, VAULT, 1_000n, 9, TOKEN_2022_PROGRAM);
          return { ...t, accounts: [...t.accounts, { pubkey: UNKNOWN_PROGRAM, isSigner: false, isWritable: false }] };
        })(),
      ]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "TransferChecked with extra accounts is not supported" },
    },
    {
      name: "decline_ata_address_mismatch",
      description: "CreateIdempotent names an owner and mint, but the account address isn't their associated token account.",
      signer: VAULT,
      spec: durable([
        advance,
        ix.createAtaIdempotent(VAULT, LOOKUP_TABLE, RECIPIENT, MINT, TOKEN_PROGRAM),
        ix.tokenTransferChecked(srcAta, MINT, LOOKUP_TABLE, VAULT, 1_000n, 6, TOKEN_PROGRAM),
      ]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "token account address doesn't match its owner and mint" },
    },
    {
      name: "decline_two_sends",
      description: "A second send below the one the user asked for, where it could go unnoticed.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, RECIPIENT, 1_000_000_000n), ix.systemTransfer(VAULT, DESK, 1_000_000n)]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "at most one send per transaction" },
    },
    {
      name: "decline_token_account_for_someone_else_without_send",
      description: "Opens a token account for someone else (rent that never comes back) without sending them tokens.",
      signer: VAULT,
      spec: durable([advance, ix.createAtaIdempotent(VAULT, dstAta, RECIPIENT, MINT, TOKEN_PROGRAM), ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n)]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "a token account for someone else may only be opened for this transaction's send" },
    },
    {
      name: "decline_memo_with_line_break",
      description: "A memo with a line break, which could look like another line of the review screen.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n), ix.memo("Refund\n2. Send 0.001 SOL to Desk wallet")]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "memos with control or formatting characters are not supported" },
    },
    {
      name: "decline_memo_with_direction_override",
      description: "A memo with a right-to-left override (U+202E), which reorders the text shown.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n), ix.memo("invoice ‮1.0 LOS")]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "memos with control or formatting characters are not supported" },
    },
    {
      name: "decline_memo_too_long",
      description: "A memo longer than the 256 bytes the vault shows.",
      signer: VAULT,
      spec: durable([advance, ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n), ix.memo("a".repeat(257))]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "memos longer than 256 bytes are not supported" },
    },
    {
      name: "decline_create_account_not_nonce",
      description: "CreateAccountWithSeed for something other than an 80-byte nonce account.",
      signer: VAULT,
      spec: {
        feePayer: VAULT,
        lifetime: RECENT_BLOCKHASH,
        instructions: [
          ix.createAccountWithSeed(VAULT, createWithSeed(VAULT, NONCE_SEED, TOKEN_PROGRAM), VAULT, NONCE_SEED, 2_039_280n, 165n, TOKEN_PROGRAM),
        ],
      },
      expected: { decision: "decline", reason: DECLINE_RULE, why: "accounts may only be created as nonce accounts" },
    },
    {
      name: "decline_tokens_not_from_vault_ata",
      description: "TransferChecked whose source isn't the vault's own associated token account.",
      signer: VAULT,
      spec: durable([
        advance,
        ix.createAtaIdempotent(VAULT, dstAta, RECIPIENT, MINT, TOKEN_PROGRAM),
        ix.tokenTransferChecked(LOOKUP_TABLE, MINT, dstAta, VAULT, 1_000n, 6, TOKEN_PROGRAM),
      ]),
      expected: { decision: "decline", reason: DECLINE_RULE, why: "tokens must come from the vault's own token account" },
    },
  ];
}

function transactionVectors() {
  return txCases().map((c) => {
    const compiled = compileMessage(c.spec);
    const message = c.mutate ? c.mutate(compiled) : compiled;
    if (c.expected.decision === "accept") c.expected.warnings ??= [];
    const request: SignTxRequest = { type: "sign_tx_request", requestId: requestId(c.name), signer: c.signer, message };
    const out: Record<string, unknown> = {
      name: c.name,
      description: c.description,
      message_hex: toHex(message),
      message_len: message.length,
      request: { request_id_hex: toHex(request.requestId), signer: b58(c.signer), ...framesOf(encodePayload(request)) },
      expected: c.expected,
    };
    if (c.expected.decision === "accept") {
      const response = createSignTxResponse(VAULT_SEED, request);
      out.response = {
        message_hash_hex: toHex(response.messageHash),
        signature_hex: toHex(response.signature),
        ...framesOf(encodePayload(response)),
      };
    } else {
      out.declined = framesOf(encodePayload(createDeclined(request, c.expected.reason)));
    }
    return out;
  });
}

// ---- Invalid input: must be rejected with the given error code ----

function invalidVectors() {
  const pairPayload = encodePayload({ type: "pair_request", challenge: label("pairing challenge"), origin: "isol8.app" });
  const good = encodeFrames(pairPayload)[0]!;
  // Correctly framed (split normally), so the error comes from the payload itself.
  const single = (payload: Uint8Array) => encodeFrames(payload);
  const body = good.slice("ISOL8:".length);

  // A valid sign request payload to mutate.
  const message = compileMessage({ feePayer: VAULT, lifetime: NONCE_VALUE, instructions: [ix.advanceNonce(NONCE_ACCOUNT, VAULT), ix.systemTransfer(VAULT, RECIPIENT, 1n)] });
  const signHeader = concat(u8(0x03), requestId("invalid"), VAULT);

  // Two parts where the first is short: valid hashes, but parts must be full size except the last.
  const twoPartPayload = new Uint8Array(300).fill(7);
  const twoPartId = payloadId(twoPartPayload);

  const cases: { name: string; frames: string[]; error: string }[] = [
    { name: "bad_prefix", frames: ["ISOL9:" + body], error: "BAD_PREFIX" },
    { name: "lowercase_prefix", frames: ["isol8:" + body], error: "BAD_PREFIX" },
    { name: "bad_base45_character", frames: ["ISOL8:" + body.slice(0, -3) + "aaa"], error: "BAD_BASE45" },
    { name: "bad_base45_length", frames: ["ISOL8:" + body + "0"], error: "BAD_BASE45" },
    { name: "frame_too_short", frames: ["ISOL8:" + base45Encode(Uint8Array.of(1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0))], error: "BAD_FRAME" },
    { name: "wrong_version", frames: [frameText(2, 0, 1, payloadId(pairPayload), pairPayload)], error: "BAD_VERSION" },
    { name: "part_index_out_of_range", frames: [frameText(1, 1, 1, payloadId(pairPayload), pairPayload)], error: "BAD_PART" },
    { name: "part_count_zero", frames: [frameText(1, 0, 0, payloadId(pairPayload), pairPayload)], error: "BAD_PART" },
    { name: "part_count_17", frames: [frameText(1, 0, 17, payloadId(pairPayload), pairPayload)], error: "BAD_PART" },
    { name: "chunk_too_long", frames: [frameText(1, 0, 1, new Uint8Array(8), new Uint8Array(MAX_CHUNK + 1))], error: "BAD_FRAME" },
    { name: "payload_id_mismatch", frames: [frameText(1, 0, 1, new Uint8Array(8), pairPayload)], error: "PAYLOAD_ID_MISMATCH" },
    {
      name: "short_non_final_part",
      frames: [frameText(1, 0, 2, twoPartId, twoPartPayload.slice(0, 100)), frameText(1, 1, 2, twoPartId, twoPartPayload.slice(100))],
      error: "BAD_FRAME",
    },
    { name: "unknown_type", frames: single(Uint8Array.of(0x09, 0, 0)), error: "UNKNOWN_TYPE" },
    { name: "trailing_bytes", frames: single(concat(pairPayload, Uint8Array.of(0))), error: "TRAILING_BYTES" },
    { name: "truncated_payload", frames: single(pairPayload.slice(0, -1)), error: "TRUNCATED" },
    { name: "uppercase_origin", frames: single(concat(pairPayload.slice(0, 34), utf8("ISOL8.APP"))), error: "BAD_FIELD" },
    { name: "empty_origin", frames: single(concat(pairPayload.slice(0, 33), u8(0))), error: "BAD_FIELD" },
    { name: "hints_not_empty", frames: single(concat(signHeader, u16le(message.length), message, u16le(1), Uint8Array.of(0))), error: "BAD_FIELD" },
    { name: "message_len_zero", frames: single(concat(signHeader, u16le(0), u16le(0))), error: "BAD_FIELD" },
    // Claims 4044 message bytes (one over the limit) while the whole request still fits the 16 frames.
    { name: "message_len_4044", frames: encodeFrames(concat(signHeader, u16le(4044), new Uint8Array(4040), u16le(0))), error: "BAD_FIELD" },
    { name: "account_index_not_hardened_range", frames: single(concat(u8(0x02), VAULT, Uint8Array.of(0, 0, 0, 0x80), new Uint8Array(4), new Uint8Array(64))), error: "BAD_FIELD" },
    { name: "decline_reason_zero", frames: single(concat(u8(0x05), requestId("invalid"), u8(0))), error: "BAD_FIELD" },
  ];
  return cases;
}

export function buildVectors() {
  return {
    "common.json": {
      warning: "TEST KEYS ONLY. These seeds are public; never use them for real funds.",
      spec: "docs/PROTOCOL.md draft v0.1",
      vault_seed_hex: toHex(VAULT_SEED),
      vault_pubkey_hex: toHex(VAULT),
      vault_address: b58(VAULT),
      other_seed_hex: toHex(OTHER_SEED),
      other_address: b58(OTHER),
      recipient_address: b58(RECIPIENT),
      mint_address: b58(MINT),
      token_2022_mint_address: b58(MINT_2022),
      nonce_account: { address: b58(NONCE_ACCOUNT), seed: NONCE_SEED, base: b58(VAULT), owner: b58(SYSTEM_PROGRAM) },
      nonce_value_hex: toHex(NONCE_VALUE),
      recent_blockhash_hex: toHex(RECENT_BLOCKHASH),
      vault_state: {
        held_signers: VAULT_STATE.heldSigners.map(b58),
        address_book: VAULT_STATE.addressBook.map((e) => ({ label: e.label, address: b58(e.address) })),
        high_fee_threshold_lamports: VAULT_STATE.highFeeThresholdLamports.toString(),
      },
    },
    "base45.json": base45Vectors(),
    "pairing.json": pairingVectors(),
    "transactions.json": transactionVectors(),
    "swaps.json": swapVectors(),
    "invalid.json": invalidVectors(),
    "keys.json": keyVectors(),
    "envelopes.json": envelopeVectors(),
  };
}
