// Swap test vectors (docs/SWAPS.md), built offline from live Jupiter builds recorded in fixtures/jupiter/
// (scripts/record-jupiter.ts). Expected decisions come from Jupiter's own figures (inAmount, outAmount,
// otherAmountThreshold), not from the evaluator, so the two check each other.
import { readdirSync, readFileSync } from "node:fs";
import { DEFAULT_MAX_SWAP_FEE_BPS, KNOWN_DECIMALS, KNOWN_MINTS, WSOL_MINT } from "./acceptance.ts";
import { address, base58Encode } from "./base58.ts";
import { toHex, u16le, utf8 } from "./bytes.ts";
import { publicKeyFromSeed, sha256 } from "./crypto.ts";
import { encodeFrames } from "./frame.ts";
import { DECLINE_RULE, encodePayload, type SignTxRequest } from "./payload.ts";
import { createDeclined, createSignTxResponse } from "./signing.ts";
import {
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  associatedTokenAddress,
  compileMessage,
  createWithSeed,
  ix,
  maxFeeLamports,
  type Instruction,
} from "./solana.ts";

const label = (s: string) => sha256(utf8(`isol8 test vector: ${s}`));
const b58 = base58Encode;
const VAULT_SEED = label("vault seed");
const VAULT = publicKeyFromSeed(VAULT_SEED);
/** The fee owner in these vectors: the public "other" test key (common.json other_address). */
const FEE_OWNER = publicKeyFromSeed(label("other seed"));
const RECIPIENT = publicKeyFromSeed(label("recipient seed"));
const NONCE_ACCOUNT = createWithSeed(VAULT, "isol8-nonce-0", SYSTEM_PROGRAM);
const NONCE_VALUE = label("nonce value");
/** The compute budget the dashboard adds to every swap. */
const CU_LIMIT = 400_000;
/** Decimals of mints the vault doesn't know, as the dashboard reads them from chain. */
const CHAIN_DECIMALS: Record<string, number> = {
  "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo": 6, // PYUSD
  EyscKnGPbxVjGx4AgJqpYqtWmtnw2PpzRpvqShBQpump: 6, // POMPOMPURIN (Pump.fun, Token-2022)
};
/** The v1 header config the dashboard sets (SIMD-0385): no ComputeBudget instructions in a v1 transaction. */
const V1_CONFIG = { priorityFeeLamports: 5_000n, computeUnitLimit: 600_000, loadedAccountsDataSizeLimit: 64 * 1024 * 1024 };

type JupIx = { programId: string; accounts: { pubkey: string; isSigner: boolean; isWritable: boolean }[]; data: string };
type Fixture = {
  query: Record<string, string>;
  transaction?: "legacy" | "v1";
  fee: { bps: number; owner: string; mint: string; account: string } | null;
  response: {
    inputMint: string;
    outputMint: string;
    inAmount: string;
    outAmount: string;
    otherAmountThreshold: string;
    slippageBps: number;
    computeUnitPrice: string;
    setupInstructions: JupIx[];
    swapInstruction: JupIx;
    cleanupInstruction: JupIx | null;
    otherInstructions: JupIx[];
  };
};

const fixtureDir = new URL("../fixtures/jupiter/", import.meta.url);
const loadFixture = (name: string): Fixture => JSON.parse(readFileSync(new URL(`${name}.json`, fixtureDir), "utf8"));

const toInstruction = (j: JupIx): Instruction => ({
  programId: address(j.programId),
  accounts: j.accounts.map((a) => ({ pubkey: address(a.pubkey), isSigner: a.isSigner, isWritable: a.isWritable })),
  data: Uint8Array.from(Buffer.from(j.data, "base64")),
});

const decimalsOf = (mint: string) => KNOWN_DECIMALS[mint] ?? CHAIN_DECIMALS[mint]!;
/** shared_accounts_route_v2 (else route_v2): mints at 6/7 and token programs at 8/9, instead of 3/4 and 5/6. */
const isShared = (j: JupIx) => Buffer.from(j.data, "base64").subarray(0, 8).toString("hex") === "d19853937cfed8e9";
const programOf = (j: JupIx, input: boolean) => j.accounts[(isShared(j) ? 8 : 5) + (input ? 0 : 1)]!.pubkey;

/** The decimals checks the dashboard adds: a 0-token self-transfer for each mint the vault can't name. */
function decimalsChecks(f: Fixture): Instruction[] {
  const sw = f.response.swapInstruction;
  return ([[f.response.inputMint, true], [f.response.outputMint, false]] as const)
    .filter(([mint]) => KNOWN_DECIMALS[mint] === undefined)
    .map(([mint, input]) => {
      const program = address(programOf(sw, input));
      const ata = associatedTokenAddress(VAULT, address(mint), program);
      return ix.tokenTransferChecked(ata, address(mint), ata, VAULT, 0n, decimalsOf(mint), program);
    });
}

type Tweaks = {
  /** Change the swap instruction (a copy). */
  swap?: (j: JupIx) => JupIx;
  cleanup?: (j: JupIx) => JupIx;
  skipDecimalsChecks?: boolean;
  /** Add ComputeBudget instructions even to a v1 transaction (which must not have them). */
  forceComputeBudgetInstructions?: boolean;
};

function instructionsOf(f: Fixture, t: Tweaks = {}): Instruction[] {
  const r = f.response;
  const swap = t.swap ? t.swap(structuredClone(r.swapInstruction)) : r.swapInstruction;
  const cleanup = r.cleanupInstruction && (t.cleanup ? t.cleanup(structuredClone(r.cleanupInstruction)) : r.cleanupInstruction);
  const budget = f.transaction === "v1" && !t.forceComputeBudgetInstructions ? []
    : [ix.setComputeUnitLimit(CU_LIMIT), ix.setComputeUnitPrice(BigInt(r.computeUnitPrice))];
  return [
    ix.advanceNonce(NONCE_ACCOUNT, VAULT),
    ...budget,
    ...r.setupInstructions.map(toInstruction),
    ...(t.skipDecimalsChecks ? [] : decimalsChecks(f)),
    toInstruction(swap),
    ...r.otherInstructions.map(toInstruction),
    ...(cleanup ? [toInstruction(cleanup)] : []),
  ];
}

/** Expected actions, from the fixture itself: Jupiter's amounts and the instructions as recorded. */
function expectedActions(f: Fixture, override: { slippageBps?: number } = {}) {
  const r = f.response;
  const actions: Record<string, string | number>[] = [];
  const sym = (mint: string) => KNOWN_MINTS[mint];
  for (const s of r.setupInstructions) {
    if (s.programId === "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL") {
      const a: Record<string, string | number> = {
        kind: "create_token_account", owner: s.accounts[2]!.pubkey, mint: s.accounts[3]!.pubkey, account: s.accounts[1]!.pubkey, rent_payer: b58(VAULT),
      };
      if (sym(s.accounts[3]!.pubkey)) a.mint_symbol = sym(s.accounts[3]!.pubkey)!;
      actions.push(a);
    } else if (s.programId === "11111111111111111111111111111111") {
      actions.push({ kind: "wrap_sol", lamports: Buffer.from(s.data, "base64").readBigUInt64LE(4).toString() });
    }
  }
  const slippage = override.slippageBps ?? r.slippageBps;
  // Jupiter's own threshold, or (when the vector changes the slippage) the same rule recomputed.
  const minOut = override.slippageBps === undefined ? r.otherAmountThreshold
    : ((BigInt(r.outAmount) * BigInt(10_000 - slippage) + 9_999n) / 10_000n).toString();
  const swap: Record<string, string | number> = {
    kind: "swap",
    in_mint: r.inputMint,
    in_amount: r.inAmount,
    in_decimals: decimalsOf(r.inputMint),
    out_mint: r.outputMint,
    quoted_out_amount: r.outAmount,
    min_out_amount: minOut,
    out_decimals: decimalsOf(r.outputMint),
    slippage_bps: slippage,
    fee_bps: f.fee?.bps ?? 0,
  };
  if (f.fee) swap.fee_mint = f.fee.mint;
  if (sym(r.inputMint)) swap.in_symbol = sym(r.inputMint)!;
  if (sym(r.outputMint)) swap.out_symbol = sym(r.outputMint)!;
  actions.push(swap);
  if (r.cleanupInstruction) actions.push({ kind: "unwrap_sol" });
  return actions;
}

type SwapCase = { name: string; description: string; instructions: Instruction[]; expected: Record<string, unknown>; v1?: boolean };

const accept = (f: Fixture, actions: Record<string, string | number>[], warnings: Record<string, string | number>[] = []) => ({
  decision: "accept",
  lifetime: "durable_nonce",
  max_fee_lamports: (f.transaction === "v1" ? 5_000n + V1_CONFIG.priorityFeeLamports : maxFeeLamports(1, CU_LIMIT, BigInt(f.response.computeUnitPrice))).toString(),
  actions,
  warnings,
  nonce_account: b58(NONCE_ACCOUNT),
});
const declineRule = (why: string) => ({ decision: "decline", reason: DECLINE_RULE, why });

const setData = (j: JupIx, at: number, bytes: Uint8Array): JupIx => {
  const data = Buffer.from(j.data, "base64");
  data.set(bytes, at);
  return { ...j, data: data.toString("base64") };
};
const setAccount = (j: JupIx, slot: number, pubkey: Uint8Array): JupIx => {
  j.accounts[slot] = { ...j.accounts[slot]!, pubkey: b58(pubkey) };
  return j;
};

function swapCases(): SwapCase[] {
  const names = readdirSync(fixtureDir).filter((n) => n.endsWith(".json")).map((n) => n.slice(0, -5)).sort();
  const cases: SwapCase[] = names.map((name) => {
    const f = loadFixture(name);
    return {
      name,
      description: `Live Jupiter build${f.transaction === "v1" ? " (v1 transaction)" : ""}: ${f.query.amount} base units of ${KNOWN_MINTS[f.response.inputMint] ?? f.response.inputMint} to ${KNOWN_MINTS[f.response.outputMint] ?? f.response.outputMint}, fee ${f.fee?.bps ?? 0} bps.`,
      instructions: instructionsOf(f),
      expected: accept(f, expectedActions(f)),
      v1: f.transaction === "v1",
    };
  });

  const fee = loadFixture("sol_to_usdc_fee");
  const noFee = loadFixture("sol_to_usdc_no_fee");
  const pyusd = loadFixture("sol_to_pyusd_token_2022");
  const usdc = address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
  const wsol = address(WSOL_MINT);
  const vaultWsol = associatedTokenAddress(VAULT, wsol, TOKEN_PROGRAM);
  const pomp = loadFixture("v1_sol_to_pompompurin");
  const shared = loadFixture("v1_shared_sol_to_jup");
  const jup = address("JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN");
  cases.push(
    {
      name: "decline_v1_with_compute_budget_instructions",
      description: "A v1 swap that also carries ComputeBudget instructions (v1 sets its budget in the header; these would be ignored).",
      instructions: instructionsOf(pomp, { forceComputeBudgetInstructions: true }),
      expected: declineRule("a v1 transaction sets its compute budget in its header, not with instructions"),
      v1: true,
    },
    {
      name: "swap_high_slippage_warning",
      description: "A live build with slippage raised to 5%: accepted, minimum recomputed, with a HIGH_SLIPPAGE warning.",
      instructions: instructionsOf(noFee, { swap: (j) => setData(j, 24, u16le(500)) }),
      expected: accept(noFee, expectedActions(noFee, { slippageBps: 500 }), [{ code: "HIGH_SLIPPAGE", slippage_bps: 500, threshold_bps: 300 }]),
    },
    {
      name: "decline_swap_fee_above_cap",
      description: "The platform fee raised to 0.6%, above the vault's 0.5% cap.",
      instructions: instructionsOf(fee, { swap: (j) => setData(j, 26, u16le(60)) }),
      expected: declineRule("the swap fee is above the vault's limit of 50 basis points"),
    },
    {
      name: "decline_swap_fee_to_another_account",
      description: "The fee account swapped for one that isn't isol8's fee owner's.",
      instructions: instructionsOf(fee, { swap: (j) => setAccount(j, 10, associatedTokenAddress(RECIPIENT, usdc, TOKEN_PROGRAM)) }),
      expected: declineRule("the swap fee must go to isol8's fee account for one of the two tokens"),
    },
    {
      name: "decline_swap_pays_someone_else",
      description: "The destination token account swapped for the recipient's.",
      instructions: instructionsOf(fee, { swap: (j) => setAccount(j, 2, associatedTokenAddress(RECIPIENT, usdc, TOKEN_PROGRAM)) }),
      expected: declineRule("a swap must pay into the vault's own token account"),
    },
    {
      name: "decline_other_jupiter_instruction",
      description: "The route_v2 discriminator replaced by shared_accounts_route's (the older instruction): not signed.",
      instructions: instructionsOf(fee, { swap: (j) => setData(j, 0, sha256(utf8("global:shared_accounts_route")).slice(0, 8)) }),
      expected: declineRule("the only Jupiter instructions the vault signs are route_v2 and shared_accounts_route_v2"),
    },
    {
      name: "decline_swap_redirects_output",
      description: "route_v2's optional destination_token_account (slot 7) set to the recipient's token account: Jupiter would pay the output there.",
      instructions: instructionsOf(fee, { swap: (j) => setAccount(j, 7, associatedTokenAddress(RECIPIENT, usdc, TOKEN_PROGRAM)) }),
      expected: declineRule("a swap must not redirect its output to another account"),
    },
    {
      name: "decline_swap_positive_slippage",
      description: "route_v2 with positive_slippage_bps set: part of any better-than-quoted output would go to the fee account.",
      instructions: instructionsOf(fee, { swap: (j) => setData(j, 28, u16le(5000)) }),
      expected: declineRule("a swap must not give away positive slippage"),
    },
    {
      name: "decline_shared_wrong_program_authority",
      description: "shared_accounts_route_v2 with its program authority (slot 0) replaced by the recipient.",
      instructions: instructionsOf(shared, { swap: (j) => setAccount(j, 0, RECIPIENT) }),
      expected: declineRule("shared_accounts_route_v2 must use Jupiter's program authority for its id"),
      v1: true,
    },
    {
      name: "decline_shared_wrong_id",
      description: "shared_accounts_route_v2 with its id byte changed, so the program authority no longer matches it.",
      instructions: instructionsOf(shared, { swap: (j) => setData(j, 8, Uint8Array.of((Buffer.from(j.data, "base64")[8]! + 1) % 256)) }),
      expected: declineRule("shared_accounts_route_v2 must use Jupiter's program authority for its id"),
      v1: true,
    },
    {
      name: "decline_shared_through_other_account",
      description: "shared_accounts_route_v2 with Jupiter's destination account (slot 4) replaced by the recipient's token account.",
      instructions: instructionsOf(shared, { swap: (j) => setAccount(j, 4, associatedTokenAddress(RECIPIENT, jup, TOKEN_PROGRAM)) }),
      expected: declineRule("shared_accounts_route_v2 must route through Jupiter's own token accounts"),
      v1: true,
    },
    {
      name: "decline_shared_pays_someone_else",
      description: "shared_accounts_route_v2 with the destination (slot 5) replaced by the recipient's token account.",
      instructions: instructionsOf(shared, { swap: (j) => setAccount(j, 5, associatedTokenAddress(RECIPIENT, jup, TOKEN_PROGRAM)) }),
      expected: declineRule("a swap must pay into the vault's own token account"),
      v1: true,
    },
    {
      name: "decline_shared_fee_to_another_account",
      description: "shared_accounts_route_v2 with the fee account (slot 12) replaced by the recipient's wSOL account.",
      instructions: instructionsOf(shared, { swap: (j) => setAccount(j, 12, associatedTokenAddress(RECIPIENT, wsol, TOKEN_PROGRAM)) }),
      expected: declineRule("the swap fee must go to isol8's fee account for one of the two tokens"),
      v1: true,
    },
    {
      name: "decline_swap_unknown_token_without_decimals_check",
      description: "A swap into PYUSD (not a mint the vault knows) without the on-chain decimals check.",
      instructions: instructionsOf(pyusd, { skipDecimalsChecks: true }),
      expected: declineRule(`the swap needs a decimals check for ${pyusd.response.outputMint}`),
    },
    {
      name: "decline_unwrap_to_someone_else",
      description: "The wSOL account closed with the leftover paid to the recipient instead of the vault.",
      instructions: instructionsOf(fee, { cleanup: (j) => setAccount(j, 1, RECIPIENT) }),
      expected: declineRule("a closed token account must pay back to the vault, by the vault"),
    },
    {
      name: "decline_wrap_without_swap",
      description: "Wrapping SOL into the vault's wSOL account with no swap.",
      instructions: [
        ix.advanceNonce(NONCE_ACCOUNT, VAULT),
        ix.createAtaIdempotent(VAULT, vaultWsol, VAULT, wsol, TOKEN_PROGRAM),
        ix.systemTransfer(VAULT, vaultWsol, 1_000_000n),
        { programId: TOKEN_PROGRAM, accounts: [{ pubkey: vaultWsol, isSigner: false, isWritable: true }], data: Uint8Array.of(17) },
      ],
      expected: declineRule("wrapping SOL only as part of a swap involving SOL"),
    },
  );
  return cases;
}

function framesOf(payload: Uint8Array) {
  return { payload_hex: toHex(payload), frames: encodeFrames(payload) };
}

export function swapVectors() {
  return {
    warning: "TEST KEYS ONLY. Recorded mainnet Jupiter builds re-signed with public test keys; never broadcast.",
    spec: "docs/SWAPS.md (vault rules version 2)",
    fee_owner: b58(FEE_OWNER),
    max_swap_fee_bps: DEFAULT_MAX_SWAP_FEE_BPS,
    cases: swapCases().map((c) => {
      const message = compileMessage({ feePayer: VAULT, lifetime: NONCE_VALUE, instructions: c.instructions, ...(c.v1 ? { v1: V1_CONFIG } : {}) });
      const request: SignTxRequest = { type: "sign_tx_request", requestId: sha256(utf8(`request:swap:${c.name}`)).slice(0, 16), signer: VAULT, message };
      const out: Record<string, unknown> = {
        name: c.name,
        description: c.description,
        transaction: c.v1 ? "v1" : "legacy",
        message_hex: toHex(message),
        message_len: message.length,
        request: { request_id_hex: toHex(request.requestId), signer: b58(VAULT), ...framesOf(encodePayload(request)) },
        expected: c.expected,
      };
      if (c.expected.decision === "accept") {
        const response = createSignTxResponse(VAULT_SEED, request);
        out.response = { message_hash_hex: toHex(response.messageHash), signature_hex: toHex(response.signature), ...framesOf(encodePayload(response)) };
      } else {
        out.declined = framesOf(encodePayload(createDeclined(request, c.expected.reason as number)));
      }
      return out;
    }),
  };
}
