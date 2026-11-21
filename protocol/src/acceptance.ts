// Vault acceptance rules (PROTOCOL.md §6). Pure function: request + vault state -> accept (with a display
// summary and warnings) or decline (with a reason code). Never throws for any input bytes.
// The dashboard runs the same rules before showing a request, so the vault rarely has to decline.
import { base58Decode, base58Encode } from "./base58.ts";
import { ProtocolError, Reader, equal, fromUtf8, toHex, utf8 } from "./bytes.ts";
import { parseMessage, type ParsedMessage } from "./message.ts";
import {
  DECLINE_LOOKUP_TABLES,
  DECLINE_MALFORMED,
  DECLINE_RULE,
  DECLINE_UNKNOWN_SIGNER,
  DECLINE_UNSUPPORTED,
  type SignTxRequest,
} from "./payload.ts";
import {
  ASSOCIATED_TOKEN_PROGRAM,
  COMPUTE_BUDGET_PROGRAM,
  LAMPORTS_PER_SIGNATURE,
  MEMO_PROGRAM,
  NONCE_ACCOUNT_SPACE,
  SYSTEM_PROGRAM,
  SYSVAR_RECENT_BLOCKHASHES,
  SYSVAR_RENT,
  TOKEN_2022_PROGRAM,
  TOKEN_PROGRAM,
  associatedTokenAddress,
  createWithSeed,
  findProgramAddress,
} from "./solana.ts";

/** Upper bound used for the fee when no SetComputeUnitLimit is present (the runtime maximum). */
export const MAX_COMPUTE_UNITS = 1_400_000;
export const DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS = 10_000_000n; // 0.01 SOL
const NONCE_SEED_RE = /^isol8-nonce-(0|[1-9][0-9]{0,5})$/;

/** Jupiter's swap program and the two instructions of it the vault signs (docs/SWAPS.md). */
export const JUPITER_PROGRAM = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
export const ROUTE_V2_DISCRIMINATOR = "bb64facc31c4af14";
/** The same swap through Jupiter's own token accounts (multi-hop routes often come back this way). */
export const SHARED_ACCOUNTS_ROUTE_V2_DISCRIMINATOR = "d19853937cfed8e9";
export const WSOL_MINT = "So11111111111111111111111111111111111111112";
/** isol8's swap fee cap: 0.5%. */
export const DEFAULT_MAX_SWAP_FEE_BPS = 50;
/** Swaps with more slippage than this get a warning: 3%. */
export const HIGH_SLIPPAGE_BPS = 300;
/** Longest memo the vault shows, in bytes. */
export const MAX_MEMO_BYTES = 256;

/** Decimals the vault knows offline, for its named mints. Other mints need an on-chain decimals check. */
export const KNOWN_DECIMALS: Record<string, number> = {
  So11111111111111111111111111111111111111112: 9,
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: 6,
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: 6,
  JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN: 6,
};

/** Mints the vault can name offline. Everything else is shown by address only. */
export const KNOWN_MINTS: Record<string, string> = {
  So11111111111111111111111111111111111111112: "wSOL",
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: "USDC",
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: "USDT",
  JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN: "JUP",
};

export type VaultState = {
  /** Keys this vault can sign with. */
  heldSigners: Uint8Array[];
  /** Entries only the user can edit, on the vault. */
  addressBook: { label: string; address: Uint8Array }[];
  highFeeThresholdLamports: bigint;
  /** isol8's fee owner, built into the vault: swap fees may only go to its token accounts. None: no swap fee allowed. */
  swapFeeOwner?: Uint8Array;
  /** Highest swap fee the vault signs, in basis points. Defaults to DEFAULT_MAX_SWAP_FEE_BPS. */
  maxSwapFeeBps?: number;
};

export type Action =
  | { kind: "sol_transfer"; to: string; lamports: string; to_label?: string }
  | { kind: "create_token_account"; owner: string; mint: string; account: string; rent_payer: string; mint_symbol?: string }
  | {
      kind: "token_transfer";
      mint: string;
      amount: string;
      decimals: number;
      to_owner: string;
      to_account: string;
      mint_symbol?: string;
      to_label?: string;
    }
  | { kind: "memo"; text: string }
  | { kind: "create_nonce_account"; account: string; seed: string; lamports: string; authority: string }
  | { kind: "wrap_sol"; lamports: string }
  | { kind: "unwrap_sol" }
  /** An empty token account closed, its rent back to the vault (the token program refuses if it holds tokens). */
  | { kind: "close_token_account"; account: string }
  /** SOL withdrawn from a nonce account back to the vault; withdrawing all of it closes the account. */
  | { kind: "withdraw_nonce_account"; account: string; lamports: string }
  | {
      kind: "swap";
      in_mint: string;
      in_amount: string;
      in_decimals: number;
      out_mint: string;
      quoted_out_amount: string;
      min_out_amount: string;
      out_decimals: number;
      slippage_bps: number;
      fee_bps: number;
      fee_mint?: string;
      in_symbol?: string;
      out_symbol?: string;
    };

export type Warning =
  | { code: "HIGH_FEE"; max_fee_lamports: string; threshold_lamports: string }
  | { code: "LOOKALIKE_ADDRESS"; address: string; resembles: string; label: string }
  /** A few characters from a known address: almost always a typo. Solana addresses have no checksum. */
  | { code: "NEAR_MISS_ADDRESS"; address: string; resembles: string; label: string; differences: number }
  | { code: "HIGH_SLIPPAGE"; slippage_bps: number; threshold_bps: number };

export type Decision =
  | {
      decision: "accept";
      lifetime: "durable_nonce" | "recent_blockhash";
      nonce_account?: string;
      max_fee_lamports: string;
      actions: Action[];
      warnings: Warning[];
    }
  | { decision: "decline"; reason: number; why: string };

class Decline extends Error {
  readonly reason: number;
  constructor(reason: number, why: string) {
    super(why);
    this.reason = reason;
  }
}

const b58 = base58Encode;
const decline = (reason: number, why: string): never => {
  throw new Decline(reason, why);
};
const rule = (ok: boolean, why: string) => {
  if (!ok) decline(DECLINE_RULE, why);
};

type Item =
  | { t: "advance"; index: number; nonce: Uint8Array }
  | { t: "sol_transfer"; to: Uint8Array; lamports: bigint }
  | { t: "create_with_seed"; created: Uint8Array; seed: string; lamports: bigint }
  | { t: "init_nonce"; nonce: Uint8Array }
  | { t: "cu_limit"; units: number }
  | { t: "cu_price"; microLamports: bigint }
  | { t: "transfer_checked"; program: Uint8Array; mint: Uint8Array; dest: Uint8Array; amount: bigint; decimals: number }
  | { t: "create_ata"; program: Uint8Array; ata: Uint8Array; owner: Uint8Array; mint: Uint8Array }
  | { t: "memo"; text: string }
  | { t: "wrap"; lamports: bigint }
  | { t: "sync" }
  /** CloseAccount, rent to the vault: "unwrap" when it's the vault's own wSOL account, else a close. */
  | { t: "close"; account: Uint8Array; wsol: boolean }
  | { t: "withdraw_nonce"; nonce: Uint8Array; lamports: bigint }
  | { t: "decimals"; program: Uint8Array; mint: Uint8Array; decimals: number }
  | {
      t: "swap";
      inMint: Uint8Array;
      outMint: Uint8Array;
      inAmount: bigint;
      quotedOut: bigint;
      slippageBps: number;
      feeBps: number;
      feeMint?: Uint8Array;
    };

function u64(r: Reader): bigint {
  const b = r.take(8);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  return v;
}

export function evaluateSignRequest(request: SignTxRequest, state: VaultState): Decision {
  try {
    return evaluate(request, state);
  } catch (e) {
    if (e instanceof Decline) return { decision: "decline", reason: e.reason, why: e.message };
    // Any unexpected failure is treated as malformed input, never as an accept.
    return { decision: "decline", reason: DECLINE_MALFORMED, why: e instanceof Error ? e.message : String(e) };
  }
}

function evaluate(request: SignTxRequest, state: VaultState): Decision {
  const signer = request.signer;
  if (!state.heldSigners.some((k) => equal(k, signer))) decline(DECLINE_UNKNOWN_SIGNER, "the vault doesn't hold this key");

  let msg: ParsedMessage;
  try {
    msg = parseMessage(request.message);
  } catch (e) {
    return decline(DECLINE_MALFORMED, e instanceof ProtocolError ? e.message : "malformed message");
  }
  if (msg.version === 0) {
    if (msg.lookups.length > 0) decline(DECLINE_LOOKUP_TABLES, "address lookup tables present");
    decline(DECLINE_RULE, "only legacy messages are accepted in version 1");
  }
  rule(msg.numRequiredSignatures === 1, "exactly one required signer (the vault) in version 1");
  // v1 (SIMD-0385) sets the compute budget in its header; ComputeBudget instructions there would be ignored no-ops.
  if (msg.version === 1 && msg.instructions.some((ix) => equal(msg.staticKeys[ix.programIdIndex]!, COMPUTE_BUDGET_PROGRAM))) {
    decline(DECLINE_RULE, "a v1 transaction sets its compute budget in its header, not with instructions");
  }
  rule(equal(msg.staticKeys[0]!, signer), "the fee payer and only signer must be the requested signer");

  const key = (i: number) => msg.staticKeys[i]!;
  const isVault = (i: number) => i === 0; // index 0 is the only signer, and equals `signer`
  const wsolAccount = associatedTokenAddress(signer, base58Decode(WSOL_MINT), TOKEN_PROGRAM);
  const isTokenProgram = (p: Uint8Array) => equal(p, TOKEN_PROGRAM) || equal(p, TOKEN_2022_PROGRAM);

  const items: Item[] = msg.instructions.map((ix, index): Item => {
    const program = key(ix.programIdIndex);
    const acc = ix.accounts;
    const r = new Reader(ix.data);
    const done = <T extends Item>(item: T): T => {
      r.end();
      return item;
    };

    if (equal(program, SYSTEM_PROGRAM)) {
      const kind = ix.data.length >= 4 ? r.u32() : decline(DECLINE_MALFORMED, "system instruction too short");
      switch (kind) {
        case 2: {
          rule(acc.length === 2 && isVault(acc[0]!), "SOL transfers must come from the vault");
          const to = key(acc[1]!);
          // Into the vault's own wSOL account: wrapping SOL for a swap, not a send.
          if (equal(to, wsolAccount)) return done({ t: "wrap", lamports: u64(r) });
          return done({ t: "sol_transfer", to, lamports: u64(r) });
        }
        case 5: {
          // WithdrawNonceAccount: only back to the vault, on the vault's authority. Withdrawing everything closes it.
          rule(acc.length === 5, "WithdrawNonceAccount needs 5 accounts");
          rule(equal(key(acc[2]!), SYSVAR_RECENT_BLOCKHASHES) && equal(key(acc[3]!), SYSVAR_RENT), "WithdrawNonceAccount must use the sysvars");
          rule(isVault(acc[1]!) && isVault(acc[4]!), "a nonce account may only be withdrawn to the vault, by the vault");
          return done({ t: "withdraw_nonce", nonce: key(acc[0]!), lamports: u64(r) });
        }
        case 4: {
          rule(acc.length === 3, "AdvanceNonceAccount needs 3 accounts");
          rule(equal(key(acc[1]!), SYSVAR_RECENT_BLOCKHASHES), "AdvanceNonceAccount must use the RecentBlockhashes sysvar");
          rule(isVault(acc[2]!), "the nonce authority must be the vault");
          return done({ t: "advance", index, nonce: key(acc[0]!) });
        }
        case 3: {
          const base = r.take(32);
          const seedLen = u64(r);
          rule(seedLen <= 32n, "seed longer than 32 bytes");
          const seed = fromUtf8(r.take(Number(seedLen)));
          const lamports = u64(r);
          const space = u64(r);
          const owner = r.take(32);
          rule(acc.length === 2 || acc.length === 3, "CreateAccountWithSeed needs 2 or 3 accounts");
          rule(isVault(acc[0]!) && equal(base, signer) && (acc.length === 2 || isVault(acc[2]!)), "the nonce account must be funded and based on the vault");
          rule(equal(owner, SYSTEM_PROGRAM) && space === BigInt(NONCE_ACCOUNT_SPACE), "accounts may only be created as nonce accounts");
          rule(NONCE_SEED_RE.test(seed), "nonce account seeds must be isol8-nonce-<n>");
          const created = key(acc[1]!);
          rule(equal(created, createWithSeed(signer, seed, SYSTEM_PROGRAM)), "created address doesn't match the seed");
          return done({ t: "create_with_seed", created, seed, lamports });
        }
        case 6: {
          const authority = r.take(32);
          rule(acc.length === 3, "InitializeNonceAccount needs 3 accounts");
          rule(equal(key(acc[1]!), SYSVAR_RECENT_BLOCKHASHES) && equal(key(acc[2]!), SYSVAR_RENT), "InitializeNonceAccount must use the sysvars");
          rule(equal(authority, signer), "new nonce accounts must have the vault as authority");
          return done({ t: "init_nonce", nonce: key(acc[0]!) });
        }
        default:
          return decline(DECLINE_UNSUPPORTED, `unsupported System instruction ${kind}`);
      }
    }

    if (equal(program, COMPUTE_BUDGET_PROGRAM)) {
      rule(acc.length === 0, "compute budget instructions take no accounts");
      const kind = r.u8();
      if (kind === 2) return done({ t: "cu_limit", units: r.u32() });
      if (kind === 3) return done({ t: "cu_price", microLamports: u64(r) });
      return decline(DECLINE_UNSUPPORTED, `unsupported compute budget instruction ${kind}`);
    }

    if (equal(program, TOKEN_PROGRAM) || equal(program, TOKEN_2022_PROGRAM)) {
      const kind = r.u8();
      if (kind === 17) {
        // SyncNative, after wrapping SOL into the vault's own wSOL account.
        rule(equal(program, TOKEN_PROGRAM) && acc.length === 1 && equal(key(acc[0]!), wsolAccount), "SyncNative only on the vault's own wSOL account");
        return done({ t: "sync" });
      }
      if (kind === 9) {
        // CloseAccount: the rent (and, for wSOL, the wrapped SOL) goes back to the vault, on the vault's authority.
        // The vault can't see balances offline; it doesn't need to: the token program refuses to close an account
        // that still holds tokens, so the worst a lying dashboard can do is make the transaction fail.
        rule(acc.length === 3, "CloseAccount needs 3 accounts");
        rule(isVault(acc[1]!) && isVault(acc[2]!), "a closed token account must pay back to the vault, by the vault");
        const account = key(acc[0]!);
        return done({ t: "close", account, wsol: equal(program, TOKEN_PROGRAM) && equal(account, wsolAccount) });
      }
      if (kind !== 12) return decline(DECLINE_UNSUPPORTED, kind === 3 ? "plain token Transfer is not supported" : `unsupported token instruction ${kind}`);
      rule(acc.length === 4, "TransferChecked with extra accounts (multisig or transfer hooks) is not supported");
      rule(isVault(acc[3]!), "token transfers must be authorized by the vault");
      const mint = key(acc[1]!);
      rule(equal(key(acc[0]!), associatedTokenAddress(signer, mint, program)), "tokens must come from the vault's own token account");
      const amount = u64(r);
      const decimals = r.u8();
      // Zero tokens from the vault's account to itself: an on-chain check that `decimals` is right (it fails otherwise).
      if (amount === 0n && acc[2] === acc[0]) return done({ t: "decimals", program, mint, decimals });
      return done({ t: "transfer_checked", program, mint, dest: key(acc[2]!), amount, decimals });
    }

    if (equal(program, ASSOCIATED_TOKEN_PROGRAM)) {
      const kind = ix.data.length === 0 ? 0 : r.u8();
      if (kind !== 0 && kind !== 1) return decline(DECLINE_UNSUPPORTED, `unsupported associated token instruction ${kind}`);
      rule(acc.length === 6, "associated token account creation needs 6 accounts");
      rule(isVault(acc[0]!), "the vault must pay for token account creation");
      const [ata, owner, mint, system, tokenProgram] = [key(acc[1]!), key(acc[2]!), key(acc[3]!), key(acc[4]!), key(acc[5]!)];
      rule(equal(system, SYSTEM_PROGRAM), "associated token account creation must use the System program");
      rule(equal(tokenProgram, TOKEN_PROGRAM) || equal(tokenProgram, TOKEN_2022_PROGRAM), "unknown token program");
      rule(equal(ata, associatedTokenAddress(owner, mint, tokenProgram)), "token account address doesn't match its owner and mint");
      return done({ t: "create_ata", program: tokenProgram, ata, owner, mint });
    }

    if (equal(program, MEMO_PROGRAM)) {
      rule(acc.length === 0, "memos with signer accounts are not supported");
      let text: string;
      try {
        text = fromUtf8(ix.data);
      } catch {
        return decline(DECLINE_RULE, "memo is not valid UTF-8");
      }
      // Line breaks, direction overrides or invisible characters could make a memo look like more of the review screen.
      rule(ix.data.length <= MAX_MEMO_BYTES, `memos longer than ${MAX_MEMO_BYTES} bytes are not supported`);
      rule(!/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(text), "memos with control or formatting characters are not supported");
      return { t: "memo", text };
    }

    if (b58(program) === JUPITER_PROGRAM) {
      // route_v2 and shared_accounts_route_v2 (Jupiter's IDL). Same arguments, except shared starts with an id byte;
      // shared moves the tokens through Jupiter's program-authority accounts, which are pinned below.
      const discriminator = ix.data.length >= 8 ? toHex(ix.data.subarray(0, 8)) : "";
      const shared = discriminator === SHARED_ACCOUNTS_ROUTE_V2_DISCRIMINATOR;
      rule(shared || discriminator === ROUTE_V2_DISCRIMINATOR, "the only Jupiter instructions the vault signs are route_v2 and shared_accounts_route_v2");
      rule(ix.data.length >= (shared ? 35 : 34), "Jupiter swap data is too short");
      r.take(8);
      const id = shared ? r.u8() : 0;
      const inAmount = u64(r);
      const quotedOut = u64(r);
      const slippageBps = r.u16();
      const feeBps = r.u16();
      const positiveSlippageBps = r.u16();
      // The route plan follows; the vault doesn't need it (Jupiter enforces the minimum on-chain).
      // Slots: route_v2 = authority 0, source 1, destination 2, mints 3/4, token programs 5/6, optional
      // destination override 7, then fee account 10. Shared = program authority 0, authority 1, source 2,
      // Jupiter's source and destination 3/4, destination 5, mints 6/7, token programs 8/9, then fee account 12.
      const [vaultSlot, sourceSlot, destSlot, mintSlot, programSlot, feeSlot] = shared ? [1, 2, 5, 6, 8, 12] : [0, 1, 2, 3, 5, 10];
      const name = shared ? "shared_accounts_route_v2" : "route_v2";
      rule(acc.length >= (feeBps > 0 ? feeSlot + 1 : feeSlot), `${name} has too few accounts`);
      rule(isVault(acc[vaultSlot]!), "the swap must be authorized by the vault");
      const [inMint, outMint, inProgram, outProgram] = [key(acc[mintSlot]!), key(acc[mintSlot + 1]!), key(acc[programSlot]!), key(acc[programSlot + 1]!)];
      rule(isTokenProgram(inProgram) && isTokenProgram(outProgram), "unknown token program in the swap");
      rule(!equal(inMint, outMint), "a swap needs two different tokens");
      rule(equal(key(acc[sourceSlot]!), associatedTokenAddress(signer, inMint, inProgram)), "a swap must spend from the vault's own token account");
      rule(equal(key(acc[destSlot]!), associatedTokenAddress(signer, outMint, outProgram)), "a swap must pay into the vault's own token account");
      if (shared) {
        const authority = findProgramAddress([utf8("authority"), Uint8Array.of(id)], base58Decode(JUPITER_PROGRAM)).address;
        rule(equal(key(acc[0]!), authority), "shared_accounts_route_v2 must use Jupiter's program authority for its id");
        rule(equal(key(acc[3]!), associatedTokenAddress(authority, inMint, inProgram)) && equal(key(acc[4]!), associatedTokenAddress(authority, outMint, outProgram)),
          "shared_accounts_route_v2 must route through Jupiter's own token accounts");
      } else {
        // An account here would receive the output instead of the vault's own token account.
        rule(b58(key(acc[7]!)) === JUPITER_PROGRAM, "a swap must not redirect its output to another account");
      }
      rule(positiveSlippageBps === 0, "a swap must not give away positive slippage");
      rule(inAmount > 0n && quotedOut > 0n, "a swap needs amounts above zero");
      rule(slippageBps < 10_000, "slippage must be below 100%");
      let feeMint: Uint8Array | undefined;
      if (feeBps > 0) {
        const cap = state.maxSwapFeeBps ?? DEFAULT_MAX_SWAP_FEE_BPS;
        rule(feeBps <= cap, `the swap fee is above the vault's limit of ${cap} basis points`);
        rule(state.swapFeeOwner !== undefined, "this vault doesn't allow swap fees");
        const feeAccount = key(acc[feeSlot]!);
        if (equal(feeAccount, associatedTokenAddress(state.swapFeeOwner!, inMint, inProgram))) feeMint = inMint;
        else if (equal(feeAccount, associatedTokenAddress(state.swapFeeOwner!, outMint, outProgram))) feeMint = outMint;
        else rule(false, "the swap fee must go to isol8's fee account for one of the two tokens");
      }
      return { t: "swap", inMint, outMint, inAmount, quotedOut, slippageBps, feeBps, feeMint };
    }

    return decline(DECLINE_UNSUPPORTED, `unknown program ${b58(program)}`);
  });

  // ---- rules across instructions ----
  for (const it of items) rule(it.t !== "advance" || it.index === 0, "AdvanceNonceAccount must be the first instruction");
  const first = items[0];
  const durable = first?.t === "advance";
  rule(items.filter((i) => i.t === "cu_limit").length <= 1 && items.filter((i) => i.t === "cu_price").length <= 1, "duplicate compute budget instruction");
  const swaps = items.filter((i) => i.t === "swap");
  rule(swaps.length <= 1, "at most one swap per transaction");
  const swap = swaps[0];
  const swapUsesSol = swap?.t === "swap" && (b58(swap.inMint) === WSOL_MINT || b58(swap.outMint) === WSOL_MINT);
  rule(swapUsesSol || !items.some((i) => i.t === "wrap" || i.t === "sync"), "wrapping SOL only as part of a swap involving SOL");
  // Decimals come from the vault's own list or an on-chain check in this transaction, never from the hot side alone.
  const decimalsOf = (mint: Uint8Array): number => {
    const known = KNOWN_DECIMALS[b58(mint)];
    if (known !== undefined) return known;
    const check = items.find((i) => i.t === "decimals" && equal(i.mint, mint));
    return check?.t === "decimals" ? check.decimals : decline(DECLINE_RULE, `the swap needs a decimals check for ${b58(mint)}`);
  };

  const actions: Action[] = [];
  const createdAtas: { program: Uint8Array; ata: Uint8Array; owner: Uint8Array; mint: Uint8Array }[] = [];
  for (let i = 0; i < items.length; i++) {
    const it = items[i]!;
    switch (it.t) {
      case "advance":
      case "cu_limit":
      case "cu_price":
        break;
      case "sol_transfer":
        actions.push({ kind: "sol_transfer", to: b58(it.to), lamports: it.lamports.toString() });
        break;
      case "create_with_seed": {
        const next = items[i + 1];
        rule(next?.t === "init_nonce" && equal(next.nonce, it.created), "a created account must be initialized as a nonce account right after");
        actions.push({ kind: "create_nonce_account", account: b58(it.created), seed: it.seed, lamports: it.lamports.toString(), authority: b58(signer) });
        i++; // the init_nonce is part of this action
        break;
      }
      case "init_nonce":
        rule(false, "InitializeNonceAccount must follow CreateAccountWithSeed");
        break;
      case "create_ata": {
        createdAtas.push(it);
        const a: Action = { kind: "create_token_account", owner: b58(it.owner), mint: b58(it.mint), account: b58(it.ata), rent_payer: b58(signer) };
        const symbol = KNOWN_MINTS[b58(it.mint)];
        if (symbol) a.mint_symbol = symbol;
        actions.push(a);
        break;
      }
      case "transfer_checked": {
        const named = createdAtas.find((c) => equal(c.ata, it.dest) && equal(c.mint, it.mint) && equal(c.program, it.program));
        rule(named !== undefined, "every token destination needs a CreateIdempotent naming its owner");
        const a: Action = {
          kind: "token_transfer",
          mint: b58(it.mint),
          amount: it.amount.toString(),
          decimals: it.decimals,
          to_owner: b58(named!.owner),
          to_account: b58(it.dest),
        };
        const symbol = KNOWN_MINTS[b58(it.mint)];
        if (symbol) a.mint_symbol = symbol;
        actions.push(a);
        break;
      }
      case "memo":
        actions.push({ kind: "memo", text: it.text });
        break;
      case "wrap":
        actions.push({ kind: "wrap_sol", lamports: it.lamports.toString() });
        break;
      case "withdraw_nonce":
        actions.push({ kind: "withdraw_nonce_account", account: b58(it.nonce), lamports: it.lamports.toString() });
        break;
      case "close":
        // Closing the vault's own wSOL account is an unwrap: its wrapped SOL and rent come back to the vault as SOL
        // (the token program closes a wSOL account even with a balance). Any other token account must be empty.
        actions.push(it.wsol ? { kind: "unwrap_sol" } : { kind: "close_token_account", account: b58(it.account) });
        break;
      case "sync":
      case "decimals":
        break;
      case "swap": {
        const minOut = (it.quotedOut * BigInt(10_000 - it.slippageBps) + 9_999n) / 10_000n;
        const a: Action = {
          kind: "swap",
          in_mint: b58(it.inMint),
          in_amount: it.inAmount.toString(),
          in_decimals: decimalsOf(it.inMint),
          out_mint: b58(it.outMint),
          quoted_out_amount: it.quotedOut.toString(),
          min_out_amount: minOut.toString(),
          out_decimals: decimalsOf(it.outMint),
          slippage_bps: it.slippageBps,
          fee_bps: it.feeBps,
        };
        if (it.feeMint) a.fee_mint = b58(it.feeMint);
        const inSymbol = KNOWN_MINTS[b58(it.inMint)];
        const outSymbol = KNOWN_MINTS[b58(it.outMint)];
        if (inSymbol) a.in_symbol = inSymbol;
        if (outSymbol) a.out_symbol = outSymbol;
        actions.push(a);
        break;
      }
    }
  }

  // One send per transaction, so a second can't hide below the one the user asked for.
  rule(actions.filter((a) => a.kind === "sol_transfer" || a.kind === "token_transfer").length <= 1, "at most one send per transaction");
  // A token account for someone else costs rent that never comes back: only for this transaction's send.
  for (const c of createdAtas) {
    rule(equal(c.owner, signer) || items.some((i) => i.t === "transfer_checked" && equal(i.dest, c.ata)), "a token account for someone else may only be opened for this transaction's send");
  }

  // ---- fee and warnings ----
  const limit = items.find((i) => i.t === "cu_limit");
  const price = items.find((i) => i.t === "cu_price");
  const units = BigInt(limit?.t === "cu_limit" ? Math.min(limit.units, MAX_COMPUTE_UNITS) : MAX_COMPUTE_UNITS);
  const micro = price?.t === "cu_price" ? price.microLamports : 0n;
  // v1 states its priority fee as a total in lamports; legacy as a price per compute unit.
  const priority = msg.version === 1 ? (msg.config?.priorityFeeLamports ?? 0n) : (units * micro + 999_999n) / 1_000_000n;
  const maxFee = BigInt(LAMPORTS_PER_SIGNATURE * msg.numRequiredSignatures) + priority;

  const warnings: Warning[] = [];
  if (swap?.t === "swap" && swap.slippageBps > HIGH_SLIPPAGE_BPS) {
    warnings.push({ code: "HIGH_SLIPPAGE", slippage_bps: swap.slippageBps, threshold_bps: HIGH_SLIPPAGE_BPS });
  }
  if (maxFee > state.highFeeThresholdLamports) {
    warnings.push({ code: "HIGH_FEE", max_fee_lamports: maxFee.toString(), threshold_lamports: state.highFeeThresholdLamports.toString() });
  }
  const known = [...state.heldSigners.map((k) => ({ label: "this vault", address: b58(k) })), ...state.addressBook.map((e) => ({ label: e.label, address: b58(e.address) }))];
  const checkDestination = (address: string): string | undefined => {
    const exact = known.find((k) => k.address === address);
    if (exact) return exact.label;
    for (const k of known) {
      // A few edits away is a typo (whatever the ends); same ends with a different middle is poisoning.
      const differences = editDistance(address, k.address, NEAR_MISS_EDITS);
      if (differences <= NEAR_MISS_EDITS) warnings.push({ code: "NEAR_MISS_ADDRESS", address, resembles: k.address, label: k.label, differences });
      else if (looksAlike(address, k.address)) warnings.push({ code: "LOOKALIKE_ADDRESS", address, resembles: k.address, label: k.label });
    }
    return undefined;
  };
  for (const a of actions) {
    if (a.kind === "sol_transfer") {
      const label = checkDestination(a.to);
      if (label) a.to_label = label;
    } else if (a.kind === "token_transfer") {
      const label = checkDestination(a.to_owner);
      if (label) a.to_label = label;
    }
  }

  const accepted: Decision = { decision: "accept", lifetime: durable ? "durable_nonce" : "recent_blockhash", max_fee_lamports: maxFee.toString(), actions, warnings };
  if (durable && first?.t === "advance") accepted.nonce_account = b58(first.nonce);
  return accepted;
}

/**
 * Up to this many character edits from a known address is a near miss. Unrelated addresses differ in about 43 of 44
 * characters, so this only happens through a typo, a bad edit or a deliberate lookalike: never by chance.
 */
export const NEAR_MISS_EDITS = 4;

/** Levenshtein distance (changed, missing or extra characters), or limit + 1 once it's known to exceed limit. */
export function editDistance(a: string, b: string, limit: number): number {
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
      rowMin = Math.min(rowMin, cur[j]!);
    }
    if (rowMin > limit) return limit + 1;
    prev = cur;
  }
  return prev[b.length]!;
}

/** Address poisoning: different addresses whose first 4 and last 4 Base58 characters match. */
export function looksAlike(a: string, b: string): boolean {
  return a !== b && a.slice(0, 4) === b.slice(0, 4) && a.slice(-4) === b.slice(-4);
}
