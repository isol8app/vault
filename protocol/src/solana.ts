// Minimal Solana helpers for building test vectors: addresses, PDAs, instructions and message compilation.
// Dependency-free; cross-checked against @solana/kit by scripts/crosscheck-kit.ts.
import { address } from "./base58.ts";
import { concat, toHex, u16le, u32le, u64le, u8, utf8 } from "./bytes.ts";
import { sha256 } from "./crypto.ts";

export const SYSTEM_PROGRAM = address("11111111111111111111111111111111");
export const COMPUTE_BUDGET_PROGRAM = address("ComputeBudget111111111111111111111111111111");
export const TOKEN_PROGRAM = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const TOKEN_2022_PROGRAM = address("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const ASSOCIATED_TOKEN_PROGRAM = address("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const MEMO_PROGRAM = address("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
export const SYSVAR_RECENT_BLOCKHASHES = address("SysvarRecentB1ockHashes11111111111111111111");
export const SYSVAR_RENT = address("SysvarRent111111111111111111111111111111111");

/** Space and rent-exempt minimum for a nonce account. */
export const NONCE_ACCOUNT_SPACE = 80;
export const NONCE_ACCOUNT_RENT_LAMPORTS = 1_447_680;
/** Base fee per signature. */
export const LAMPORTS_PER_SIGNATURE = 5_000;

// ---- ed25519 point check, matching curve25519-dalek's CompressedEdwardsY::decompress ----

const P = 2n ** 255n - 19n;
const mod = (a: bigint): bigint => ((a % P) + P) % P;
function pow(base: bigint, exp: bigint): bigint {
  let r = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}
const D = mod(-121665n * pow(121666n, P - 2n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

/** True if the 32 bytes decompress to a point on the curve (so it can't be a PDA). */
export function isOnCurve(bytes: Uint8Array): boolean {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? bytes[i]! & 0x7f : bytes[i]!);
  y = mod(y); // dalek reduces non-canonical y instead of rejecting it
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const v3 = (((v * v) % P) * v) % P;
  const v7 = (((v3 * v3) % P) * v) % P;
  let x = (((u * v3) % P) * pow((u * v7) % P, (P - 5n) / 8n)) % P;
  const vx2 = (((v * x) % P) * x) % P;
  if (vx2 === u) return true;
  if (vx2 === mod(-u)) {
    x = (x * SQRT_M1) % P;
    return true;
  }
  return false;
}

export function findProgramAddress(seeds: Uint8Array[], programId: Uint8Array): { address: Uint8Array; bump: number } {
  for (const s of seeds) if (s.length > 32) throw new Error("PDA seed longer than 32 bytes");
  for (let bump = 255; bump >= 0; bump--) {
    const candidate = sha256(...seeds, Uint8Array.of(bump), programId, utf8("ProgramDerivedAddress"));
    if (!isOnCurve(candidate)) return { address: candidate, bump };
  }
  throw new Error("no viable PDA bump");
}

export function associatedTokenAddress(owner: Uint8Array, mint: Uint8Array, tokenProgram: Uint8Array): Uint8Array {
  return findProgramAddress([owner, tokenProgram, mint], ASSOCIATED_TOKEN_PROGRAM).address;
}

/** System program "create with seed" address: SHA-256(base || seed || owner). */
export function createWithSeed(base: Uint8Array, seed: string, owner: Uint8Array): Uint8Array {
  const s = utf8(seed);
  if (s.length > 32) throw new Error("seed longer than 32 bytes");
  return sha256(base, s, owner);
}

// ---- instructions ----

export type AccountMeta = { pubkey: Uint8Array; isSigner: boolean; isWritable: boolean };
export type Instruction = { programId: Uint8Array; accounts: AccountMeta[]; data: Uint8Array };

const w = (pubkey: Uint8Array, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: true });
const r = (pubkey: Uint8Array, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: false });

export const ix = {
  systemTransfer: (from: Uint8Array, to: Uint8Array, lamports: bigint): Instruction => ({
    programId: SYSTEM_PROGRAM,
    accounts: [w(from, true), w(to)],
    data: concat(u32le(2), u64le(lamports)),
  }),
  advanceNonce: (nonce: Uint8Array, authority: Uint8Array): Instruction => ({
    programId: SYSTEM_PROGRAM,
    accounts: [w(nonce), r(SYSVAR_RECENT_BLOCKHASHES), r(authority, true)],
    data: u32le(4),
  }),
  createAccountWithSeed: (
    funder: Uint8Array,
    created: Uint8Array,
    base: Uint8Array,
    seed: string,
    lamports: bigint,
    space: bigint,
    owner: Uint8Array,
  ): Instruction => {
    const s = utf8(seed);
    return {
      programId: SYSTEM_PROGRAM,
      accounts: [w(funder, true), w(created), r(base, true)],
      data: concat(u32le(3), base, u64le(s.length), s, u64le(lamports), u64le(space), owner),
    };
  },
  initializeNonce: (nonce: Uint8Array, authority: Uint8Array): Instruction => ({
    programId: SYSTEM_PROGRAM,
    accounts: [w(nonce), r(SYSVAR_RECENT_BLOCKHASHES), r(SYSVAR_RENT)],
    data: concat(u32le(6), authority),
  }),
  withdrawNonce: (nonce: Uint8Array, to: Uint8Array, authority: Uint8Array, lamports: bigint): Instruction => ({
    programId: SYSTEM_PROGRAM,
    accounts: [w(nonce), w(to), r(SYSVAR_RECENT_BLOCKHASHES), r(SYSVAR_RENT), r(authority, true)],
    data: concat(u32le(5), u64le(lamports)),
  }),
  setComputeUnitLimit: (units: number): Instruction => ({
    programId: COMPUTE_BUDGET_PROGRAM,
    accounts: [],
    data: concat(u8(2), u32le(units)),
  }),
  setComputeUnitPrice: (microLamports: bigint): Instruction => ({
    programId: COMPUTE_BUDGET_PROGRAM,
    accounts: [],
    data: concat(u8(3), u64le(microLamports)),
  }),
  tokenTransferChecked: (
    source: Uint8Array,
    mint: Uint8Array,
    destination: Uint8Array,
    owner: Uint8Array,
    amount: bigint,
    decimals: number,
    tokenProgram: Uint8Array,
  ): Instruction => ({
    programId: tokenProgram,
    accounts: [w(source), r(mint), w(destination), r(owner, true)],
    data: concat(u8(12), u64le(amount), u8(decimals)),
  }),
  /** CloseAccount: the account's rent goes to `destination`; refused by the token program if it holds tokens. */
  closeAccount: (account: Uint8Array, destination: Uint8Array, owner: Uint8Array, tokenProgram: Uint8Array): Instruction => ({
    programId: tokenProgram,
    accounts: [w(account), w(destination), r(owner, true)],
    data: u8(9),
  }),
  /** Plain Transfer: carries no mint or decimals, so the vault must refuse it. */
  tokenTransfer: (source: Uint8Array, destination: Uint8Array, owner: Uint8Array, amount: bigint): Instruction => ({
    programId: TOKEN_PROGRAM,
    accounts: [w(source), w(destination), r(owner, true)],
    data: concat(u8(3), u64le(amount)),
  }),
  createAtaIdempotent: (payer: Uint8Array, ata: Uint8Array, owner: Uint8Array, mint: Uint8Array, tokenProgram: Uint8Array): Instruction => ({
    programId: ASSOCIATED_TOKEN_PROGRAM,
    accounts: [w(payer, true), w(ata), r(owner), r(mint), r(SYSTEM_PROGRAM), r(tokenProgram)],
    data: u8(1),
  }),
  memo: (text: string): Instruction => ({ programId: MEMO_PROGRAM, accounts: [], data: utf8(text) }),
};

// ---- message compilation ----

export function compactU16(n: number): Uint8Array {
  if (n < 0 || n > 0xffff) throw new Error(`compact-u16 out of range: ${n}`);
  const out: number[] = [];
  let v = n;
  for (;;) {
    const b = v & 0x7f;
    v >>= 7;
    if (v === 0) {
      out.push(b);
      break;
    }
    out.push(b | 0x80);
  }
  return Uint8Array.from(out);
}

export type LookupTable = {
  table: Uint8Array;
  /** Addresses loaded from the table as writable, in table index order. */
  writable: { index: number; address: Uint8Array }[];
};

/** v1 (SIMD-0385) header config, set instead of ComputeBudget instructions. */
export type V1ConfigSpec = { priorityFeeLamports?: bigint; computeUnitLimit?: number; loadedAccountsDataSizeLimit?: number; heapSize?: number };

export type MessageSpec = {
  /** A v1 transaction message (SIMD-0385): version byte 0x81, fixed-width fields, config in the header. */
  v1?: V1ConfigSpec;
  feePayer: Uint8Array;
  /** Recent blockhash, or the nonce value for durable-nonce transactions. */
  lifetime: Uint8Array;
  instructions: Instruction[];
  /** Legacy unless a lookup table is given (or v0 is set), which produces a v0 message. */
  lookup?: LookupTable;
  v0?: boolean;
};

/** Compile a message. Account order: fee payer, then writable signers, readonly signers, writable, readonly. */
export function compileMessage(spec: MessageSpec): Uint8Array {
  type Meta = { pubkey: Uint8Array; isSigner: boolean; isWritable: boolean; order: number };
  const metas = new Map<string, Meta>();
  const add = (pubkey: Uint8Array, isSigner: boolean, isWritable: boolean) => {
    const key = toHex(pubkey);
    const m = metas.get(key);
    if (m) {
      m.isSigner ||= isSigner;
      m.isWritable ||= isWritable;
    } else {
      metas.set(key, { pubkey, isSigner, isWritable, order: metas.size });
    }
  };
  add(spec.feePayer, true, true);
  for (const instruction of spec.instructions) {
    for (const a of instruction.accounts) add(a.pubkey, a.isSigner, a.isWritable);
    add(instruction.programId, false, false);
  }

  const loaded = new Set((spec.lookup?.writable ?? []).map((l) => toHex(l.address)));
  const category = (m: Meta) => (m.isSigner ? (m.isWritable ? 0 : 1) : m.isWritable ? 2 : 3);
  const feePayerKey = toHex(spec.feePayer);
  const staticKeys = [...metas.entries()]
    .filter(([key]) => !loaded.has(key))
    .map(([, m]) => m)
    .sort((a, b) => {
      const af = toHex(a.pubkey) === feePayerKey ? 0 : 1;
      const bf = toHex(b.pubkey) === feePayerKey ? 0 : 1;
      return af - bf || category(a) - category(b) || a.order - b.order;
    });

  const indexOf = new Map<string, number>();
  staticKeys.forEach((m, i) => indexOf.set(toHex(m.pubkey), i));
  (spec.lookup?.writable ?? []).forEach((l, i) => indexOf.set(toHex(l.address), staticKeys.length + i));

  const numSigners = staticKeys.filter((m) => m.isSigner).length;
  const numReadonlySigned = staticKeys.filter((m) => category(m) === 1).length;
  const numReadonlyUnsigned = staticKeys.filter((m) => category(m) === 3).length;

  const parts: Uint8Array[] = [];
  if (spec.v1) {
    const c = spec.v1;
    let mask = 0;
    const values: Uint8Array[] = [];
    if (c.priorityFeeLamports !== undefined) { mask |= 3; values.push(u64le(c.priorityFeeLamports)); }
    if (c.computeUnitLimit !== undefined) { mask |= 4; values.push(u32le(c.computeUnitLimit)); }
    if (c.loadedAccountsDataSizeLimit !== undefined) { mask |= 8; values.push(u32le(c.loadedAccountsDataSizeLimit)); }
    if (c.heapSize !== undefined) { mask |= 16; values.push(u32le(c.heapSize)); }
    parts.push(u8(0x81), Uint8Array.of(numSigners, numReadonlySigned, numReadonlyUnsigned), u32le(mask), spec.lifetime);
    parts.push(u8(spec.instructions.length), u8(staticKeys.length), ...staticKeys.map((m) => m.pubkey), ...values);
    for (const instruction of spec.instructions) {
      parts.push(u8(indexOf.get(toHex(instruction.programId))!), u8(instruction.accounts.length), u16le(instruction.data.length));
    }
    for (const instruction of spec.instructions) {
      parts.push(Uint8Array.from(instruction.accounts.map((a) => indexOf.get(toHex(a.pubkey))!)), instruction.data);
    }
    return concat(...parts);
  }
  const v0 = spec.v0 || spec.lookup !== undefined;
  if (v0) parts.push(u8(0x80)); // v0 prefix
  parts.push(Uint8Array.of(numSigners, numReadonlySigned, numReadonlyUnsigned));
  parts.push(compactU16(staticKeys.length), ...staticKeys.map((m) => m.pubkey));
  parts.push(spec.lifetime);
  parts.push(compactU16(spec.instructions.length));
  for (const instruction of spec.instructions) {
    parts.push(u8(indexOf.get(toHex(instruction.programId))!));
    parts.push(compactU16(instruction.accounts.length), Uint8Array.from(instruction.accounts.map((a) => indexOf.get(toHex(a.pubkey))!)));
    parts.push(compactU16(instruction.data.length), instruction.data);
  }
  if (spec.lookup) {
    parts.push(compactU16(1), spec.lookup.table);
    parts.push(compactU16(spec.lookup.writable.length), Uint8Array.from(spec.lookup.writable.map((l) => l.index)));
    parts.push(compactU16(0));
  } else if (v0) {
    parts.push(compactU16(0)); // v0 with no lookup tables
  }
  return concat(...parts);
}

/** Maximum total fee in lamports: signature fees plus priority fee (price in micro-lamports × unit limit). */
export function maxFeeLamports(signatures: number, unitLimit?: number, microLamportsPerUnit?: bigint): bigint {
  const priority = unitLimit !== undefined && microLamportsPerUnit !== undefined
    ? (BigInt(unitLimit) * microLamportsPerUnit + 999_999n) / 1_000_000n
    : 0n;
  return BigInt(signatures * LAMPORTS_PER_SIGNATURE) + priority;
}
