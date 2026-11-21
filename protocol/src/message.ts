// Strict parser for Solana transaction messages (legacy, v0 and v1 / SIMD-0385), as the vault would run it.
// Rejects anything malformed with ProtocolError("MALFORMED_MESSAGE"). Bounds are checked before every read.
import { ProtocolError, Reader, toHex } from "./bytes.ts";

export type CompiledInstruction = { programIdIndex: number; accounts: number[]; data: Uint8Array };
export type AddressTableLookup = { table: Uint8Array; writable: number[]; readonly: number[] };

/** v1 transaction config (SIMD-0385): what legacy transactions set with ComputeBudget instructions. */
export type V1Config = {
  priorityFeeLamports?: bigint;
  computeUnitLimit?: number;
  loadedAccountsDataSizeLimit?: number;
  heapSize?: number;
};

export type ParsedMessage = {
  version: "legacy" | 0 | 1;
  /** v1 only. */
  config?: V1Config;
  numRequiredSignatures: number;
  numReadonlySigned: number;
  numReadonlyUnsigned: number;
  staticKeys: Uint8Array[];
  lifetime: Uint8Array;
  instructions: CompiledInstruction[];
  lookups: AddressTableLookup[];
};

function malformed(why: string): never {
  throw new ProtocolError("MALFORMED_MESSAGE", why);
}

/** Solana short_vec: at most 3 bytes, canonical encoding only, value at most 0xffff. */
export function readCompactU16(r: Reader): number {
  let value = 0;
  for (let i = 0; i < 3; i++) {
    const byte = r.u8();
    value |= (byte & 0x7f) << (7 * i);
    if ((byte & 0x80) === 0) {
      if (i > 0 && byte === 0) malformed("non-canonical compact-u16");
      if (value > 0xffff) malformed("compact-u16 out of range");
      return value;
    }
    if (i === 2) malformed("compact-u16 longer than 3 bytes");
  }
  return malformed("unreachable");
}

function readIndexes(r: Reader): number[] {
  const n = readCompactU16(r);
  if (n > r.remaining) malformed("index list longer than the message");
  return Array.from(r.take(n));
}

export function parseMessage(bytes: Uint8Array): ParsedMessage {
  try {
    return parse(bytes);
  } catch (e) {
    if (e instanceof ProtocolError && e.code !== "MALFORMED_MESSAGE") malformed(e.message);
    throw e;
  }
}

/** SIMD-0385: version byte 0x81, fixed-width fields, config in the header, no lookup tables. */
export const V1_MAX_ACCOUNTS = 64;
export const V1_MAX_INSTRUCTIONS = 64;
const V1_CONFIG_BITS = 0b11111; // priority fee (bits 0+1), CU limit, loaded data size, heap size

function parseV1(r: Reader): ParsedMessage {
  const numRequiredSignatures = r.u8();
  const numReadonlySigned = r.u8();
  const numReadonlyUnsigned = r.u8();
  const mask = r.u32();
  if (mask & ~V1_CONFIG_BITS) malformed(`unknown v1 config bits ${mask.toString(2)}`);
  if (((mask & 1) === 0) !== ((mask & 2) === 0)) malformed("the v1 priority fee needs both of its config bits");
  const lifetime = r.take(32);
  const ixCount = r.u8();
  const keyCount = r.u8();
  if (keyCount === 0 || keyCount > V1_MAX_ACCOUNTS) malformed(`account count ${keyCount}`);
  if (ixCount > V1_MAX_INSTRUCTIONS) malformed(`instruction count ${ixCount}`);
  const staticKeys: Uint8Array[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < keyCount; i++) {
    const key = r.take(32);
    const hex = toHex(key);
    if (seen.has(hex)) malformed("duplicate account key");
    seen.add(hex);
    staticKeys.push(key);
  }
  if (numRequiredSignatures < 1) malformed("no required signatures");
  if (numReadonlySigned >= numRequiredSignatures) malformed("the fee payer must be writable");
  if (numRequiredSignatures + numReadonlyUnsigned > keyCount) malformed("header counts exceed the account list");

  const config: V1Config = {};
  if (mask & 1) {
    const low = BigInt(r.u32());
    const high = BigInt(r.u32());
    config.priorityFeeLamports = (high << 32n) | low;
  }
  if (mask & 4) config.computeUnitLimit = r.u32();
  if (mask & 8) config.loadedAccountsDataSizeLimit = r.u32();
  if (mask & 16) {
    const heap = r.u32();
    if (heap % 1024 !== 0 || heap < 32 * 1024 || heap > 256 * 1024) malformed(`heap size ${heap}`);
    config.heapSize = heap;
  }

  const headers: { programIdIndex: number; numAccounts: number; dataLen: number }[] = [];
  for (let i = 0; i < ixCount; i++) headers.push({ programIdIndex: r.u8(), numAccounts: r.u8(), dataLen: r.u16() });
  const instructions: CompiledInstruction[] = headers.map((h) => ({
    programIdIndex: h.programIdIndex,
    accounts: Array.from(r.take(h.numAccounts)),
    data: r.take(h.dataLen),
  }));
  r.end();
  for (const ix of instructions) {
    if (ix.programIdIndex === 0 || ix.programIdIndex >= keyCount) malformed(`invalid program index ${ix.programIdIndex}`);
    for (const a of ix.accounts) if (a >= keyCount) malformed(`account index ${a} out of range`);
  }
  return { version: 1, config, numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned, staticKeys, lifetime, instructions, lookups: [] };
}

function parse(bytes: Uint8Array): ParsedMessage {
  const r = new Reader(bytes);
  if (bytes[0] === 0x81) {
    r.u8();
    return parseV1(r);
  }
  let version: "legacy" | 0 = "legacy";
  let first = r.u8();
  if (first & 0x80) {
    const v = first & 0x7f;
    if (v !== 0) malformed(`unsupported message version ${v}`);
    version = 0;
    first = r.u8();
  }
  const numRequiredSignatures = first;
  const numReadonlySigned = r.u8();
  const numReadonlyUnsigned = r.u8();

  const keyCount = readCompactU16(r);
  if (keyCount === 0 || keyCount > 256) malformed(`account count ${keyCount}`);
  if (keyCount * 32 > r.remaining) malformed("account list longer than the message");
  const staticKeys: Uint8Array[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < keyCount; i++) {
    const key = r.take(32);
    const hex = toHex(key);
    if (seen.has(hex)) malformed("duplicate account key");
    seen.add(hex);
    staticKeys.push(key);
  }
  if (numRequiredSignatures < 1) malformed("no required signatures");
  if (numReadonlySigned >= numRequiredSignatures) malformed("the fee payer must be writable");
  if (numRequiredSignatures + numReadonlyUnsigned > keyCount) malformed("header counts exceed the account list");

  const lifetime = r.take(32);

  const ixCount = readCompactU16(r);
  if (ixCount > r.remaining) malformed("instruction count longer than the message");
  const instructions: CompiledInstruction[] = [];
  for (let i = 0; i < ixCount; i++) {
    const programIdIndex = r.u8();
    const accounts = readIndexes(r);
    const dataLen = readCompactU16(r);
    instructions.push({ programIdIndex, accounts, data: r.take(dataLen) });
  }

  const lookups: AddressTableLookup[] = [];
  if (version === 0) {
    const n = readCompactU16(r);
    if (n * 34 > r.remaining) malformed("lookup list longer than the message");
    for (let i = 0; i < n; i++) {
      lookups.push({ table: r.take(32), writable: readIndexes(r), readonly: readIndexes(r) });
    }
  }
  r.end();

  const loaded = lookups.reduce((sum, l) => sum + l.writable.length + l.readonly.length, 0);
  const totalKeys = keyCount + loaded;
  if (totalKeys > 256) malformed("too many accounts");
  for (const ix of instructions) {
    if (ix.programIdIndex === 0 || ix.programIdIndex >= keyCount) malformed(`invalid program index ${ix.programIdIndex}`);
    for (const a of ix.accounts) if (a >= totalKeys) malformed(`account index ${a} out of range`);
  }

  return { version, numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned, staticKeys, lifetime, instructions, lookups };
}
