// Byte helpers shared by the protocol implementation.

/** Error with a stable code. Codes are part of the test vectors and must match across implementations. */
export class ProtocolError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.code = code;
    this.name = "ProtocolError";
  }
}

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(text: string): Uint8Array {
  return utf8Encoder.encode(text);
}

export function fromUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error(`invalid hex: ${hex}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function u8(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff);
}

export function u16le(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff, (n >>> 8) & 0xff);
}

export function u32le(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
}

export function u64le(n: bigint | number): Uint8Array {
  let v = BigInt(n);
  if (v < 0n || v > 0xffffffffffffffffn) throw new Error(`u64 out of range: ${v}`);
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Bounds-checked reader. Every read checks the remaining length first. */
export class Reader {
  private offset = 0;
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  u8(): number {
    this.need(1);
    return this.bytes[this.offset++]!;
  }

  u16(): number {
    this.need(2);
    const v = this.bytes[this.offset]! | (this.bytes[this.offset + 1]! << 8);
    this.offset += 2;
    return v;
  }

  u32(): number {
    this.need(4);
    const b = this.bytes;
    const o = this.offset;
    const v = (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;
    this.offset += 4;
    return v;
  }

  take(n: number): Uint8Array {
    this.need(n);
    const out = this.bytes.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  end(): void {
    if (this.remaining !== 0) {
      throw new ProtocolError("TRAILING_BYTES", `${this.remaining} unexpected trailing byte(s)`);
    }
  }

  private need(n: number): void {
    if (n > this.remaining) {
      throw new ProtocolError("TRUNCATED", `needed ${n} byte(s), ${this.remaining} left`);
    }
  }
}
