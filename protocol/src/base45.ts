// Base45 (RFC 9285). Strict decoding: anything outside the spec is rejected.
import { ProtocolError } from "./bytes.ts";

export const BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

const INDEX = new Map<string, number>(Array.from(BASE45_ALPHABET, (c, i) => [c, i]));

export function base45Encode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 1 < bytes.length; i += 2) {
    const v = bytes[i]! * 256 + bytes[i + 1]!;
    out += BASE45_ALPHABET[v % 45]! + BASE45_ALPHABET[Math.floor(v / 45) % 45]! + BASE45_ALPHABET[Math.floor(v / 2025)]!;
  }
  if (i < bytes.length) {
    const v = bytes[i]!;
    out += BASE45_ALPHABET[v % 45]! + BASE45_ALPHABET[Math.floor(v / 45)]!;
  }
  return out;
}

export function base45Decode(text: string): Uint8Array {
  if (text.length % 3 === 1) {
    throw new ProtocolError("BAD_BASE45", `invalid length ${text.length}`);
  }
  const digits: number[] = [];
  for (const c of text) {
    const d = INDEX.get(c);
    if (d === undefined) throw new ProtocolError("BAD_BASE45", `invalid character ${JSON.stringify(c)}`);
    digits.push(d);
  }
  const out: number[] = [];
  for (let i = 0; i < digits.length; i += 3) {
    if (i + 2 < digits.length) {
      const v = digits[i]! + digits[i + 1]! * 45 + digits[i + 2]! * 2025;
      if (v > 0xffff) throw new ProtocolError("BAD_BASE45", `triple value ${v} out of range`);
      out.push(v >> 8, v & 0xff);
    } else {
      const v = digits[i]! + digits[i + 1]! * 45;
      if (v > 0xff) throw new ProtocolError("BAD_BASE45", `pair value ${v} out of range`);
      out.push(v);
    }
  }
  return Uint8Array.from(out);
}
