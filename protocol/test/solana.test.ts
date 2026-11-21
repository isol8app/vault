import { strict as assert } from "node:assert";
import { test } from "node:test";
import { base58Decode, base58Encode } from "../src/base58.ts";
import { toHex } from "../src/bytes.ts";
import { publicKeyFromSeed, sha256 } from "../src/crypto.ts";
import { compactU16, isOnCurve } from "../src/solana.ts";

test("compact-u16 encoding", () => {
  assert.equal(toHex(compactU16(0)), "00");
  assert.equal(toHex(compactU16(127)), "7f");
  assert.equal(toHex(compactU16(128)), "8001");
  assert.equal(toHex(compactU16(16383)), "ff7f");
  assert.equal(toHex(compactU16(16384)), "808001");
  assert.equal(toHex(compactU16(65535)), "ffff03");
});

test("base58 round trip, including leading zeros", () => {
  assert.equal(base58Encode(new Uint8Array(32)), "11111111111111111111111111111111");
  for (let i = 0; i < 20; i++) {
    const b = sha256(new TextEncoder().encode(`b58 ${i}`));
    if (i % 4 === 0) b[0] = 0;
    assert.equal(toHex(base58Decode(base58Encode(b))), toHex(b));
  }
});

test("real public keys are on the curve", () => {
  for (let i = 0; i < 20; i++) {
    assert.ok(isOnCurve(publicKeyFromSeed(sha256(new TextEncoder().encode(`seed ${i}`)))));
  }
});
