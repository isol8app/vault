import { strict as assert } from "node:assert";
import { test } from "node:test";
import { BASE45_ALPHABET } from "../src/base45.ts";
import { ProtocolError, equal } from "../src/bytes.ts";
import { sha256 } from "../src/crypto.ts";
import { MAX_PAYLOAD, Reassembler, decodeFrames, encodeFrames } from "../src/frame.ts";

function bytes(n: number, tag = "x"): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 32) out.set(sha256(new TextEncoder().encode(`${tag}${i}`)).slice(0, Math.min(32, n - i)), i);
  return out;
}

test("round trip at boundary sizes, in shuffled order with duplicates", () => {
  for (const n of [1, 2, 255, 256, 257, 512, 1000, MAX_PAYLOAD]) {
    const payload = bytes(n, `size${n}`);
    const frames = encodeFrames(payload);
    assert.equal(frames.length, Math.ceil(n / 256));
    const shuffled = [...frames, ...frames].reverse();
    assert.ok(equal(decodeFrames(shuffled), payload), `size ${n}`);
  }
});

test("frames use only QR alphanumeric characters", () => {
  const allowed = new Set([...BASE45_ALPHABET]);
  for (const f of encodeFrames(bytes(1000))) for (const ch of f) assert.ok(allowed.has(ch), `unexpected ${ch}`);
});

test("payload size limits", () => {
  assert.throws(() => encodeFrames(new Uint8Array(0)), (e: unknown) => e instanceof ProtocolError && e.code === "BAD_LENGTH");
  assert.throws(() => encodeFrames(new Uint8Array(MAX_PAYLOAD + 1)), (e: unknown) => e instanceof ProtocolError && e.code === "BAD_LENGTH");
});

test("a frame from another payload starts collection over", () => {
  const a = encodeFrames(bytes(600, "a"));
  const b = encodeFrames(bytes(600, "b"));
  const r = new Reassembler();
  assert.deepEqual(r.add(a[0]!), { status: "partial", have: 1, total: 3 });
  assert.deepEqual(r.add(a[1]!), { status: "partial", have: 2, total: 3 });
  assert.deepEqual(r.add(b[0]!), { status: "partial", have: 1, total: 3 });
  r.add(b[1]!);
  const done = r.add(b[2]!);
  assert.equal(done.status, "complete");
  assert.ok(done.status === "complete" && equal(done.payload, bytes(600, "b")));
});
