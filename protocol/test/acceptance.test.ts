import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { evaluateSignRequest, looksAlike, type VaultState } from "../src/acceptance.ts";
import { address } from "../src/base58.ts";
import { fromHex } from "../src/bytes.ts";
import { ProtocolError, Reader } from "../src/bytes.ts";
import { sha256 } from "../src/crypto.ts";
import { readCompactU16 } from "../src/message.ts";
import type { SignTxRequest } from "../src/payload.ts";

const load = (file: string) => JSON.parse(readFileSync(new URL(`../vectors/${file}`, import.meta.url), "utf8"));
const common = load("common.json");
const state: VaultState = {
  heldSigners: common.vault_state.held_signers.map(address),
  addressBook: common.vault_state.address_book.map((e: { label: string; address: string }) => ({ label: e.label, address: address(e.address) })),
  highFeeThresholdLamports: BigInt(common.vault_state.high_fee_threshold_lamports),
};
const cases = load("transactions.json");

const requestOf = (c: { request: { request_id_hex: string; signer: string }; message_hex: string }): SignTxRequest => ({
  type: "sign_tx_request",
  requestId: fromHex(c.request.request_id_hex),
  signer: address(c.request.signer),
  message: fromHex(c.message_hex),
});

test("every transaction vector gets the expected decision", () => {
  for (const c of cases) {
    const d = evaluateSignRequest(requestOf(c), state);
    if (c.expected.decision === "accept") {
      assert.deepEqual(d, c.expected, c.name);
    } else {
      assert.equal(d.decision, "decline", `${c.name}: ${JSON.stringify(d)}`);
      assert.equal(d.decision === "decline" && d.reason, c.expected.reason, `${c.name}: ${d.decision === "decline" ? d.why : ""}`);
    }
  }
});

test("corrupted and random messages never crash the evaluator; random bytes are always declined", () => {
  const accepted = cases.filter((c: { expected: { decision: string } }) => c.expected.decision === "accept");
  let n = 0;
  for (const c of accepted) {
    const base = fromHex(c.message_hex);
    for (let i = 0; i < 400; i++) {
      const m = base.slice();
      const h = sha256(new TextEncoder().encode(`${c.name}:${i}`));
      const flips = 1 + (h[0]! % 3);
      for (let f = 0; f < flips; f++) m[(h[1 + f * 2]! * 256 + h[2 + f * 2]!) % m.length]! ^= 1 << (h[8 + f]! % 8);
      const d = evaluateSignRequest({ ...requestOf(c), message: m }, state);
      assert.ok(d.decision === "accept" || d.decision === "decline");
      if (d.decision === "accept") {
        // A corrupted message may still be valid (e.g. a changed amount), but it must still be shown in full.
        assert.ok(d.actions.length > 0 || c.expected.actions.length === 0, c.name);
      }
      n++;
    }
  }
  for (let i = 0; i < 2000; i++) {
    const len = 1 + (i % 400);
    const m = new Uint8Array(len).map((_, j) => sha256(new TextEncoder().encode(`rand ${i} ${Math.floor(j / 32)}`))[j % 32]!);
    const d = evaluateSignRequest({ type: "sign_tx_request", requestId: new Uint8Array(16), signer: state.heldSigners[0]!, message: m }, state);
    assert.equal(d.decision, "decline");
    n++;
  }
  assert.ok(n > 2000);
});

test("compact-u16 rejects non-canonical and oversized encodings", () => {
  const read = (...b: number[]) => readCompactU16(new Reader(Uint8Array.from(b)));
  assert.equal(read(0x00), 0);
  assert.equal(read(0x80, 0x01), 128);
  assert.equal(read(0xff, 0xff, 0x03), 0xffff);
  for (const bad of [[0x80, 0x00], [0x80, 0x80, 0x00], [0xff, 0xff, 0x04], [0x80, 0x80, 0x80, 0x01]]) {
    assert.throws(() => read(...bad), (e: unknown) => e instanceof ProtocolError);
  }
});

test("lookalike rule", () => {
  assert.ok(looksAlike("AbCdXXXXXXXXwXyZ", "AbCdYYYYYYYYwXyZ"));
  assert.ok(!looksAlike("AbCdXXXXXXXXwXyZ", "AbCdXXXXXXXXwXyZ"), "identical is not a lookalike");
  assert.ok(!looksAlike("AbCdXXXXXXXXwXyZ", "AbCeXXXXXXXXwXyZ"));
});

test("every swap vector gets the expected decision", () => {
  const swaps = load("swaps.json");
  const swapState: VaultState = { ...state, swapFeeOwner: address(swaps.fee_owner), maxSwapFeeBps: swaps.max_swap_fee_bps };
  assert.ok(swaps.cases.length >= 10);
  for (const c of swaps.cases) {
    const d = evaluateSignRequest(requestOf(c), swapState);
    if (c.expected.decision === "accept") {
      assert.deepEqual(d, c.expected, c.name);
    } else {
      assert.equal(d.decision, "decline", `${c.name}: ${JSON.stringify(d)}`);
      assert.equal(d.decision === "decline" && d.reason, c.expected.reason, c.name);
      assert.equal(d.decision === "decline" && d.why, c.expected.why, c.name);
    }
  }
});

test("a vault without a fee owner refuses any swap fee, and signs fee-free swaps", () => {
  const swaps = load("swaps.json");
  const withFee = swaps.cases.find((c: { name: string }) => c.name === "sol_to_usdc_fee");
  const noFee = swaps.cases.find((c: { name: string }) => c.name === "sol_to_usdc_no_fee");
  const d = evaluateSignRequest(requestOf(withFee), state);
  assert.equal(d.decision === "decline" && d.why, "this vault doesn't allow swap fees");
  assert.equal(evaluateSignRequest(requestOf(noFee), state).decision, "accept");
});
