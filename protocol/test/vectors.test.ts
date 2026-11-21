import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { base45Decode, base45Encode } from "../src/base45.ts";
import { ProtocolError, fromHex, toHex } from "../src/bytes.ts";
import { decodeFrames } from "../src/frame.ts";
import { offchainMessageV0, verifyPairResponse } from "../src/pairing.ts";
import { decodePayload, type PairRequest, type PairResponse, type SignTxRequest, type SignTxResponse } from "../src/payload.ts";
import { verifySignTxResponse } from "../src/signing.ts";
import { buildVectors } from "../src/vectors.ts";

const load = (file: string) => JSON.parse(readFileSync(new URL(`../vectors/${file}`, import.meta.url), "utf8"));

function expectCode(fn: () => unknown, code: string) {
  assert.throws(fn, (e: unknown) => e instanceof ProtocolError && e.code === code, `expected ${code}`);
}

test("committed vectors match the generator (run `npm run vectors` if this fails)", () => {
  for (const [file, data] of Object.entries(buildVectors())) {
    assert.deepEqual(load(file), JSON.parse(JSON.stringify(data)), file);
  }
});

test("base45 vectors", () => {
  const v = load("base45.json");
  for (const c of v.valid) {
    assert.equal(base45Encode(fromHex(c.bytes_hex)), c.text);
    assert.equal(toHex(base45Decode(c.text)), c.bytes_hex);
  }
  for (const c of v.invalid) expectCode(() => base45Decode(c.text), c.error);
});

test("RFC 9285 examples", () => {
  assert.equal(base45Encode(new TextEncoder().encode("AB")), "BB8");
  assert.equal(base45Encode(new TextEncoder().encode("Hello!!")), "%69 VD92EX0");
  assert.equal(base45Encode(new TextEncoder().encode("base-45")), "UJCLQE7W581");
  assert.equal(new TextDecoder().decode(base45Decode("QED8WEX0")), "ietf!");
});

test("pairing vectors", () => {
  const v = load("pairing.json");
  const request = decodePayload(decodeFrames(v.request.frames)) as PairRequest;
  assert.equal(request.type, "pair_request");
  assert.equal(request.origin, v.origin);
  assert.equal(toHex(request.challenge), v.challenge_hex);

  const response = decodePayload(decodeFrames(v.response.frames)) as PairResponse;
  assert.equal(response.type, "pair_response");
  assert.equal(toHex(response.pubkey), v.response.pubkey_hex);
  assert.equal(toHex(offchainMessageV0(v.statement, response.pubkey)), v.offchain_message_hex);
  assert.ok(verifyPairResponse(request, response));

  const tampered = { ...response, signature: response.signature.slice() };
  tampered.signature[0]! ^= 1;
  assert.ok(!verifyPairResponse(request, tampered));
  assert.ok(!verifyPairResponse({ ...request, origin: "isol8-app.example" }, response), "a different origin must not verify");
});

test("transaction vectors", () => {
  for (const c of load("transactions.json")) {
    const request = decodePayload(decodeFrames(c.request.frames)) as SignTxRequest;
    assert.equal(request.type, "sign_tx_request", c.name);
    assert.equal(toHex(request.message), c.message_hex, c.name);
    assert.equal(request.message.length, c.message_len, c.name);
    if (c.expected.decision === "accept") {
      const response = decodePayload(decodeFrames(c.response.frames)) as SignTxResponse;
      assert.equal(c.response.frames.length, 1, `${c.name}: responses fit one frame`);
      assert.ok(verifySignTxResponse(request, response), c.name);
      const wrongMessage = { ...request, message: request.message.slice(0, -1) };
      assert.ok(!verifySignTxResponse(wrongMessage, response), `${c.name}: must not verify against another message`);
    } else {
      const declined = decodePayload(decodeFrames(c.declined.frames));
      assert.equal(declined.type, "sign_tx_declined", c.name);
      assert.equal(declined.type === "sign_tx_declined" && declined.reason, c.expected.reason, c.name);
    }
  }
});

test("invalid vectors are rejected with the expected code", () => {
  for (const c of load("invalid.json")) {
    expectCode(() => decodePayload(decodeFrames(c.frames)), c.error);
  }
});
