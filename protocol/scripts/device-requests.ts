// Development tool: signing requests for hands-on testing on a TEST device.
// Builds requests for any signer address (e.g. the public BIP39 test phrase's), so the vault's
// "accept" path can be exercised. Test data only: fake nonce values and recipients, nothing on chain.
// Usage: node scripts/device-requests.ts <signer base58> <out.json>
import { writeFileSync } from "node:fs";
import { base58Decode, base58Encode } from "../src/base58.ts";
import { toHex, utf8 } from "../src/bytes.ts";
import { publicKeyFromSeed, sha256 } from "../src/crypto.ts";
import { DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS, evaluateSignRequest } from "../src/acceptance.ts";
import { encodePayload, type SignTxRequest } from "../src/payload.ts";
import { VAULT } from "../src/vectors.ts";
import {
  NONCE_ACCOUNT_RENT_LAMPORTS,
  NONCE_ACCOUNT_SPACE,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  associatedTokenAddress,
  compileMessage,
  createWithSeed,
  ix,
  type Instruction,
} from "../src/solana.ts";

const [signerB58, out] = process.argv.slice(2);
if (!signerB58 || !out) throw new Error("usage: device-requests.ts <signer base58> <out.json>");
const SIGNER = base58Decode(signerB58);
if (SIGNER.length !== 32) throw new Error("signer must be a 32-byte address");

const label = (s: string) => sha256(utf8(`isol8 device test: ${s}`));
const RECIPIENT = publicKeyFromSeed(label("recipient"));
const UNKNOWN_MINT = publicKeyFromSeed(label("unknown mint"));
const UNKNOWN_PROGRAM = publicKeyFromSeed(label("unknown program"));
const USDC = base58Decode("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const NONCE_SEED = "isol8-nonce-0";
const NONCE = createWithSeed(SIGNER, NONCE_SEED, SYSTEM_PROGRAM);
const NONCE_VALUE = label("nonce value");
const BLOCKHASH = label("blockhash");
const advance = ix.advanceNonce(NONCE, SIGNER);

/** Same first and last 4 Base58 characters as [addr], different address: an address-poisoning lookalike. */
function lookalikeOf(addr: Uint8Array): Uint8Array {
  const text = base58Encode(addr);
  for (let pos = 10; pos < text.length - 10; pos++) {
    for (const c of "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") {
      if (c === text[pos]) continue;
      const candidate = text.slice(0, pos) + c + text.slice(pos + 1);
      const bytes = base58Decode(candidate);
      if (bytes.length === 32 && base58Encode(bytes) === candidate) return bytes;
    }
  }
  throw new Error("no lookalike found");
}
const LOOKALIKE = lookalikeOf(RECIPIENT);
const durable = (instructions: Instruction[]) => compileMessage({ feePayer: SIGNER, lifetime: NONCE_VALUE, instructions });

function tokenSend(mint: Uint8Array, amount: bigint, decimals: number): Instruction[] {
  const src = associatedTokenAddress(SIGNER, mint, TOKEN_PROGRAM);
  const dst = associatedTokenAddress(RECIPIENT, mint, TOKEN_PROGRAM);
  return [ix.createAtaIdempotent(SIGNER, dst, RECIPIENT, mint, TOKEN_PROGRAM), ix.tokenTransferChecked(src, mint, dst, SIGNER, amount, decimals, TOKEN_PROGRAM)];
}

const cases: { name: string; expect: string; signer: Uint8Array; message: Uint8Array }[] = [
  { name: "Send 1.5 SOL", expect: "accept, durable nonce", signer: SIGNER, message: durable([advance, ix.systemTransfer(SIGNER, RECIPIENT, 1_500_000_000n)]) },
  {
    name: "Send 250 USDC with a priority fee and a memo",
    expect: "accept, several frames, USDC named",
    signer: SIGNER,
    message: durable([advance, ix.setComputeUnitLimit(60_000), ix.setComputeUnitPrice(50_000n), ...tokenSend(USDC, 250_000_000n, 6), ix.memo("isol8 device test")]),
  },
  { name: "Send an unknown token", expect: "accept, mint shown by address", signer: SIGNER, message: durable([advance, ...tokenSend(UNKNOWN_MINT, 40_000_000_000_000n, 6)]) },
  {
    name: "Send 0.001 SOL with a huge priority fee",
    expect: "accept with a HIGH_FEE warning",
    signer: SIGNER,
    message: durable([advance, ix.setComputeUnitLimit(200_000), ix.setComputeUnitPrice(100_000_000n), ix.systemTransfer(SIGNER, RECIPIENT, 1_000_000n)]),
  },
  {
    name: "Activate: create the nonce account",
    expect: "accept, recent blockhash",
    signer: SIGNER,
    message: compileMessage({
      feePayer: SIGNER,
      lifetime: BLOCKHASH,
      instructions: [
        ix.createAccountWithSeed(SIGNER, NONCE, SIGNER, NONCE_SEED, BigInt(NONCE_ACCOUNT_RENT_LAMPORTS), BigInt(NONCE_ACCOUNT_SPACE), SYSTEM_PROGRAM),
        ix.initializeNonce(NONCE, SIGNER),
      ],
    }),
  },
  {
    name: "Send 0.5 SOL to a lookalike of the test recipient",
    expect: "accept; once the recipient is in the address book, a LOOKALIKE_ADDRESS warning",
    signer: SIGNER,
    message: durable([advance, ix.systemTransfer(SIGNER, LOOKALIKE, 500_000_000n)]),
  },
  {
    name: "Unknown program",
    expect: "refused: unsupported (reason 2)",
    signer: SIGNER,
    message: durable([advance, { programId: UNKNOWN_PROGRAM, accounts: [{ pubkey: SIGNER, isSigner: true, isWritable: true }], data: Uint8Array.of(1, 2, 3) }]),
  },
  {
    name: "Request for another vault's key",
    expect: "refused: key not held (reason 4)",
    signer: VAULT,
    message: compileMessage({ feePayer: VAULT, lifetime: NONCE_VALUE, instructions: [ix.advanceNonce(createWithSeed(VAULT, NONCE_SEED, SYSTEM_PROGRAM), VAULT), ix.systemTransfer(VAULT, RECIPIENT, 1_000_000n)] }),
  },
];

const state = { heldSigners: [SIGNER], addressBook: [], highFeeThresholdLamports: DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS };
const requests = cases.map((c) => {
  const request: SignTxRequest = { type: "sign_tx_request", requestId: label(`request ${c.name}`).slice(0, 16), signer: c.signer, message: c.message };
  // What the reference evaluator decides, so the device result can be compared with it.
  const d = evaluateSignRequest(request, state);
  const reference = d.decision === "accept" ? `accept${d.warnings?.length ? " + " + d.warnings.map((w) => w.code).join(", ") : ""}` : `decline ${d.reason}: ${d.why}`;
  console.log(`${c.name}: ${reference}`);
  return { name: c.name, expect: c.expect, reference, payload_hex: toHex(encodePayload(request)) };
});
// Wallet receive codes for the address book: plain QR text, not isol8 frames.
const address_codes = [
  { name: "Test recipient (Solana Pay link)", text: `solana:${base58Encode(RECIPIENT)}?label=Test%20recipient` },
  { name: "Lookalike of the test recipient (bare address)", text: base58Encode(LOOKALIKE) },
];
writeFileSync(out, JSON.stringify({ signer: base58Encode(SIGNER), recipient: base58Encode(RECIPIENT), lookalike: base58Encode(LOOKALIKE), requests, address_codes }, null, 2) + "\n");
console.log(`wrote ${requests.length} requests for ${base58Encode(SIGNER)} to ${out}`);
