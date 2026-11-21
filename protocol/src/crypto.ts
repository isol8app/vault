// SHA-256 and ed25519 via Node's built-in crypto. No third-party crypto.
import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { concat, fromHex } from "./bytes.ts";

const PKCS8_ED25519_PREFIX = fromHex("302e020100300506032b657004220420");
const SPKI_ED25519_PREFIX = fromHex("302a300506032b6570032100");

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

function privateKey(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) throw new Error(`ed25519 seed must be 32 bytes, got ${seed.length}`);
  return createPrivateKey({ key: Buffer.from(concat(PKCS8_ED25519_PREFIX, seed)), format: "der", type: "pkcs8" });
}

export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  const der = createPublicKey(privateKey(seed)).export({ format: "der", type: "spki" });
  return new Uint8Array(der).slice(-32);
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return new Uint8Array(sign(null, message, privateKey(seed)));
}

export function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = createPublicKey({ key: Buffer.from(concat(SPKI_ED25519_PREFIX, publicKey)), format: "der", type: "spki" });
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}
