// Solana key derivation vectors, computed with Node's own crypto (pbkdf2Sync, createHmac, ed25519) —
// independent of the vault's Kotlin PBKDF2/SLIP-0010 code and of BouncyCastle.
import { createHmac, pbkdf2Sync } from "node:crypto";
import { readFileSync } from "node:fs";
import { base58Encode } from "./base58.ts";
import { concat, toHex, utf8 } from "./bytes.ts";
import { ed25519Sign, publicKeyFromSeed } from "./crypto.ts";

export function bip39Seed(mnemonic: string, passphrase: string): Uint8Array {
  return new Uint8Array(pbkdf2Sync(mnemonic.normalize("NFKD"), ("mnemonic" + passphrase).normalize("NFKD"), 2048, 64, "sha512"));
}

function hmac512(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha512", key).update(data).digest());
}

export function slip10Ed25519(seed: Uint8Array, path: string): Uint8Array {
  let i = hmac512(utf8("ed25519 seed"), seed);
  let key = i.slice(0, 32);
  let chain = i.slice(32);
  for (const part of path.split("/").slice(1)) {
    if (!part.endsWith("'")) throw new Error("hardened only");
    const index = (Number(part.slice(0, -1)) + 0x80000000) >>> 0;
    const be = Uint8Array.of(index >>> 24, (index >>> 16) & 0xff, (index >>> 8) & 0xff, index & 0xff);
    i = hmac512(chain, concat(Uint8Array.of(0), key, be));
    key = i.slice(0, 32);
    chain = i.slice(32);
  }
  return key;
}

export const SIGNED_MESSAGE = "isol8 key vector";

export function keyVectors() {
  // Mnemonics from the official BIP39 English vectors (the vault's Kotlin test resources hold the full set).
  const official = JSON.parse(readFileSync(new URL("../../vault-android/core/src/test/resources/bip39-vectors.json", import.meta.url), "utf8"));
  const mnemonics: string[] = official.cases.filter((_: unknown, i: number) => [0, 1, 3, 12, 17, 23].includes(i)).map((c: { mnemonic: string }) => c.mnemonic);
  // NFC input whose NFKD form differs, so a byte-handling mismatch would change the seed.
  const passphrases = ["", "TREZOR", "Ünïcödé ﬁ パスワード"];
  const cases = [];
  for (const mnemonic of mnemonics) {
    for (const passphrase of passphrases) {
      const seed = bip39Seed(mnemonic, passphrase);
      for (const account of [0, 1]) {
        const path = `m/44'/501'/${account}'/0'`;
        const priv = slip10Ed25519(seed, path);
        cases.push({
          mnemonic,
          passphrase,
          account,
          path,
          seed_hex: toHex(seed),
          private_hex: toHex(priv),
          address: base58Encode(publicKeyFromSeed(priv)),
          signature_hex: toHex(ed25519Sign(priv, utf8(SIGNED_MESSAGE))),
        });
      }
    }
  }
  return { warning: "TEST PHRASES ONLY. These are public; never use them for real funds.", signed_message: SIGNED_MESSAGE, cases };
}
