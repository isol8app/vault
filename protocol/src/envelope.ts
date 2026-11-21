// Vault passphrase-envelope vectors, built with Node's own Argon2id and AES-GCM (OpenSSL) —
// independent of the vault's BouncyCastle Argon2 and the JDK/Android AES-GCM.
// Format: vault-android/crypto/src/main/kotlin/app/isol8/vault/crypto/VaultEnvelope.kt
import { argon2Sync, createCipheriv } from "node:crypto";
import { concat, toHex, u16le, u32le, u8, utf8 } from "./bytes.ts";
import { sha256 } from "./crypto.ts";

type Params = { memoryKiB: number; iterations: number; parallelism: number };

function argon2id(passphrase: string, salt: Uint8Array, p: Params): Uint8Array {
  return new Uint8Array(
    argon2Sync("argon2id", {
      message: Buffer.from(utf8(passphrase.normalize("NFKD"))),
      nonce: Buffer.from(salt),
      parallelism: p.parallelism,
      tagLength: 32,
      memory: p.memoryKiB,
      passes: p.iterations,
    }),
  );
}

export function sealEnvelope(entropy: Uint8Array, bip39Passphrase: string, passphrase: string, p: Params, salt: Uint8Array, nonce: Uint8Array): Uint8Array {
  const header = concat(utf8("I8PV"), u8(1), u8(1), u32le(p.memoryKiB), u32le(p.iterations), u8(p.parallelism), salt, nonce);
  const b39 = utf8(bip39Passphrase);
  const record = concat(u8(1), u8(1), u8(entropy.length), entropy, u16le(b39.length), b39);
  const cipher = createCipheriv("aes-256-gcm", argon2id(passphrase, salt, p), nonce, { authTagLength: 16 });
  cipher.setAAD(header);
  return concat(header, new Uint8Array(cipher.update(record)), new Uint8Array(cipher.final()), new Uint8Array(cipher.getAuthTag()));
}

const label = (s: string) => sha256(utf8(`isol8 envelope vector: ${s}`));
const PRODUCTION: Params = { memoryKiB: 65536, iterations: 3, parallelism: 1 };

export function envelopeVectors() {
  const specs = [
    { name: "production_params_24_words", entropy: label("a"), bip39: "", passphrase: "correct horse battery staple", params: PRODUCTION, bounds: "production" },
    { name: "unicode_passphrase_with_bip39_passphrase", entropy: label("b").slice(0, 16), bip39: "TREZOR", passphrase: "Pässwörd ﬁ 金庫", params: { memoryKiB: 1024, iterations: 2, parallelism: 1 }, bounds: "test" },
    { name: "two_lanes_18_words", entropy: label("c").slice(0, 24), bip39: "", passphrase: "abcdefgh", params: { memoryKiB: 2048, iterations: 1, parallelism: 2 }, bounds: "test" },
  ];
  const valid = specs.map((s) => {
    const salt = label(`${s.name} salt`).slice(0, 16);
    const nonce = label(`${s.name} nonce`).slice(0, 12);
    return {
      name: s.name,
      entropy_hex: toHex(s.entropy),
      bip39_passphrase: s.bip39,
      passphrase: s.passphrase,
      params: s.params,
      bounds: s.bounds,
      salt_hex: toHex(salt),
      nonce_hex: toHex(nonce),
      envelope_hex: toHex(sealEnvelope(s.entropy, s.bip39, s.passphrase, s.params, salt, nonce)),
    };
  });

  const base = Uint8Array.from(Buffer.from(valid[0]!.envelope_hex, "hex"));
  const mutate = (f: (b: Uint8Array) => Uint8Array) => toHex(f(base.slice()));
  const set = (offset: number, value: number) => (b: Uint8Array) => ((b[offset] = value), b);
  // Header: magic 0-3, version 4, kdf 5, memory 6-9, iterations 10-13, parallelism 14, salt 15-30, nonce 31-42.
  const invalid = [
    { name: "wrong_passphrase", envelope_hex: valid[0]!.envelope_hex, passphrase: "correct horse battery stapler", error: "WRONG_PASSPHRASE_OR_TAMPERED" },
    { name: "bad_magic", envelope_hex: mutate(set(0, 0x58)), passphrase: valid[0]!.passphrase, error: "MALFORMED" },
    { name: "newer_version", envelope_hex: mutate(set(4, 2)), passphrase: valid[0]!.passphrase, error: "UNSUPPORTED_VERSION" },
    { name: "unknown_kdf", envelope_hex: mutate(set(5, 2)), passphrase: valid[0]!.passphrase, error: "UNSUPPORTED_VERSION" },
    { name: "memory_below_minimum", envelope_hex: mutate((b) => (b.set(u32le(8192), 6), b)), passphrase: valid[0]!.passphrase, error: "UNSAFE_PARAMETERS" },
    { name: "memory_absurd", envelope_hex: mutate((b) => (b.set(u32le(0xffffffff), 6), b)), passphrase: valid[0]!.passphrase, error: "UNSAFE_PARAMETERS" },
    { name: "iterations_lowered_in_bounds", envelope_hex: mutate(set(10, 2)), passphrase: valid[0]!.passphrase, error: "WRONG_PASSPHRASE_OR_TAMPERED" },
    { name: "salt_changed", envelope_hex: mutate((b) => ((b[20]! ^= 1), b)), passphrase: valid[0]!.passphrase, error: "WRONG_PASSPHRASE_OR_TAMPERED" },
    { name: "ciphertext_changed", envelope_hex: mutate((b) => ((b[50]! ^= 1), b)), passphrase: valid[0]!.passphrase, error: "WRONG_PASSPHRASE_OR_TAMPERED" },
    { name: "tag_changed", envelope_hex: mutate((b) => ((b[b.length - 1]! ^= 1), b)), passphrase: valid[0]!.passphrase, error: "WRONG_PASSPHRASE_OR_TAMPERED" },
    { name: "truncated", envelope_hex: toHex(base.slice(0, 50)), passphrase: valid[0]!.passphrase, error: "MALFORMED" },
  ];
  return {
    warning: "TEST VALUES ONLY. These passphrases and entropies are public.",
    format: "vault-android/crypto/src/main/kotlin/app/isol8/vault/crypto/VaultEnvelope.kt",
    valid,
    invalid,
  };
}
