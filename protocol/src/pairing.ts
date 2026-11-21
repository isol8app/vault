// Pairing (PROTOCOL.md §5): the vault signs a statement in Solana's off-chain message format (v0).
import { base58Encode } from "./base58.ts";
import { ProtocolError, concat, equal, toHex, u16le, u8, utf8 } from "./bytes.ts";
import { ed25519Sign, ed25519Verify, publicKeyFromSeed, sha256 } from "./crypto.ts";
import type { PairRequest, PairResponse } from "./payload.ts";

/** "\xff" + "solana offchain": cannot be the start of a valid transaction message. */
export const OFFCHAIN_SIGNING_DOMAIN = concat(Uint8Array.of(0xff), utf8("solana offchain"));
/** Off-chain message application domain for isol8: SHA-256("isol8.app"). */
export const APPLICATION_DOMAIN = sha256(utf8("isol8.app"));
const FORMAT_RESTRICTED_ASCII = 0;
const MAX_OFFCHAIN_TEXT = 1232;

export function pairingStatement(origin: string, pubkey: Uint8Array, challenge: Uint8Array): string {
  return `isol8 pairing; origin: ${origin}; account: ${base58Encode(pubkey)}; challenge: ${toHex(challenge)}`;
}

/** Off-chain message v0 bytes: domain, version 0, application domain, format, signers, length, text. */
export function offchainMessageV0(text: string, signer: Uint8Array): Uint8Array {
  if (!/^[\x20-\x7e]+$/.test(text)) throw new ProtocolError("BAD_FIELD", "off-chain text must be printable ASCII");
  const body = utf8(text);
  if (body.length > MAX_OFFCHAIN_TEXT) throw new ProtocolError("BAD_FIELD", "off-chain text too long");
  return concat(
    OFFCHAIN_SIGNING_DOMAIN,
    u8(0), // version
    APPLICATION_DOMAIN,
    u8(FORMAT_RESTRICTED_ASCII),
    u8(1), // signer count
    signer,
    u16le(body.length),
    body,
  );
}

/** Vault side: answer a pairing request. */
export function createPairResponse(
  seed: Uint8Array,
  request: PairRequest,
  accountIndex: number,
  appVersion: { major: number; minor: number },
): PairResponse {
  const pubkey = publicKeyFromSeed(seed);
  const message = offchainMessageV0(pairingStatement(request.origin, pubkey, request.challenge), pubkey);
  return { type: "pair_response", pubkey, accountIndex, appVersion, signature: ed25519Sign(seed, message) };
}

/** Hot side: check a pairing response against the request it issued. */
export function verifyPairResponse(request: PairRequest, response: PairResponse): boolean {
  const message = offchainMessageV0(pairingStatement(request.origin, response.pubkey, request.challenge), response.pubkey);
  return ed25519Verify(response.pubkey, message, response.signature);
}

export function samePubkey(a: Uint8Array, b: Uint8Array): boolean {
  return equal(a, b);
}
