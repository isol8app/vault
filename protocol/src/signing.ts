// Transaction signing round trip (PROTOCOL.md §4.3–4.4, §7).
// The vault's acceptance rules (§6) are NOT implemented here; this only produces and checks signatures.
import { ProtocolError, equal } from "./bytes.ts";
import { ed25519Sign, ed25519Verify, publicKeyFromSeed, sha256 } from "./crypto.ts";
import type { SignTxDeclined, SignTxRequest, SignTxResponse } from "./payload.ts";

/** Vault side: sign the request's message with the key for `seed`. */
export function createSignTxResponse(seed: Uint8Array, request: SignTxRequest): SignTxResponse {
  const pubkey = publicKeyFromSeed(seed);
  if (!equal(pubkey, request.signer)) throw new ProtocolError("UNKNOWN_SIGNER", "this seed does not hold the requested signer");
  return {
    type: "sign_tx_response",
    requestId: request.requestId,
    signer: pubkey,
    messageHash: sha256(request.message),
    signature: ed25519Sign(seed, request.message),
  };
}

export function createDeclined(request: SignTxRequest, reason: number): SignTxDeclined {
  return { type: "sign_tx_declined", requestId: request.requestId, reason };
}

/** Hot side: every check from PROTOCOL.md §7 before attaching the signature. */
export function verifySignTxResponse(request: SignTxRequest, response: SignTxResponse): boolean {
  return (
    equal(request.requestId, response.requestId) &&
    equal(request.signer, response.signer) &&
    equal(sha256(request.message), response.messageHash) &&
    ed25519Verify(response.signer, request.message, response.signature)
  );
}
