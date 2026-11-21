// Payload encoding (PROTOCOL.md §4). Fixed layouts, strict lengths, no trailing bytes.
import { ProtocolError, Reader, concat, u16le, u32le, u8, utf8, fromUtf8 } from "./bytes.ts";

export const MSG_PAIR_REQUEST = 0x01;
export const MSG_PAIR_RESPONSE = 0x02;
export const MSG_SIGN_TX_REQUEST = 0x03;
export const MSG_SIGN_TX_RESPONSE = 0x04;
export const MSG_SIGN_TX_DECLINED = 0x05;

export const DECLINE_USER = 0x01;
export const DECLINE_UNSUPPORTED = 0x02;
export const DECLINE_LOOKUP_TABLES = 0x03;
export const DECLINE_UNKNOWN_SIGNER = 0x04;
export const DECLINE_MALFORMED = 0x05;
export const DECLINE_RULE = 0x06;
export const DECLINE_DEVICE_ONLINE = 0x07;

/**
 * Largest message in a SIGN_TX_REQUEST: what fits the 16 frames of 256 bytes (4096) after the request's own 53 bytes.
 * Legacy messages are far smaller (1232-byte transactions); v1 transactions (SIMD-0385) can be up to 4096 bytes.
 */
export const MAX_MESSAGE_LEN = 4043;
const ORIGIN_RE = /^[a-z0-9.-]{1,64}$/;

export type PairRequest = { type: "pair_request"; challenge: Uint8Array; origin: string };
export type PairResponse = {
  type: "pair_response";
  pubkey: Uint8Array;
  accountIndex: number;
  appVersion: { major: number; minor: number };
  signature: Uint8Array;
};
export type SignTxRequest = { type: "sign_tx_request"; requestId: Uint8Array; signer: Uint8Array; message: Uint8Array };
export type SignTxResponse = {
  type: "sign_tx_response";
  requestId: Uint8Array;
  signer: Uint8Array;
  messageHash: Uint8Array;
  signature: Uint8Array;
};
export type SignTxDeclined = { type: "sign_tx_declined"; requestId: Uint8Array; reason: number };
export type Payload = PairRequest | PairResponse | SignTxRequest | SignTxResponse | SignTxDeclined;

function fixed(name: string, bytes: Uint8Array, len: number): Uint8Array {
  if (bytes.length !== len) throw new ProtocolError("BAD_FIELD", `${name} must be ${len} bytes, got ${bytes.length}`);
  return bytes;
}

function checkOrigin(origin: string): string {
  if (!ORIGIN_RE.test(origin)) throw new ProtocolError("BAD_FIELD", `origin ${JSON.stringify(origin)} is not a lowercase hostname`);
  return origin;
}

function checkMessageLen(len: number): void {
  if (len < 1 || len > MAX_MESSAGE_LEN) throw new ProtocolError("BAD_FIELD", `message length ${len} outside 1..${MAX_MESSAGE_LEN}`);
}

function checkAccountIndex(i: number): void {
  if (!Number.isInteger(i) || i < 0 || i > 0x7fffffff) throw new ProtocolError("BAD_FIELD", `account index ${i} outside 0..2^31-1`);
}

function checkReason(r: number): void {
  if (!Number.isInteger(r) || r < 1 || r > 0xff) throw new ProtocolError("BAD_FIELD", `decline reason ${r} outside 1..255`);
}

export function encodePayload(p: Payload): Uint8Array {
  switch (p.type) {
    case "pair_request": {
      const origin = utf8(checkOrigin(p.origin));
      return concat(u8(MSG_PAIR_REQUEST), fixed("challenge", p.challenge, 32), u8(origin.length), origin);
    }
    case "pair_response": {
      checkAccountIndex(p.accountIndex);
      return concat(
        u8(MSG_PAIR_RESPONSE),
        fixed("pubkey", p.pubkey, 32),
        u32le(p.accountIndex),
        u16le(p.appVersion.major),
        u16le(p.appVersion.minor),
        fixed("signature", p.signature, 64),
      );
    }
    case "sign_tx_request": {
      checkMessageLen(p.message.length);
      return concat(
        u8(MSG_SIGN_TX_REQUEST),
        fixed("requestId", p.requestId, 16),
        fixed("signer", p.signer, 32),
        u16le(p.message.length),
        p.message,
        u16le(0), // hints_len: must be 0 in version 1
      );
    }
    case "sign_tx_response":
      return concat(
        u8(MSG_SIGN_TX_RESPONSE),
        fixed("requestId", p.requestId, 16),
        fixed("signer", p.signer, 32),
        fixed("messageHash", p.messageHash, 32),
        fixed("signature", p.signature, 64),
      );
    case "sign_tx_declined":
      checkReason(p.reason);
      return concat(u8(MSG_SIGN_TX_DECLINED), fixed("requestId", p.requestId, 16), u8(p.reason));
  }
}

export function decodePayload(bytes: Uint8Array): Payload {
  const r = new Reader(bytes);
  const type = r.u8();
  let p: Payload;
  switch (type) {
    case MSG_PAIR_REQUEST: {
      const challenge = r.take(32);
      const originLen = r.u8();
      const raw = r.take(originLen);
      let origin: string;
      try {
        origin = fromUtf8(raw);
      } catch {
        throw new ProtocolError("BAD_FIELD", "origin is not valid text");
      }
      p = { type: "pair_request", challenge, origin: checkOrigin(origin) };
      break;
    }
    case MSG_PAIR_RESPONSE: {
      const pubkey = r.take(32);
      const accountIndex = r.u32();
      checkAccountIndex(accountIndex);
      const major = r.u16();
      const minor = r.u16();
      p = { type: "pair_response", pubkey, accountIndex, appVersion: { major, minor }, signature: r.take(64) };
      break;
    }
    case MSG_SIGN_TX_REQUEST: {
      const requestId = r.take(16);
      const signer = r.take(32);
      const len = r.u16();
      checkMessageLen(len);
      const message = r.take(len);
      const hintsLen = r.u16();
      if (hintsLen !== 0) throw new ProtocolError("BAD_FIELD", `hints_len must be 0 in version 1, got ${hintsLen}`);
      p = { type: "sign_tx_request", requestId, signer, message };
      break;
    }
    case MSG_SIGN_TX_RESPONSE:
      p = { type: "sign_tx_response", requestId: r.take(16), signer: r.take(32), messageHash: r.take(32), signature: r.take(64) };
      break;
    case MSG_SIGN_TX_DECLINED: {
      const requestId = r.take(16);
      const reason = r.u8();
      checkReason(reason);
      p = { type: "sign_tx_declined", requestId, reason };
      break;
    }
    default:
      throw new ProtocolError("UNKNOWN_TYPE", `unknown message type 0x${type.toString(16).padStart(2, "0")}`);
  }
  r.end();
  return p;
}
