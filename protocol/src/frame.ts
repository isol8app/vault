// QR framing (PROTOCOL.md §3): "ISOL8:" + Base45(frame bytes), with multi-part reassembly.
import { base45Decode, base45Encode } from "./base45.ts";
import { ProtocolError, concat, toHex } from "./bytes.ts";
import { sha256 } from "./crypto.ts";

export const FRAME_PREFIX = "ISOL8:";
export const PROTOCOL_VERSION = 1;
export const MAX_CHUNK = 256;
export const MAX_PARTS = 16;
export const MAX_PAYLOAD = MAX_CHUNK * MAX_PARTS;
export const FRAME_HEADER_LEN = 11;

export type Frame = {
  partIndex: number;
  partCount: number;
  payloadId: Uint8Array;
  chunk: Uint8Array;
};

export function payloadId(payload: Uint8Array): Uint8Array {
  return sha256(payload).slice(0, 8);
}

/** Raw frame text from header fields. Exposed so test vectors can build invalid frames. */
export function frameText(version: number, partIndex: number, partCount: number, id: Uint8Array, chunk: Uint8Array): string {
  return FRAME_PREFIX + base45Encode(concat(Uint8Array.of(version, partIndex, partCount), id, chunk));
}

/** Split a payload into the QR texts to display, in part order. */
export function encodeFrames(payload: Uint8Array): string[] {
  if (payload.length === 0 || payload.length > MAX_PAYLOAD) {
    throw new ProtocolError("BAD_LENGTH", `payload length ${payload.length} outside 1..${MAX_PAYLOAD}`);
  }
  const id = payloadId(payload);
  const count = Math.ceil(payload.length / MAX_CHUNK);
  const frames: string[] = [];
  for (let i = 0; i < count; i++) {
    frames.push(frameText(PROTOCOL_VERSION, i, count, id, payload.slice(i * MAX_CHUNK, (i + 1) * MAX_CHUNK)));
  }
  return frames;
}

export function decodeFrame(text: string): Frame {
  if (!text.startsWith(FRAME_PREFIX)) throw new ProtocolError("BAD_PREFIX", "not an isol8 QR code");
  const bytes = base45Decode(text.slice(FRAME_PREFIX.length));
  if (bytes.length < FRAME_HEADER_LEN + 1) {
    throw new ProtocolError("BAD_FRAME", `frame is ${bytes.length} bytes, minimum ${FRAME_HEADER_LEN + 1}`);
  }
  if (bytes[0] !== PROTOCOL_VERSION) throw new ProtocolError("BAD_VERSION", `unsupported version ${bytes[0]}`);
  const partIndex = bytes[1]!;
  const partCount = bytes[2]!;
  if (partCount < 1 || partCount > MAX_PARTS || partIndex >= partCount) {
    throw new ProtocolError("BAD_PART", `part ${partIndex} of ${partCount}`);
  }
  const chunk = bytes.slice(FRAME_HEADER_LEN);
  if (chunk.length > MAX_CHUNK) throw new ProtocolError("BAD_FRAME", `chunk is ${chunk.length} bytes, maximum ${MAX_CHUNK}`);
  return { partIndex, partCount, payloadId: bytes.slice(3, FRAME_HEADER_LEN), chunk };
}

export type ScanResult =
  | { status: "partial"; have: number; total: number }
  | { status: "complete"; payload: Uint8Array };

/**
 * Collects frames in any order. A frame from a different payload (other id or part count) starts over.
 * Timeouts are the caller's job (PROTOCOL.md §3.3: reset after 30 s without a new part).
 */
export class Reassembler {
  private id: string | null = null;
  private count = 0;
  private parts = new Map<number, Uint8Array>();

  add(text: string): ScanResult {
    const frame = decodeFrame(text);
    const id = toHex(frame.payloadId);
    if (id !== this.id || frame.partCount !== this.count) {
      this.reset();
      this.id = id;
      this.count = frame.partCount;
    }
    if (!this.parts.has(frame.partIndex)) this.parts.set(frame.partIndex, frame.chunk);
    if (this.parts.size < this.count) return { status: "partial", have: this.parts.size, total: this.count };

    const chunks: Uint8Array[] = [];
    for (let i = 0; i < this.count; i++) chunks.push(this.parts.get(i)!);
    this.reset();
    for (let i = 0; i < chunks.length - 1; i++) {
      if (chunks[i]!.length !== MAX_CHUNK) {
        throw new ProtocolError("BAD_FRAME", `part ${i} is ${chunks[i]!.length} bytes; every part but the last must be ${MAX_CHUNK}`);
      }
    }
    const payload = concat(...chunks);
    if (toHex(payloadId(payload)) !== id) throw new ProtocolError("PAYLOAD_ID_MISMATCH", "reassembled payload does not match its id");
    return { status: "complete", payload };
  }

  reset(): void {
    this.id = null;
    this.count = 0;
    this.parts.clear();
  }
}

/** Convenience: reassemble a full set of frame texts (any order). */
export function decodeFrames(texts: string[]): Uint8Array {
  const r = new Reassembler();
  for (const t of texts) {
    const result = r.add(t);
    if (result.status === "complete") return result.payload;
  }
  throw new ProtocolError("INCOMPLETE", "not all parts were provided");
}
