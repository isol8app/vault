package app.isol8.vault.core

/** QR framing (PROTOCOL.md §3): "ISOL8:" + Base45(frame bytes), with multi-part reassembly. */
object Frames {
    const val PREFIX = "ISOL8:"
    const val VERSION = 1
    const val MAX_CHUNK = 256
    const val MAX_PARTS = 16
    const val MAX_PAYLOAD = MAX_CHUNK * MAX_PARTS
    const val HEADER_LEN = 11

    class Frame(val partIndex: Int, val partCount: Int, val payloadId: ByteArray, val chunk: ByteArray)

    fun payloadId(payload: ByteArray): ByteArray = sha256(payload).copyOf(8)

    fun encode(payload: ByteArray): List<String> {
        if (payload.isEmpty() || payload.size > MAX_PAYLOAD) {
            throw ProtocolException("BAD_LENGTH", "payload length ${payload.size} outside 1..$MAX_PAYLOAD")
        }
        val id = payloadId(payload)
        val count = (payload.size + MAX_CHUNK - 1) / MAX_CHUNK
        return (0 until count).map { i ->
            val chunk = payload.copyOfRange(i * MAX_CHUNK, minOf(payload.size, (i + 1) * MAX_CHUNK))
            PREFIX + Base45.encode(concat(byteArrayOf(VERSION.toByte(), i.toByte(), count.toByte()), id, chunk))
        }
    }

    fun decode(text: String): Frame {
        if (!text.startsWith(PREFIX)) throw ProtocolException("BAD_PREFIX", "not an isol8 QR code")
        val bytes = Base45.decode(text.substring(PREFIX.length))
        if (bytes.size < HEADER_LEN + 1) throw ProtocolException("BAD_FRAME", "frame is ${bytes.size} bytes, minimum ${HEADER_LEN + 1}")
        if (bytes.u8At(0) != VERSION) throw ProtocolException("BAD_VERSION", "unsupported version ${bytes.u8At(0)}")
        val partIndex = bytes.u8At(1)
        val partCount = bytes.u8At(2)
        if (partCount < 1 || partCount > MAX_PARTS || partIndex >= partCount) {
            throw ProtocolException("BAD_PART", "part $partIndex of $partCount")
        }
        val chunk = bytes.copyOfRange(HEADER_LEN, bytes.size)
        if (chunk.size > MAX_CHUNK) throw ProtocolException("BAD_FRAME", "chunk is ${chunk.size} bytes, maximum $MAX_CHUNK")
        return Frame(partIndex, partCount, bytes.copyOfRange(3, HEADER_LEN), chunk)
    }

    sealed class ScanResult {
        data class Partial(val have: Int, val total: Int) : ScanResult()
        class Complete(val payload: ByteArray) : ScanResult()
    }

    /**
     * Collects frames in any order. A frame from a different payload (other id or part count) starts over.
     * Timeouts are the caller's job (PROTOCOL.md §3.3: reset after 30 s without a new part).
     */
    class Reassembler {
        private var id: String? = null
        private var count = 0
        private val parts = HashMap<Int, ByteArray>()

        fun add(text: String): ScanResult {
            val frame = decode(text)
            val frameId = hex(frame.payloadId)
            if (frameId != id || frame.partCount != count) {
                reset()
                id = frameId
                count = frame.partCount
            }
            parts.putIfAbsent(frame.partIndex, frame.chunk)
            if (parts.size < count) return ScanResult.Partial(parts.size, count)

            val chunks = (0 until count).map { parts.getValue(it) }
            reset()
            for (i in 0 until chunks.size - 1) {
                if (chunks[i].size != MAX_CHUNK) {
                    throw ProtocolException("BAD_FRAME", "part $i is ${chunks[i].size} bytes; every part but the last must be $MAX_CHUNK")
                }
            }
            val payload = concat(*chunks.toTypedArray())
            if (hex(payloadId(payload)) != frameId) throw ProtocolException("PAYLOAD_ID_MISMATCH", "reassembled payload does not match its id")
            return ScanResult.Complete(payload)
        }

        fun reset() {
            id = null
            count = 0
            parts.clear()
        }
    }

    /** Reassemble a full set of frame texts (any order). */
    fun decodeAll(texts: List<String>): ByteArray {
        val r = Reassembler()
        for (t in texts) {
            val result = r.add(t)
            if (result is ScanResult.Complete) return result.payload
        }
        throw ProtocolException("INCOMPLETE", "not all parts were provided")
    }
}
