package app.isol8.vault.core

/** Payload encoding (PROTOCOL.md §4). Fixed layouts, strict lengths, no trailing bytes. */
sealed class Payload {
    class PairRequest(val challenge: ByteArray, val origin: String) : Payload()

    class PairResponse(
        val pubkey: ByteArray,
        val accountIndex: Long,
        val appVersionMajor: Int,
        val appVersionMinor: Int,
        val signature: ByteArray,
    ) : Payload()

    class SignTxRequest(val requestId: ByteArray, val signer: ByteArray, val message: ByteArray) : Payload()

    class SignTxResponse(val requestId: ByteArray, val signer: ByteArray, val messageHash: ByteArray, val signature: ByteArray) : Payload()

    class SignTxDeclined(val requestId: ByteArray, val reason: Int) : Payload()

    companion object {
        const val PAIR_REQUEST = 0x01
        const val PAIR_RESPONSE = 0x02
        const val SIGN_TX_REQUEST = 0x03
        const val SIGN_TX_RESPONSE = 0x04
        const val SIGN_TX_DECLINED = 0x05

        /** What fits 16 frames of 256 bytes after the request's own 53 bytes: legacy messages, and v1 ones up to here. */
        const val MAX_MESSAGE_LEN = 4043
        private val ORIGIN = Regex("^[a-z0-9.-]{1,64}$")

        private fun fixed(name: String, bytes: ByteArray, len: Int): ByteArray {
            if (bytes.size != len) throw ProtocolException("BAD_FIELD", "$name must be $len bytes, got ${bytes.size}")
            return bytes
        }

        private fun checkOrigin(origin: String): String {
            if (!ORIGIN.matches(origin)) throw ProtocolException("BAD_FIELD", "origin is not a lowercase hostname")
            return origin
        }

        private fun checkMessageLen(len: Int) {
            if (len < 1 || len > MAX_MESSAGE_LEN) throw ProtocolException("BAD_FIELD", "message length $len outside 1..$MAX_MESSAGE_LEN")
        }

        private fun checkAccountIndex(i: Long) {
            if (i < 0 || i > 0x7fffffffL) throw ProtocolException("BAD_FIELD", "account index $i outside 0..2^31-1")
        }

        private fun checkReason(r: Int) {
            if (r < 1 || r > 0xff) throw ProtocolException("BAD_FIELD", "decline reason $r outside 1..255")
        }

        fun encode(p: Payload): ByteArray = when (p) {
            is PairRequest -> {
                val origin = utf8(checkOrigin(p.origin))
                concat(u8(PAIR_REQUEST), fixed("challenge", p.challenge, 32), u8(origin.size), origin)
            }
            is PairResponse -> {
                checkAccountIndex(p.accountIndex)
                concat(
                    u8(PAIR_RESPONSE), fixed("pubkey", p.pubkey, 32), u32le(p.accountIndex),
                    u16le(p.appVersionMajor), u16le(p.appVersionMinor), fixed("signature", p.signature, 64),
                )
            }
            is SignTxRequest -> {
                checkMessageLen(p.message.size)
                concat(
                    u8(SIGN_TX_REQUEST), fixed("requestId", p.requestId, 16), fixed("signer", p.signer, 32),
                    u16le(p.message.size), p.message, u16le(0),
                )
            }
            is SignTxResponse -> concat(
                u8(SIGN_TX_RESPONSE), fixed("requestId", p.requestId, 16), fixed("signer", p.signer, 32),
                fixed("messageHash", p.messageHash, 32), fixed("signature", p.signature, 64),
            )
            is SignTxDeclined -> {
                checkReason(p.reason)
                concat(u8(SIGN_TX_DECLINED), fixed("requestId", p.requestId, 16), u8(p.reason))
            }
        }

        fun decode(bytes: ByteArray): Payload {
            val r = Reader(bytes)
            val p: Payload = when (val type = r.u8()) {
                PAIR_REQUEST -> {
                    val challenge = r.take(32)
                    val origin = strictUtf8(r.take(r.u8()))
                    PairRequest(challenge, checkOrigin(origin))
                }
                PAIR_RESPONSE -> {
                    val pubkey = r.take(32)
                    val index = r.u32()
                    checkAccountIndex(index)
                    PairResponse(pubkey, index, r.u16(), r.u16(), r.take(64))
                }
                SIGN_TX_REQUEST -> {
                    val requestId = r.take(16)
                    val signer = r.take(32)
                    val len = r.u16()
                    checkMessageLen(len)
                    val message = r.take(len)
                    val hintsLen = r.u16()
                    if (hintsLen != 0) throw ProtocolException("BAD_FIELD", "hints_len must be 0 in version 1, got $hintsLen")
                    SignTxRequest(requestId, signer, message)
                }
                SIGN_TX_RESPONSE -> SignTxResponse(r.take(16), r.take(32), r.take(32), r.take(64))
                SIGN_TX_DECLINED -> {
                    val requestId = r.take(16)
                    val reason = r.u8()
                    checkReason(reason)
                    SignTxDeclined(requestId, reason)
                }
                else -> throw ProtocolException("UNKNOWN_TYPE", "unknown message type 0x%02x".format(type))
            }
            r.end()
            return p
        }
    }
}
