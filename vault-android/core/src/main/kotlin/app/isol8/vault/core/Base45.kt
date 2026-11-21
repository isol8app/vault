package app.isol8.vault.core

/** Base45 (RFC 9285). Strict decoding: anything outside the spec is rejected. */
object Base45 {
    const val ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size / 2 * 3 + 2)
        var i = 0
        while (i + 1 < bytes.size) {
            val v = bytes.u8At(i) * 256 + bytes.u8At(i + 1)
            sb.append(ALPHABET[v % 45]).append(ALPHABET[v / 45 % 45]).append(ALPHABET[v / 2025])
            i += 2
        }
        if (i < bytes.size) {
            val v = bytes.u8At(i)
            sb.append(ALPHABET[v % 45]).append(ALPHABET[v / 45])
        }
        return sb.toString()
    }

    fun decode(text: String): ByteArray {
        if (text.length % 3 == 1) throw ProtocolException("BAD_BASE45", "invalid length ${text.length}")
        val digits = IntArray(text.length) { i ->
            val d = ALPHABET.indexOf(text[i])
            if (d < 0) throw ProtocolException("BAD_BASE45", "invalid character")
            d
        }
        val out = java.io.ByteArrayOutputStream(text.length / 3 * 2 + 1)
        var i = 0
        while (i < digits.size) {
            if (i + 2 < digits.size) {
                val v = digits[i] + digits[i + 1] * 45 + digits[i + 2] * 2025
                if (v > 0xffff) throw ProtocolException("BAD_BASE45", "triple value $v out of range")
                out.write(v ushr 8)
                out.write(v and 0xff)
                i += 3
            } else {
                val v = digits[i] + digits[i + 1] * 45
                if (v > 0xff) throw ProtocolException("BAD_BASE45", "pair value $v out of range")
                out.write(v)
                i += 2
            }
        }
        return out.toByteArray()
    }
}
