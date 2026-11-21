package app.isol8.vault.core

/** Base58 (Bitcoin alphabet), used to show Solana addresses. */
object Base58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    fun encode(bytes: ByteArray): String {
        var zeros = 0
        while (zeros < bytes.size && bytes[zeros].toInt() == 0) zeros++
        val digits = ArrayList<Int>()
        for (b in bytes) {
            var carry = b.toInt() and 0xff
            for (j in digits.indices) {
                carry += digits[j] shl 8
                digits[j] = carry % 58
                carry /= 58
            }
            while (carry > 0) {
                digits.add(carry % 58)
                carry /= 58
            }
        }
        val sb = StringBuilder()
        repeat(zeros) { sb.append('1') }
        for (d in digits.asReversed()) sb.append(ALPHABET[d])
        return sb.toString()
    }

    fun decode(text: String): ByteArray {
        var zeros = 0
        while (zeros < text.length && text[zeros] == '1') zeros++
        val bytes = ArrayList<Int>()
        for (c in text) {
            var carry = ALPHABET.indexOf(c)
            require(carry >= 0) { "invalid base58 character" }
            for (j in bytes.indices) {
                carry += bytes[j] * 58
                bytes[j] = carry and 0xff
                carry = carry ushr 8
            }
            while (carry > 0) {
                bytes.add(carry and 0xff)
                carry = carry ushr 8
            }
        }
        val out = ByteArray(zeros + bytes.size)
        for ((i, b) in bytes.asReversed().withIndex()) out[zeros + i] = b.toByte()
        return out
    }

    /** Decode a 32-byte Solana address. */
    fun address(text: String): ByteArray {
        val b = decode(text)
        require(b.size == 32) { "address must be 32 bytes" }
        return b
    }
}
