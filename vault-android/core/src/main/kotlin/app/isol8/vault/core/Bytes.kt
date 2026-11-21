package app.isol8.vault.core

import java.math.BigInteger
import java.security.MessageDigest

/** Error with a stable code. Codes are shared with the TypeScript reference (docs/PROTOCOL.md §11). */
class ProtocolException(val code: String, message: String) : Exception("$code: $message")

internal fun ByteArray.u8At(i: Int): Int = this[i].toInt() and 0xff

fun hex(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xff
        sb.append(HEX[v ushr 4]).append(HEX[v and 0x0f])
    }
    return sb.toString()
}

private const val HEX = "0123456789abcdef"

fun unhex(text: String): ByteArray {
    require(text.length % 2 == 0 && text.all { it in HEX }) { "invalid hex" }
    return ByteArray(text.length / 2) { ((HEX.indexOf(text[it * 2]) shl 4) or HEX.indexOf(text[it * 2 + 1])).toByte() }
}

fun concat(vararg parts: ByteArray): ByteArray {
    val out = ByteArray(parts.sumOf { it.size })
    var offset = 0
    for (p in parts) {
        p.copyInto(out, offset)
        offset += p.size
    }
    return out
}

fun u8(n: Int): ByteArray = byteArrayOf(n.toByte())

fun u16le(n: Int): ByteArray = byteArrayOf(n.toByte(), (n ushr 8).toByte())

fun u32le(n: Long): ByteArray = ByteArray(4) { (n ushr (8 * it)).toByte() }

fun u64le(n: ULong): ByteArray = ByteArray(8) { (n shr (8 * it)).toByte() }

fun utf8(text: String): ByteArray = text.toByteArray(Charsets.UTF_8)

/** Strict UTF-8 decoding: malformed input throws instead of being replaced. */
fun strictUtf8(bytes: ByteArray): String {
    val decoder = Charsets.UTF_8.newDecoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
    return try {
        decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
    } catch (e: java.nio.charset.CharacterCodingException) {
        throw ProtocolException("BAD_FIELD", "invalid UTF-8")
    }
}

fun sha256(vararg parts: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-256")
    for (p in parts) md.update(p)
    return md.digest()
}

/** Constant-time comparison. */
fun bytesEqual(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

fun ULong.toBigInteger(): BigInteger = BigInteger(this.toString())

/** Bounds-checked reader. Every read checks the remaining length first. */
class Reader(private val bytes: ByteArray) {
    private var offset = 0

    val remaining: Int get() = bytes.size - offset

    fun u8(): Int {
        need(1)
        return bytes.u8At(offset++)
    }

    fun u16(): Int {
        need(2)
        val v = bytes.u8At(offset) or (bytes.u8At(offset + 1) shl 8)
        offset += 2
        return v
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        for (i in 3 downTo 0) v = (v shl 8) or bytes.u8At(offset + i).toLong()
        offset += 4
        return v
    }

    fun u64(): ULong {
        need(8)
        var v = 0UL
        for (i in 7 downTo 0) v = (v shl 8) or bytes.u8At(offset + i).toULong()
        offset += 8
        return v
    }

    fun take(n: Int): ByteArray {
        need(n)
        val out = bytes.copyOfRange(offset, offset + n)
        offset += n
        return out
    }

    fun end() {
        if (remaining != 0) throw ProtocolException("TRAILING_BYTES", "$remaining unexpected trailing byte(s)")
    }

    private fun need(n: Int) {
        if (n < 0 || n > remaining) throw ProtocolException("TRUNCATED", "needed $n byte(s), $remaining left")
    }
}
