package app.isol8.vault.core

import java.text.Normalizer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class InvalidMnemonicException(val reason: Reason, val wordIndex: Int? = null) :
    Exception(reason.message + (wordIndex?.let { " (word ${it + 1})" } ?: "")) {
    enum class Reason(val message: String) {
        WORD_COUNT("a recovery phrase has 12, 15, 18, 21 or 24 words"),
        UNKNOWN_WORD("not a word from the BIP39 English list"),
        CHECKSUM("the words don't form a valid phrase; check their order and spelling"),
    }
}

/**
 * BIP39 recovery phrases (English). Uses only platform crypto: SHA-256 and HMAC-SHA512.
 * The wordlist ships as a resource and is checked against its published SHA-256 when first loaded.
 */
object Bip39 {
    const val WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    private val WORD_COUNTS = setOf(12, 15, 18, 21, 24)

    val WORDS: List<String> by lazy {
        val bytes = Bip39::class.java.getResourceAsStream("bip39-english.txt")?.use { it.readBytes() }
            ?: error("BIP39 wordlist missing")
        check(hex(sha256(bytes)) == WORDLIST_SHA256) { "BIP39 wordlist checksum mismatch" }
        val words = String(bytes, Charsets.UTF_8).split('\n').filter { it.isNotEmpty() }
        check(words.size == 2048) { "BIP39 wordlist must have 2048 words" }
        words
    }

    private val INDEX: Map<String, Int> by lazy { WORDS.withIndex().associate { (i, w) -> w to i } }

    /** Words for a picker: every word starting with [prefix]. English words are unique within 4 letters. */
    fun wordsStartingWith(prefix: String): List<String> = WORDS.filter { it.startsWith(prefix) }

    fun entropyToMnemonic(entropy: ByteArray): List<String> {
        require(entropy.size in 16..32 && entropy.size % 4 == 0) { "entropy must be 16, 20, 24, 28 or 32 bytes" }
        val checksumBits = entropy.size * 8 / 32
        val bits = BitReader(concat(entropy, sha256(entropy)))
        val wordCount = (entropy.size * 8 + checksumBits) / 11
        return List(wordCount) { WORDS[bits.read(11)] }
    }

    /** Validates the words and returns the entropy they encode. */
    fun mnemonicToEntropy(words: List<String>): ByteArray {
        if (words.size !in WORD_COUNTS) throw InvalidMnemonicException(InvalidMnemonicException.Reason.WORD_COUNT)
        val indexes = words.mapIndexed { i, w ->
            INDEX[w] ?: throw InvalidMnemonicException(InvalidMnemonicException.Reason.UNKNOWN_WORD, i)
        }
        val totalBits = words.size * 11
        val checksumBits = totalBits / 33
        val entropyBytes = (totalBits - checksumBits) / 8
        val packed = ByteArray((totalBits + 7) / 8)
        var bit = 0
        for (index in indexes) {
            for (b in 10 downTo 0) {
                if ((index shr b) and 1 == 1) packed[bit / 8] = (packed[bit / 8].toInt() or (0x80 ushr (bit % 8))).toByte()
                bit++
            }
        }
        val entropy = packed.copyOf(entropyBytes)
        val expected = BitReader(sha256(entropy)).read(checksumBits)
        val actual = BitReader(packed).apply { skip(entropyBytes * 8) }.read(checksumBits)
        if (expected != actual) throw InvalidMnemonicException(InvalidMnemonicException.Reason.CHECKSUM)
        return entropy
    }

    /** The 64-byte BIP39 seed. Validates the phrase first. [passphrase] is the optional BIP39 passphrase. */
    fun mnemonicToSeed(words: List<String>, passphrase: String = ""): ByteArray {
        mnemonicToEntropy(words)
        val mnemonic = Normalizer.normalize(words.joinToString(" "), Normalizer.Form.NFKD)
        val salt = Normalizer.normalize("mnemonic$passphrase", Normalizer.Form.NFKD)
        return pbkdf2HmacSha512(utf8(mnemonic), utf8(salt), 2048, 64)
    }

    /** PBKDF2-HMAC-SHA512 over exact bytes (RFC 8018), so every platform derives the same seed. */
    internal fun pbkdf2HmacSha512(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(password, "HmacSHA512"))
        val out = ByteArray(length)
        var block = 1
        var offset = 0
        while (offset < length) {
            mac.update(salt)
            mac.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            repeat(iterations - 1) {
                u = mac.doFinal(u)
                for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
            }
            val n = minOf(t.size, length - offset)
            t.copyInto(out, offset, 0, n)
            t.fill(0)
            u.fill(0)
            offset += n
            block++
        }
        return out
    }

    private class BitReader(private val bytes: ByteArray) {
        private var pos = 0
        fun skip(n: Int) {
            pos += n
        }
        fun read(n: Int): Int {
            var v = 0
            repeat(n) {
                val bit = (bytes[pos / 8].toInt() shr (7 - pos % 8)) and 1
                v = (v shl 1) or bit
                pos++
            }
            return v
        }
    }
}
