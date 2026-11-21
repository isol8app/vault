package app.isol8.vault.crypto

import app.isol8.vault.core.ProtocolException
import app.isol8.vault.core.Reader
import app.isol8.vault.core.concat
import app.isol8.vault.core.strictUtf8
import app.isol8.vault.core.u16le
import app.isol8.vault.core.u32le
import app.isol8.vault.core.u8
import app.isol8.vault.core.utf8
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.SecureRandom
import java.text.Normalizer
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** The secret the vault stores: BIP39 entropy, plus the optional BIP39 passphrase ("25th word"). */
class VaultSecret(val entropy: ByteArray, val bip39Passphrase: String = "") {
    init {
        require(entropy.size in 16..32 && entropy.size % 4 == 0) { "entropy must be 16, 20, 24, 28 or 32 bytes" }
    }

    fun wipe() = entropy.fill(0)
}

data class Argon2Params(val memoryKiB: Int, val iterations: Int, val parallelism: Int) {
    companion object {
        /** RFC 9106's second recommended option, with one lane: 64 MiB, 3 passes. */
        val DEFAULT = Argon2Params(memoryKiB = 65_536, iterations = 3, parallelism = 1)
    }
}

/** What a stored envelope may ask for. Stops a tampered file forcing weak or absurd parameters. */
data class Argon2Bounds(val minMemoryKiB: Int, val maxMemoryKiB: Int, val minIterations: Int, val maxIterations: Int, val maxParallelism: Int) {
    companion object {
        val PRODUCTION = Argon2Bounds(minMemoryKiB = 19_456, maxMemoryKiB = 1_048_576, minIterations = 2, maxIterations = 10, maxParallelism = 4)
    }

    fun check(p: Argon2Params) {
        if (p.memoryKiB !in minMemoryKiB..maxMemoryKiB || p.iterations !in minIterations..maxIterations || p.parallelism !in 1..maxParallelism) {
            throw VaultEnvelopeException(VaultEnvelopeException.Reason.UNSAFE_PARAMETERS)
        }
    }
}

class VaultEnvelopeException(val reason: Reason) : Exception(reason.message) {
    enum class Reason(val message: String) {
        MALFORMED("the vault file is damaged"),
        UNSUPPORTED_VERSION("the vault file was made by a newer app version"),
        UNSAFE_PARAMETERS("the vault file asks for unsafe key-derivation settings"),
        WRONG_PASSPHRASE_OR_TAMPERED("wrong passphrase, or the vault file was modified"),
        WEAK_PASSPHRASE("the passphrase must be at least ${VaultEnvelope.MIN_PASSPHRASE_LENGTH} characters"),
    }
}

/**
 * The passphrase layer of vault storage (docs: vault-android/README.md, "Storage").
 *
 *   "I8PV" | version=1 | kdf=1 (Argon2id v1.3) | memoryKiB u32 | iterations u32 | parallelism u8 | salt[16] | nonce[12] | AES-256-GCM(record)
 *
 * The 43-byte header is the GCM associated data, so changing any parameter breaks authentication.
 * Record: version=1 | kind=1 (BIP39 entropy) | len u8 | entropy | bip39PassphraseLen u16 | bip39 passphrase (UTF-8)
 */
object VaultEnvelope {
    const val MIN_PASSPHRASE_LENGTH = 8
    private val MAGIC = utf8("I8PV")
    private const val VERSION = 1
    private const val KDF_ARGON2ID = 1
    private const val HEADER_LEN = 43
    private const val RECORD_VERSION = 1
    private const val KIND_BIP39_ENTROPY = 1

    fun seal(secret: VaultSecret, passphrase: String, params: Argon2Params = Argon2Params.DEFAULT, random: SecureRandom = SecureRandom()): ByteArray {
        val salt = ByteArray(16).also(random::nextBytes)
        val nonce = ByteArray(12).also(random::nextBytes)
        return sealWith(secret, passphrase, params, salt, nonce)
    }

    /** Deterministic sealing for test vectors. Production code uses [seal]. */
    internal fun sealWith(secret: VaultSecret, passphrase: String, params: Argon2Params, salt: ByteArray, nonce: ByteArray): ByteArray {
        if (passphrase.codePointCount(0, passphrase.length) < MIN_PASSPHRASE_LENGTH) {
            throw VaultEnvelopeException(VaultEnvelopeException.Reason.WEAK_PASSPHRASE)
        }
        require(salt.size == 16 && nonce.size == 12)
        val header = concat(MAGIC, u8(VERSION), u8(KDF_ARGON2ID), u32le(params.memoryKiB.toLong()), u32le(params.iterations.toLong()), u8(params.parallelism), salt, nonce)
        val bip39Pass = utf8(secret.bip39Passphrase)
        require(bip39Pass.size <= 0xffff)
        val record = concat(u8(RECORD_VERSION), u8(KIND_BIP39_ENTROPY), u8(secret.entropy.size), secret.entropy, u16le(bip39Pass.size), bip39Pass)
        val key = deriveKey(passphrase, salt, params)
        try {
            return concat(header, aesGcm(Cipher.ENCRYPT_MODE, key, nonce, header, record))
        } finally {
            key.fill(0)
            record.fill(0)
        }
    }

    fun open(envelope: ByteArray, passphrase: String, bounds: Argon2Bounds = Argon2Bounds.PRODUCTION): VaultSecret {
        val malformed = VaultEnvelopeException(VaultEnvelopeException.Reason.MALFORMED)
        if (envelope.size < HEADER_LEN + 16 || !envelope.copyOfRange(0, 4).contentEquals(MAGIC)) throw malformed
        val r = Reader(envelope)
        r.take(4)
        if (r.u8() != VERSION || r.u8() != KDF_ARGON2ID) throw VaultEnvelopeException(VaultEnvelopeException.Reason.UNSUPPORTED_VERSION)
        val memory = r.u32()
        val iterations = r.u32()
        val parallelism = r.u8()
        if (memory > Int.MAX_VALUE || iterations > Int.MAX_VALUE) throw VaultEnvelopeException(VaultEnvelopeException.Reason.UNSAFE_PARAMETERS)
        val params = Argon2Params(memory.toInt(), iterations.toInt(), parallelism)
        bounds.check(params)
        val salt = r.take(16)
        val nonce = r.take(12)
        val header = envelope.copyOfRange(0, HEADER_LEN)
        val ciphertext = envelope.copyOfRange(HEADER_LEN, envelope.size)

        val key = deriveKey(passphrase, salt, params)
        val record = try {
            aesGcm(Cipher.DECRYPT_MODE, key, nonce, header, ciphertext)
        } catch (e: AEADBadTagException) {
            throw VaultEnvelopeException(VaultEnvelopeException.Reason.WRONG_PASSPHRASE_OR_TAMPERED)
        } finally {
            key.fill(0)
        }
        try {
            val rr = Reader(record)
            if (rr.u8() != RECORD_VERSION || rr.u8() != KIND_BIP39_ENTROPY) throw VaultEnvelopeException(VaultEnvelopeException.Reason.UNSUPPORTED_VERSION)
            val entropy = rr.take(rr.u8())
            val bip39Pass = strictUtf8(rr.take(rr.u16()))
            rr.end()
            return VaultSecret(entropy, bip39Pass)
        } catch (e: ProtocolException) {
            throw malformed
        } catch (e: IllegalArgumentException) {
            throw malformed
        } finally {
            record.fill(0)
        }
    }

    /** Argon2id over the NFKD-normalized UTF-8 passphrase, so the same typed text always gives the same key. */
    internal fun deriveKey(passphrase: String, salt: ByteArray, params: Argon2Params): ByteArray {
        val password = utf8(Normalizer.normalize(passphrase, Normalizer.Form.NFKD))
        val p = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(params.memoryKiB)
            .withIterations(params.iterations)
            .withParallelism(params.parallelism)
            .withSalt(salt)
            .build()
        val out = ByteArray(32)
        Argon2BytesGenerator().apply { init(p) }.generateBytes(password, out)
        password.fill(0)
        return out
    }

    private fun aesGcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(input)
    }
}
