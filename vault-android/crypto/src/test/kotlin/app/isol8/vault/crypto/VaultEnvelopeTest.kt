package app.isol8.vault.crypto

import app.isol8.vault.core.hex
import app.isol8.vault.core.unhex
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class VaultEnvelopeTest {
    private val vectors = JSONObject(File(System.getProperty("isol8.vectors"), "envelopes.json").readText())
    private val testBounds = Argon2Bounds(minMemoryKiB = 8, maxMemoryKiB = 1_048_576, minIterations = 1, maxIterations = 10, maxParallelism = 4)

    /** RFC 9106 §5.3: BouncyCastle's Argon2id, including the secret and associated-data inputs. */
    @Test
    fun argon2idRfc9106Vector() {
        val p = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(3).withMemoryAsKB(32).withParallelism(4)
            .withSalt(ByteArray(16) { 2 }).withSecret(ByteArray(8) { 3 }).withAdditional(ByteArray(12) { 4 })
            .build()
        val out = ByteArray(32)
        Argon2BytesGenerator().apply { init(p) }.generateBytes(ByteArray(32) { 1 }, out)
        assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", hex(out))
    }

    /** Envelopes made by Node's independent Argon2id + AES-GCM: Kotlin must reproduce them byte for byte and open them. */
    @Test
    fun matchesNodeEnvelopes() {
        val valid = vectors.getJSONArray("valid")
        for (i in 0 until valid.length()) {
            val c = valid.getJSONObject(i)
            val p = c.getJSONObject("params")
            val params = Argon2Params(p.getInt("memoryKiB"), p.getInt("iterations"), p.getInt("parallelism"))
            val secret = VaultSecret(unhex(c.getString("entropy_hex")), c.getString("bip39_passphrase"))
            val sealed = VaultEnvelope.sealWith(secret, c.getString("passphrase"), params, unhex(c.getString("salt_hex")), unhex(c.getString("nonce_hex")))
            assertEquals(c.getString("envelope_hex"), hex(sealed), c.getString("name"))

            val bounds = if (c.getString("bounds") == "production") Argon2Bounds.PRODUCTION else testBounds
            val opened = VaultEnvelope.open(unhex(c.getString("envelope_hex")), c.getString("passphrase"), bounds)
            assertEquals(c.getString("entropy_hex"), hex(opened.entropy), c.getString("name"))
            assertEquals(c.getString("bip39_passphrase"), opened.bip39Passphrase, c.getString("name"))
        }
    }

    @Test
    fun invalidEnvelopesAreRejected() {
        val invalid = vectors.getJSONArray("invalid")
        for (i in 0 until invalid.length()) {
            val c = invalid.getJSONObject(i)
            val e = assertFailsWith<VaultEnvelopeException>(c.getString("name")) {
                VaultEnvelope.open(unhex(c.getString("envelope_hex")), c.getString("passphrase"))
            }
            assertEquals(c.getString("error"), e.reason.name, c.getString("name"))
        }
    }

    @Test
    fun randomSaltAndNonceEachTime() {
        val secret = VaultSecret(ByteArray(32) { it.toByte() })
        val fast = Argon2Params(1024, 1, 1)
        val a = VaultEnvelope.seal(secret, "passphrase-1234", fast)
        val b = VaultEnvelope.seal(secret, "passphrase-1234", fast)
        assertFalse(a.contentEquals(b), "two seals of the same secret must differ")
        assertEquals(hex(secret.entropy), hex(VaultEnvelope.open(a, "passphrase-1234", testBounds).entropy))
        assertEquals(hex(secret.entropy), hex(VaultEnvelope.open(b, "passphrase-1234", testBounds).entropy))
    }

    @Test
    fun weakPassphraseIsRefused() {
        val e = assertFailsWith<VaultEnvelopeException> { VaultEnvelope.seal(VaultSecret(ByteArray(16)), "1234567", Argon2Params(1024, 1, 1)) }
        assertEquals(VaultEnvelopeException.Reason.WEAK_PASSPHRASE, e.reason)
    }
}
