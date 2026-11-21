package app.isol8.vault

import android.content.Context
import android.os.SystemClock
import app.isol8.vault.core.Base58
import app.isol8.vault.core.Bip39
import app.isol8.vault.crypto.Argon2Params
import app.isol8.vault.crypto.SolanaKeys
import app.isol8.vault.crypto.VaultEnvelope
import app.isol8.vault.crypto.VaultEnvelopeException
import app.isol8.vault.crypto.VaultSecret

/**
 * Debug-only check of the whole storage stack on a real device, with a throwaway key and file
 * (never the real vault's). Uses the public BIP39 test phrase, never a real one.
 */
object StorageSelfTest {
    /** "abandon" x11 + "about": its Solana address at m/44'/501'/0'/0' is widely published. */
    private const val TEST_ENTROPY_HEX = "00000000000000000000000000000000"
    private const val EXPECTED_ADDRESS = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"

    fun run(context: Context): String {
        val lines = mutableListOf<String>()
        val store = VaultStore(context, keyAlias = "isol8.selftest.v1", fileName = "selftest.bin")
        try {
            if (!store.isDeviceSecure()) return "✗ No screen lock is set. The vault requires a PIN, pattern or password."
            lines += "✓ Screen lock is set."

            val entropy = app.isol8.vault.core.unhex(TEST_ENTROPY_HEX)
            val words = Bip39.entropyToMnemonic(entropy)
            val address = Base58.encode(SolanaKeys.signer(words).publicKey)
            lines += if (address == EXPECTED_ADDRESS) "✓ Key derivation on this device matches the published test address." else "✗ Derived $address, expected $EXPECTED_ADDRESS."

            val passphrase = "self-test passphrase"
            var t = SystemClock.elapsedRealtime()
            val envelope = VaultEnvelope.seal(VaultSecret(entropy.copyOf()), passphrase, Argon2Params.DEFAULT)
            val sealMs = SystemClock.elapsedRealtime() - t

            store.save(envelope)
            lines += "✓ Stored under a Keystore key in: ${store.keySecurityLevel()}."

            t = SystemClock.elapsedRealtime()
            val opened = VaultEnvelope.open(store.load(), passphrase)
            val openMs = SystemClock.elapsedRealtime() - t
            lines += if (opened.entropy.contentEquals(entropy)) "✓ Read back and decrypted correctly." else "✗ Decrypted data does not match."
            opened.wipe()

            val wrong = try {
                VaultEnvelope.open(store.load(), "wrong passphrase!")
                false
            } catch (e: VaultEnvelopeException) {
                e.reason == VaultEnvelopeException.Reason.WRONG_PASSPHRASE_OR_TAMPERED
            }
            lines += if (wrong) "✓ A wrong passphrase is rejected." else "✗ A wrong passphrase was not rejected."

            val p = Argon2Params.DEFAULT
            lines += "Argon2id (${p.memoryKiB / 1024} MiB, ${p.iterations} passes): create ${sealMs} ms, unlock ${openMs} ms."
        } catch (e: Exception) {
            lines += "✗ ${e.javaClass.simpleName}: ${e.message}"
        } finally {
            store.delete()
        }
        lines += if (!store.exists()) "✓ Test key and file deleted." else "✗ Test file was not deleted."
        return lines.joinToString("\n")
    }
}
