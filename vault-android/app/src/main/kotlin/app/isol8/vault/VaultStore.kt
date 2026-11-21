package app.isol8.vault

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import app.isol8.vault.core.concat
import app.isol8.vault.core.u8
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class VaultStoreException(message: String) : Exception(message)

/**
 * The outer storage layer: wraps the passphrase envelope (crypto/VaultEnvelope) with an Android Keystore
 * AES-256-GCM key that never leaves secure hardware and only works while the device is unlocked.
 *
 * File (in noBackupFilesDir, never backed up): "I8KS" | version=1 | ivLen u8 | iv | AES-GCM(envelope),
 * AAD = "I8KS" | version | purpose. Both layers are needed to read the secret: this device's Keystore key,
 * and the user's passphrase.
 *
 * The same key also protects other vault files (settings.bin); [purpose] goes into the AAD, so one file
 * can't be swapped for another. The vault file itself has an empty purpose.
 */
class VaultStore(
    private val context: Context,
    private val keyAlias: String = KEY_ALIAS,
    private val fileName: String = FILE_NAME,
    purpose: String = "",
) {
    companion object {
        const val KEY_ALIAS = "isol8.vault.wrap.v1"
        const val FILE_NAME = "vault.bin"
        private val MAGIC = "I8KS".toByteArray(Charsets.US_ASCII)
        private const val VERSION = 1
    }

    private val file: File get() = File(context.noBackupFilesDir, fileName)
    private val aad = concat(MAGIC, u8(VERSION), purpose.toByteArray(Charsets.US_ASCII))

    fun exists(): Boolean = file.exists()

    /** The Keystore key is only meaningful behind a lock screen (PIN, pattern or password). */
    fun isDeviceSecure(): Boolean = context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    fun save(envelope: ByteArray) {
        if (!isDeviceSecure()) throw VaultStoreException("Set a screen lock (PIN, pattern or password) before creating a vault.")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey()) // the Keystore picks a fresh random IV
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(envelope)
        val iv = cipher.iv
        val blob = concat(MAGIC, u8(VERSION), u8(iv.size), iv, ciphertext)
        val atomic = AtomicFile(file)
        val out = atomic.startWrite()
        try {
            out.write(blob)
            atomic.finishWrite(out)
        } catch (e: Exception) {
            atomic.failWrite(out)
            throw e
        }
    }

    /** Returns the passphrase envelope. Requires the device to be unlocked. */
    fun load(): ByteArray {
        val blob = AtomicFile(file).readFully()
        if (blob.size < 6 || !blob.copyOfRange(0, 4).contentEquals(MAGIC) || blob[4].toInt() != VERSION) {
            throw VaultStoreException("The vault file is damaged or from a newer app version.")
        }
        val ivLen = blob[5].toInt() and 0xff
        if (ivLen != 12 || blob.size < 6 + ivLen + 16) throw VaultStoreException("The vault file is damaged.")
        val key = keyStore().getKey(keyAlias, null) as? SecretKey
            ?: throw VaultStoreException("This device's vault key is missing. Restore from your recovery phrase.")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob.copyOfRange(6, 6 + ivLen)))
        cipher.updateAAD(aad)
        return cipher.doFinal(blob, 6 + ivLen, blob.size - 6 - ivLen)
    }

    /** Deletes the file and the Keystore key. Without the key, any copy of the file is unreadable. */
    fun delete() {
        file.delete()
        keyStore().deleteEntry(keyAlias)
    }

    /** Deletes only this file, keeping the key (for files that share the vault's key). */
    fun deleteFile() {
        file.delete()
    }

    /** Where the Keystore key lives: "StrongBox", "TEE", "software" or "unknown". */
    fun keySecurityLevel(): String {
        val key = keyStore().getKey(keyAlias, null) as? SecretKey ?: return "no key"
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return if (Build.VERSION.SDK_INT >= 31) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                else -> "unknown"
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "secure hardware" else "software"
        }
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun getOrCreateKey(): SecretKey {
        (keyStore().getKey(keyAlias, null) as? SecretKey)?.let { return it }
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            try {
                generator.init(spec(strongBox = true))
                return generator.generateKey()
            } catch (e: StrongBoxUnavailableException) {
                // Fall through to the TEE.
            }
        }
        generator.init(spec(strongBox = false))
        return generator.generateKey()
    }
}
