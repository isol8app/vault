package app.isol8.vault.core

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.X509EncodedKeySpec

/** Test-only Ed25519 using the JDK. The Android app supplies its own implementation. */
class JdkEd25519Signer(seed: ByteArray, override val publicKey: ByteArray) : Ed25519Signer {
    private val key = KeyFactory.getInstance("Ed25519").generatePrivate(EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed))

    override fun sign(message: ByteArray): ByteArray = Signature.getInstance("Ed25519").run {
        initSign(key)
        update(message)
        sign()
    }
}

fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    val spki = concat(unhex("302a300506032b6570032100"), publicKey)
    val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))
    return Signature.getInstance("Ed25519").run {
        initVerify(key)
        update(message)
        verify(signature)
    }
}
