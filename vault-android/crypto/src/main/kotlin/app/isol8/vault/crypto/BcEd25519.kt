package app.isol8.vault.crypto

import app.isol8.vault.core.Bip39
import app.isol8.vault.core.Ed25519Signer
import app.isol8.vault.core.Slip10Ed25519
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer as BcSigner

/**
 * Ed25519 via BouncyCastle's lightweight API. Works on every Android version the vault supports.
 *
 * Limitation: BouncyCastle keeps its own copy of the private key bytes, which we can't wipe.
 * Keep signer instances short-lived: create one to sign, then drop it.
 */
class BcEd25519Signer(privateSeed: ByteArray) : Ed25519Signer {
    private val key: Ed25519PrivateKeyParameters

    init {
        require(privateSeed.size == 32) { "Ed25519 private seed must be 32 bytes" }
        key = Ed25519PrivateKeyParameters(privateSeed, 0)
    }

    override val publicKey: ByteArray = key.generatePublicKey().encoded

    override fun sign(message: ByteArray): ByteArray {
        val signer = BcSigner()
        signer.init(true, key)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }
}

/** Solana keys from a recovery phrase, as Phantom, Solflare and the Solana CLI derive them. */
object SolanaKeys {
    /** Signer for account [account] at m/44'/501'/account'/0'. */
    fun signer(words: List<String>, passphrase: String = "", account: Int = 0): BcEd25519Signer {
        val seed = Bip39.mnemonicToSeed(words, passphrase)
        val node = Slip10Ed25519.derive(seed, Slip10Ed25519.solanaPath(account))
        seed.fill(0)
        try {
            return BcEd25519Signer(node.privateKey)
        } finally {
            node.wipe()
        }
    }
}
