package app.isol8.vault.core

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * SLIP-0010 key derivation for Ed25519 (hardened children only, as the spec requires).
 * Solana wallets (Phantom, Solflare, Solana CLI) use m/44'/501'/<account>'/0'.
 * Produces the 32-byte Ed25519 private seed; the public key is computed by the Ed25519 implementation.
 */
object Slip10Ed25519 {
    const val HARDENED = 0x80000000L

    class Node(val privateKey: ByteArray, val chainCode: ByteArray) {
        fun wipe() {
            privateKey.fill(0)
            chainCode.fill(0)
        }
    }

    fun solanaPath(account: Int): String {
        require(account >= 0) { "account index must be non-negative" }
        return "m/44'/501'/$account'/0'"
    }

    fun master(seed: ByteArray): Node = split(hmacSha512(utf8("ed25519 seed"), seed))

    /** Hardened child; [index] includes the hardened offset. */
    fun child(parent: Node, index: Long): Node {
        require(index in HARDENED..0xffffffffL) { "Ed25519 derivation supports hardened indexes only" }
        val data = concat(byteArrayOf(0), parent.privateKey, u32be(index))
        return split(hmacSha512(parent.chainCode, data))
    }

    /** Derive along a path like "m/44'/501'/0'/0'". Every component must be hardened. */
    fun derive(seed: ByteArray, path: String): Node {
        val parts = path.split('/')
        require(parts.first() == "m") { "path must start with m" }
        var node = master(seed)
        for (part in parts.drop(1)) {
            require(part.endsWith("'") && part.length > 1) { "Ed25519 paths must use hardened components: $part" }
            val n = part.dropLast(1).toLongOrNull()
            require(n != null && n in 0 until HARDENED) { "invalid path component $part" }
            val next = child(node, n + HARDENED)
            node.wipe()
            node = next
        }
        return node
    }

    private fun split(i: ByteArray): Node {
        val node = Node(i.copyOfRange(0, 32), i.copyOfRange(32, 64))
        i.fill(0)
        return node
    }

    private fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(data)
    }

    private fun u32be(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
}
