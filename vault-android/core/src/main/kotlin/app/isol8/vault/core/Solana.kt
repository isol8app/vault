package app.isol8.vault.core

import java.math.BigInteger

/** Solana constants and address derivation the vault needs offline. */
object Solana {
    val SYSTEM_PROGRAM = Base58.address("11111111111111111111111111111111")
    val COMPUTE_BUDGET_PROGRAM = Base58.address("ComputeBudget111111111111111111111111111111")
    val TOKEN_PROGRAM = Base58.address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    val TOKEN_2022_PROGRAM = Base58.address("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
    val ASSOCIATED_TOKEN_PROGRAM = Base58.address("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
    val MEMO_PROGRAM = Base58.address("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
    val SYSVAR_RECENT_BLOCKHASHES = Base58.address("SysvarRecentB1ockHashes11111111111111111111")
    val SYSVAR_RENT = Base58.address("SysvarRent111111111111111111111111111111111")

    const val NONCE_ACCOUNT_SPACE = 80L
    const val LAMPORTS_PER_SIGNATURE = 5_000L

    // ---- ed25519 point check, matching curve25519-dalek's CompressedEdwardsY::decompress ----

    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val D: BigInteger = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)

    fun isOnCurve(bytes: ByteArray): Boolean {
        require(bytes.size == 32)
        val le = bytes.reversedArray()
        le[0] = (le[0].toInt() and 0x7f).toByte() // clear the sign bit (top bit of the last byte)
        val y = BigInteger(1, le).mod(P) // dalek reduces non-canonical y instead of rejecting it
        val y2 = y.multiply(y).mod(P)
        val u = y2.subtract(BigInteger.ONE).mod(P)
        val v = D.multiply(y2).add(BigInteger.ONE).mod(P)
        val v3 = v.multiply(v).multiply(v).mod(P)
        val v7 = v3.multiply(v3).multiply(v).mod(P)
        val x = u.multiply(v3).multiply(u.multiply(v7).mod(P).modPow(P.subtract(BigInteger.valueOf(5)).shiftRight(3), P)).mod(P)
        val vx2 = v.multiply(x).multiply(x).mod(P)
        return vx2 == u || vx2 == u.negate().mod(P)
    }

    fun findProgramAddress(seeds: List<ByteArray>, programId: ByteArray): ByteArray {
        for (s in seeds) require(s.size <= 32) { "PDA seed longer than 32 bytes" }
        for (bump in 255 downTo 0) {
            val candidate = sha256(*seeds.toTypedArray(), byteArrayOf(bump.toByte()), programId, utf8("ProgramDerivedAddress"))
            if (!isOnCurve(candidate)) return candidate
        }
        throw IllegalStateException("no viable PDA bump")
    }

    fun associatedTokenAddress(owner: ByteArray, mint: ByteArray, tokenProgram: ByteArray): ByteArray =
        findProgramAddress(listOf(owner, tokenProgram, mint), ASSOCIATED_TOKEN_PROGRAM)

    /** System program "create with seed" address: SHA-256(base || seed || owner). */
    fun createWithSeed(base: ByteArray, seed: String, owner: ByteArray): ByteArray {
        val s = utf8(seed)
        require(s.size <= 32) { "seed longer than 32 bytes" }
        return sha256(base, s, owner)
    }
}
