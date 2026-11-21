package app.isol8.vault.core

/**
 * Ed25519 signing, supplied by the platform. The core has no crypto dependency of its own:
 * the Android app provides a hardened implementation, the tests use the JDK's built-in Ed25519.
 */
interface Ed25519Signer {
    val publicKey: ByteArray
    fun sign(message: ByteArray): ByteArray
}

/** Pairing (PROTOCOL.md §5): a Solana off-chain message (v0) over a one-line statement. */
object Pairing {
    /** "\xff" + "solana offchain": cannot be the start of a valid transaction message. */
    val SIGNING_DOMAIN: ByteArray = concat(byteArrayOf(0xff.toByte()), utf8("solana offchain"))

    /** Off-chain message application domain for isol8: SHA-256("isol8.app"). */
    val APPLICATION_DOMAIN: ByteArray = sha256(utf8("isol8.app"))

    private val RESTRICTED_ASCII = Regex("^[\\x20-\\x7e]+$")

    /**
     * Origins a release build will pair with (PROTOCOL.md §5.1). The origin is self-declared by the QR code,
     * so this only stops requests that name another site; the dashboard's signature check is the real binding.
     */
    val OFFICIAL_ORIGINS: Set<String> = setOf("isol8.app")

    enum class OriginCheck { OFFICIAL, WARN, BLOCK }

    /** Release builds block unofficial origins; development builds warn, so test origins still work. */
    fun checkOrigin(origin: String, developmentBuild: Boolean): OriginCheck = when {
        origin in OFFICIAL_ORIGINS -> OriginCheck.OFFICIAL
        developmentBuild -> OriginCheck.WARN
        else -> OriginCheck.BLOCK
    }

    fun statement(origin: String, pubkey: ByteArray, challenge: ByteArray): String =
        "isol8 pairing; origin: $origin; account: ${Base58.encode(pubkey)}; challenge: ${hex(challenge)}"

    fun offchainMessageV0(text: String, signer: ByteArray): ByteArray {
        if (!RESTRICTED_ASCII.matches(text)) throw ProtocolException("BAD_FIELD", "off-chain text must be printable ASCII")
        val body = utf8(text)
        if (body.size > 1232) throw ProtocolException("BAD_FIELD", "off-chain text too long")
        return concat(SIGNING_DOMAIN, u8(0), APPLICATION_DOMAIN, u8(0), u8(1), signer, u16le(body.size), body)
    }

    fun respond(signer: Ed25519Signer, request: Payload.PairRequest, accountIndex: Long, major: Int, minor: Int): Payload.PairResponse {
        val message = offchainMessageV0(statement(request.origin, signer.publicKey, request.challenge), signer.publicKey)
        return Payload.PairResponse(signer.publicKey, accountIndex, major, minor, signer.sign(message))
    }
}

object TxSigning {
    /**
     * Sign a request's message. Call only after [Acceptance.evaluate] accepted it and the user confirmed:
     * this function does not apply the acceptance rules itself.
     */
    fun respond(signer: Ed25519Signer, request: Payload.SignTxRequest): Payload.SignTxResponse {
        if (!bytesEqual(signer.publicKey, request.signer)) throw ProtocolException("UNKNOWN_SIGNER", "this key is not the requested signer")
        return Payload.SignTxResponse(request.requestId, signer.publicKey, sha256(request.message), signer.sign(request.message))
    }

    fun decline(request: Payload.SignTxRequest, reason: Int): Payload.SignTxDeclined = Payload.SignTxDeclined(request.requestId, reason)
}
