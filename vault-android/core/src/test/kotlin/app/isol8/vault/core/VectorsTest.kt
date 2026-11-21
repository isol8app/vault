package app.isol8.vault.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Runs the Kotlin core against the shared vectors from protocol/ (the TypeScript reference). */
class VectorsTest {
    private val dir = File(System.getProperty("isol8.vectors") ?: error("isol8.vectors not set"))
    private fun obj(name: String) = JSONObject(File(dir, name).readText())
    private fun arr(name: String) = JSONArray(File(dir, name).readText())
    private fun JSONArray.strings() = List(length()) { getString(it) }
    private fun JSONArray.objects() = List(length()) { getJSONObject(it) }

    private val common = obj("common.json")
    private val vaultSeed = unhex(common.getString("vault_seed_hex"))
    private val vaultPub = unhex(common.getString("vault_pubkey_hex"))
    private val signer = JdkEd25519Signer(vaultSeed, vaultPub)
    private val state = common.getJSONObject("vault_state").let { s ->
        VaultState(
            heldSigners = s.getJSONArray("held_signers").strings().map(Base58::address),
            addressBook = s.getJSONArray("address_book").objects().map { it.getString("label") to Base58.address(it.getString("address")) },
            highFeeThresholdLamports = BigInteger(s.getString("high_fee_threshold_lamports")),
        )
    }

    @Test
    fun base45() {
        val v = obj("base45.json")
        for (c in v.getJSONArray("valid").objects()) {
            assertEquals(c.getString("text"), Base45.encode(unhex(c.getString("bytes_hex"))))
            assertEquals(c.getString("bytes_hex"), hex(Base45.decode(c.getString("text"))))
        }
        for (c in v.getJSONArray("invalid").objects()) {
            val e = assertFailsWith<ProtocolException> { Base45.decode(c.getString("text")) }
            assertEquals(c.getString("error"), e.code)
        }
    }

    @Test
    fun pairing() {
        val v = obj("pairing.json")
        val request = assertIs<Payload.PairRequest>(Payload.decode(Frames.decodeAll(v.getJSONObject("request").getJSONArray("frames").strings())))
        assertEquals(v.getString("origin"), request.origin)
        assertEquals(v.getString("challenge_hex"), hex(request.challenge))
        assertEquals(v.getString("statement"), Pairing.statement(request.origin, vaultPub, request.challenge))
        assertEquals(v.getString("offchain_message_hex"), hex(Pairing.offchainMessageV0(v.getString("statement"), vaultPub)))

        val response = Pairing.respond(signer, request, v.getLong("account_index"), 1, 0)
        val expected = v.getJSONObject("response")
        assertEquals(expected.getString("signature_hex"), hex(response.signature), "Ed25519 is deterministic, so signatures must match")
        val payload = Payload.encode(response)
        assertEquals(expected.getString("payload_hex"), hex(payload))
        assertEquals(expected.getJSONArray("frames").strings(), Frames.encode(payload))
        assertTrue(ed25519Verify(vaultPub, unhex(v.getString("offchain_message_hex")), response.signature))
    }

    @Test
    fun transactions() {
        for (c in arr("transactions.json").objects()) {
            val name = c.getString("name")
            val req = c.getJSONObject("request")
            val frames = req.getJSONArray("frames").strings()
            val request = assertIs<Payload.SignTxRequest>(Payload.decode(Frames.decodeAll(frames)), name)
            assertEquals(c.getString("message_hex"), hex(request.message), name)
            assertEquals(frames, Frames.encode(Payload.encode(request)), "$name: frames must match the TypeScript byte for byte")

            val decision = Acceptance.evaluate(request, state)
            val expected = c.getJSONObject("expected")
            if (expected.getString("decision") == "accept") {
                assertIs<Decision.Accept>(decision, "$name: $decision")
                assertEquals(expected.toMap(), decision.toJson(), name)
                val response = TxSigning.respond(signer, request)
                val exp = c.getJSONObject("response")
                assertEquals(exp.getString("payload_hex"), hex(Payload.encode(response)), name)
                assertEquals(exp.getJSONArray("frames").strings(), Frames.encode(Payload.encode(response)), name)
            } else {
                val d = assertIs<Decision.Decline>(decision, "$name: $decision")
                assertEquals(expected.getInt("reason"), d.reason, "$name: ${d.why}")
                val declined = Payload.encode(TxSigning.decline(request, d.reason))
                assertEquals(c.getJSONObject("declined").getString("payload_hex"), hex(declined), name)
            }
        }
    }

    @Test
    fun swaps() {
        val swaps = obj("swaps.json")
        val swapState = VaultState(state.heldSigners, state.addressBook, state.highFeeThresholdLamports,
            Base58.address(swaps.getString("fee_owner")), swaps.getInt("max_swap_fee_bps"))
        val cases = swaps.getJSONArray("cases").objects()
        assertTrue(cases.size >= 10)
        for (c in cases) {
            val name = c.getString("name")
            val frames = c.getJSONObject("request").getJSONArray("frames").strings()
            val request = assertIs<Payload.SignTxRequest>(Payload.decode(Frames.decodeAll(frames)), name)
            assertEquals(c.getString("message_hex"), hex(request.message), name)
            val decision = Acceptance.evaluate(request, swapState)
            val expected = c.getJSONObject("expected")
            if (expected.getString("decision") == "accept") {
                assertIs<Decision.Accept>(decision, "$name: $decision")
                assertEquals(expected.toMap(), decision.toJson(), name)
                val response = TxSigning.respond(signer, request)
                assertEquals(c.getJSONObject("response").getString("payload_hex"), hex(Payload.encode(response)), name)
            } else {
                val d = assertIs<Decision.Decline>(decision, "$name: $decision")
                assertEquals(expected.getInt("reason"), d.reason, "$name: ${d.why}")
                assertEquals(expected.getString("why"), d.why, name)
            }
        }
        // Without a fee owner built in, the vault refuses any fee but signs fee-free swaps.
        val byName = cases.associateBy { it.getString("name") }
        fun req(n: String) = Payload.decode(Frames.decodeAll(byName.getValue(n).getJSONObject("request").getJSONArray("frames").strings())) as Payload.SignTxRequest
        assertEquals("this vault doesn't allow swap fees", assertIs<Decision.Decline>(Acceptance.evaluate(req("sol_to_usdc_fee"), state)).why)
        assertIs<Decision.Accept>(Acceptance.evaluate(req("sol_to_usdc_no_fee"), state))
    }

    @Test
    fun invalidInputs() {
        for (c in arr("invalid.json").objects()) {
            val e = assertFailsWith<ProtocolException>(c.getString("name")) { Payload.decode(Frames.decodeAll(c.getJSONArray("frames").strings())) }
            assertEquals(c.getString("error"), e.code, c.getString("name"))
        }
    }

    @Test
    fun derivedAddresses() {
        val nonce = common.getJSONObject("nonce_account")
        assertEquals(nonce.getString("address"), Base58.encode(Solana.createWithSeed(vaultPub, nonce.getString("seed"), Solana.SYSTEM_PROGRAM)))
        assertContentEquals(vaultPub, Base58.address(common.getString("vault_address")))
    }

    @Test
    fun corruptedAndRandomMessagesNeverCrash() {
        val accepted = arr("transactions.json").objects().filter { it.getJSONObject("expected").getString("decision") == "accept" }
        for (c in accepted) {
            val base = unhex(c.getString("message_hex"))
            val requestId = unhex(c.getJSONObject("request").getString("request_id_hex"))
            for (i in 0 until 400) {
                val m = base.copyOf()
                val h = sha256(utf8("${c.getString("name")}:$i"))
                val flips = 1 + h.u8At(0) % 3
                for (f in 0 until flips) {
                    val pos = (h.u8At(1 + f * 2) * 256 + h.u8At(2 + f * 2)) % m.size
                    m[pos] = (m[pos].toInt() xor (1 shl (h.u8At(8 + f) % 8))).toByte()
                }
                Acceptance.evaluate(Payload.SignTxRequest(requestId, vaultPub, m), state) // must not throw
            }
        }
        for (i in 0 until 2000) {
            val len = 1 + i % 400
            val m = ByteArray(len) { j -> sha256(utf8("rand $i ${j / 32}"))[j % 32] }
            assertIs<Decision.Decline>(Acceptance.evaluate(Payload.SignTxRequest(ByteArray(16), vaultPub, m), state))
        }
    }

    @Test
    fun compactU16RejectsNonCanonical() {
        fun read(vararg b: Int) = ParsedMessage.readCompactU16(Reader(ByteArray(b.size) { b[it].toByte() }))
        assertEquals(0, read(0x00))
        assertEquals(128, read(0x80, 0x01))
        assertEquals(0xffff, read(0xff, 0xff, 0x03))
        for (bad in listOf(intArrayOf(0x80, 0x00), intArrayOf(0x80, 0x80, 0x00), intArrayOf(0xff, 0xff, 0x04), intArrayOf(0x80, 0x80, 0x80, 0x01))) {
            assertFailsWith<ProtocolException> { read(*bad) }
        }
    }
}

/** The decision format of PROTOCOL.md §6.1, for comparison with the vectors. */
fun Decision.toJson(): Map<String, Any?> = when (this) {
    is Decision.Decline -> mapOf("decision" to "decline", "reason" to reason, "why" to why)
    is Decision.Accept -> buildMap {
        put("decision", "accept")
        put("lifetime", if (durableNonce) "durable_nonce" else "recent_blockhash")
        nonceAccount?.let { put("nonce_account", it) }
        put("max_fee_lamports", maxFeeLamports)
        put("actions", actions.map { it.toJson() })
        put("warnings", warnings.map { it.toJson() })
    }
}

fun Action.toJson(): Map<String, Any> = when (this) {
    is Action.SolTransfer -> buildMap {
        put("kind", "sol_transfer"); put("to", to); put("lamports", lamports)
        toLabel?.let { put("to_label", it) }
    }
    is Action.CreateTokenAccount -> buildMap {
        put("kind", "create_token_account"); put("owner", owner); put("mint", mint); put("account", account); put("rent_payer", rentPayer)
        mintSymbol?.let { put("mint_symbol", it) }
    }
    is Action.TokenTransfer -> buildMap {
        put("kind", "token_transfer"); put("mint", mint); put("amount", amount); put("decimals", decimals)
        put("to_owner", toOwner); put("to_account", toAccount)
        mintSymbol?.let { put("mint_symbol", it) }
        toLabel?.let { put("to_label", it) }
    }
    is Action.Memo -> mapOf("kind" to "memo", "text" to text)
    is Action.CreateNonceAccount -> mapOf("kind" to "create_nonce_account", "account" to account, "seed" to seed, "lamports" to lamports, "authority" to authority)
    is Action.WrapSol -> mapOf("kind" to "wrap_sol", "lamports" to lamports)
    is Action.UnwrapSol -> mapOf("kind" to "unwrap_sol")
    is Action.CloseTokenAccount -> mapOf("kind" to "close_token_account", "account" to account)
    is Action.WithdrawNonceAccount -> mapOf("kind" to "withdraw_nonce_account", "account" to account, "lamports" to lamports)
    is Action.Swap -> buildMap {
        put("kind", "swap"); put("in_mint", inMint); put("in_amount", inAmount); put("in_decimals", inDecimals)
        put("out_mint", outMint); put("quoted_out_amount", quotedOutAmount); put("min_out_amount", minOutAmount); put("out_decimals", outDecimals)
        put("slippage_bps", slippageBps); put("fee_bps", feeBps)
        feeMint?.let { put("fee_mint", it) }
        inSymbol?.let { put("in_symbol", it) }
        outSymbol?.let { put("out_symbol", it) }
    }
}

fun Warning.toJson(): Map<String, Any> = when (this) {
    is Warning.HighFee -> mapOf("code" to "HIGH_FEE", "max_fee_lamports" to maxFeeLamports, "threshold_lamports" to thresholdLamports)
    is Warning.LookalikeAddress -> mapOf("code" to "LOOKALIKE_ADDRESS", "address" to address, "resembles" to resembles, "label" to label)
    is Warning.NearMissAddress -> mapOf("code" to "NEAR_MISS_ADDRESS", "address" to address, "resembles" to resembles, "label" to label, "differences" to differences)
    is Warning.HighSlippage -> mapOf("code" to "HIGH_SLIPPAGE", "slippage_bps" to slippageBps, "threshold_bps" to thresholdBps)
}
