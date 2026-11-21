package app.isol8.vault.crypto

import app.isol8.vault.core.Base58
import app.isol8.vault.core.Bip39
import app.isol8.vault.core.Pairing
import app.isol8.vault.core.Payload
import app.isol8.vault.core.Slip10Ed25519
import app.isol8.vault.core.concat
import app.isol8.vault.core.hex
import app.isol8.vault.core.sha256
import app.isol8.vault.core.unhex
import app.isol8.vault.core.utf8
import org.json.JSONObject
import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.X509EncodedKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BcEd25519Test {
    private val vectors = File(System.getProperty("isol8.vectors") ?: error("isol8.vectors not set"))
    private val coreTestResources = File(vectors, "../../vault-android/core/src/test/resources")

    /** RFC 8032 §7.1, tests 1–3. */
    @Test
    fun rfc8032Vectors() {
        val cases = listOf(
            Triple(
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "" to "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            Triple(
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72" to "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            Triple(
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82" to "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        )
        for ((secret, public, msgSig) in cases) {
            val signer = BcEd25519Signer(unhex(secret))
            assertEquals(public, hex(signer.publicKey))
            assertEquals(msgSig.second, hex(signer.sign(unhex(msgSig.first))))
        }
    }

    /** BouncyCastle and the JDK's independent Ed25519 must produce identical signatures (Ed25519 is deterministic). */
    @Test
    fun matchesJdkEd25519() {
        val kf = KeyFactory.getInstance("Ed25519")
        for (i in 0 until 300) {
            val seed = sha256(utf8("jdk cross-check seed $i"))
            val message = sha256(utf8("message $i")).copyOf(i % 32 + 1)
            val bc = BcEd25519Signer(seed)
            val jdkKey = kf.generatePrivate(EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed))
            val jdkSig = Signature.getInstance("Ed25519").run { initSign(jdkKey); update(message); sign() }
            assertContentEquals(jdkSig, bc.sign(message), "case $i")
            val pub = kf.generatePublic(X509EncodedKeySpec(concat(unhex("302a300506032b6570032100"), bc.publicKey)))
            assertTrue(Signature.getInstance("Ed25519").run { initVerify(pub); update(message); verify(jdkSig) }, "case $i: JDK verifies with BC's public key")
        }
    }

    /** SLIP-0010 spec vectors include the public key ("00" + Ed25519 public key). */
    @Test
    fun slip10PublicKeys() {
        val sets = JSONObject(File(coreTestResources, "slip10-ed25519.json").readText()).getJSONArray("sets")
        var checked = 0
        for (s in 0 until sets.length()) {
            val set = sets.getJSONObject(s)
            val chains = set.getJSONArray("chains")
            for (c in 0 until chains.length()) {
                val chain = chains.getJSONObject(c)
                val node = Slip10Ed25519.derive(unhex(set.getString("seed")), chain.getString("path"))
                assertEquals(chain.getString("public"), "00" + hex(BcEd25519Signer(node.privateKey).publicKey), chain.getString("path"))
                checked++
            }
        }
        assertEquals(12, checked)
    }

    /** Full Solana derivation against Node's independent implementation (protocol/vectors/keys.json). */
    @Test
    fun solanaDerivationMatchesNode() {
        val keys = JSONObject(File(vectors, "keys.json").readText())
        val message = utf8(keys.getString("signed_message"))
        val cases = keys.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val words = c.getString("mnemonic").split(" ")
            val passphrase = c.getString("passphrase")
            assertEquals(c.getString("seed_hex"), hex(Bip39.mnemonicToSeed(words, passphrase)), "case $i seed")
            val signer = SolanaKeys.signer(words, passphrase, c.getInt("account"))
            assertEquals(c.getString("address"), Base58.encode(signer.publicKey), "case $i address")
            assertEquals(c.getString("signature_hex"), hex(signer.sign(message)), "case $i signature")
        }
        assertEquals(36, cases.length())
    }

    /** The protocol's pairing vector, signed with BouncyCastle instead of the JDK. */
    @Test
    fun protocolPairingVector() {
        val common = JSONObject(File(vectors, "common.json").readText())
        val pairing = JSONObject(File(vectors, "pairing.json").readText())
        val signer = BcEd25519Signer(unhex(common.getString("vault_seed_hex")))
        assertEquals(common.getString("vault_pubkey_hex"), hex(signer.publicKey))
        val frames = pairing.getJSONObject("request").getJSONArray("frames").let { a -> List(a.length()) { a.getString(it) } }
        val request = Payload.decode(app.isol8.vault.core.Frames.decodeAll(frames)) as Payload.PairRequest
        val response = Pairing.respond(signer, request, 0, 1, 0)
        assertEquals(pairing.getJSONObject("response").getString("signature_hex"), hex(response.signature))
        assertEquals(pairing.getJSONObject("response").getString("payload_hex"), hex(Payload.encode(response)))
    }
}
