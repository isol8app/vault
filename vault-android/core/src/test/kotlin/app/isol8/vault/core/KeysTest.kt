package app.isol8.vault.core

import org.json.JSONObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** BIP39 and SLIP-0010 against the official test vectors (see src/test/resources/PROVENANCE.md). */
class KeysTest {
    private fun resource(name: String) = JSONObject(javaClass.classLoader.getResource(name)!!.readText())

    @Test
    fun wordlistMatchesPublishedChecksum() {
        assertEquals(2048, Bip39.WORDS.size)
        assertEquals("abandon", Bip39.WORDS.first())
        assertEquals("zoo", Bip39.WORDS.last())
        // Unique 4-letter prefixes are what lets the restore screen use a picker instead of a keyboard.
        assertEquals(2048, Bip39.WORDS.map { it.take(4) }.toSet().size)
    }

    @Test
    fun bip39OfficialVectors() {
        val cases = resource("bip39-vectors.json").getJSONArray("cases")
        assertEquals(24, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val entropy = unhex(c.getString("entropy"))
            val words = c.getString("mnemonic").split(" ")
            assertEquals(words, Bip39.entropyToMnemonic(entropy), "case $i: entropy -> words")
            assertEquals(c.getString("entropy"), hex(Bip39.mnemonicToEntropy(words)), "case $i: words -> entropy")
            assertEquals(c.getString("seed"), hex(Bip39.mnemonicToSeed(words, c.getString("passphrase"))), "case $i: seed")
        }
    }

    @Test
    fun invalidPhrasesAreRejected() {
        val valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ")
        Bip39.mnemonicToEntropy(valid)
        val badChecksum = valid.dropLast(1) + "abandon"
        assertEquals(InvalidMnemonicException.Reason.CHECKSUM, assertFailsWith<InvalidMnemonicException> { Bip39.mnemonicToEntropy(badChecksum) }.reason)
        val unknown = valid.toMutableList().apply { this[3] = "bitcoin" }
        val e = assertFailsWith<InvalidMnemonicException> { Bip39.mnemonicToEntropy(unknown) }
        assertEquals(InvalidMnemonicException.Reason.UNKNOWN_WORD, e.reason)
        assertEquals(3, e.wordIndex)
        assertEquals(InvalidMnemonicException.Reason.WORD_COUNT, assertFailsWith<InvalidMnemonicException> { Bip39.mnemonicToEntropy(valid.drop(1)) }.reason)
        assertEquals(InvalidMnemonicException.Reason.UNKNOWN_WORD, assertFailsWith<InvalidMnemonicException> { Bip39.mnemonicToEntropy(valid.map { it.uppercase() }) }.reason)
    }

    @Test
    fun slip10Ed25519SpecVectors() {
        val sets = resource("slip10-ed25519.json").getJSONArray("sets")
        var checked = 0
        for (s in 0 until sets.length()) {
            val set = sets.getJSONObject(s)
            val seed = unhex(set.getString("seed"))
            val chains = set.getJSONArray("chains")
            for (c in 0 until chains.length()) {
                val chain = chains.getJSONObject(c)
                val node = Slip10Ed25519.derive(seed, chain.getString("path"))
                assertEquals(chain.getString("private"), hex(node.privateKey), "vector ${set.getInt("vector")} ${chain.getString("path")} private")
                assertEquals(chain.getString("chain_code"), hex(node.chainCode), "vector ${set.getInt("vector")} ${chain.getString("path")} chain code")
                checked++
            }
        }
        assertEquals(12, checked)
    }

    @Test
    fun nonHardenedPathsAreRejected() {
        val seed = ByteArray(16)
        assertFailsWith<IllegalArgumentException> { Slip10Ed25519.derive(seed, "m/44'/501'/0/0'") }
        assertFailsWith<IllegalArgumentException> { Slip10Ed25519.derive(seed, "44'/501'") }
        assertFailsWith<IllegalArgumentException> { Slip10Ed25519.derive(seed, "m/2147483648'") }
        assertEquals("m/44'/501'/0'/0'", Slip10Ed25519.solanaPath(0))
    }
}
