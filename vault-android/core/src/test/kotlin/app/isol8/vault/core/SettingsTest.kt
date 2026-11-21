package app.isol8.vault.core

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SettingsTest {
    private val desk = Base58.decode("icrGKa8xXzoqyADEbTQTzehtbXasoNDnvA5eetr6Q5C")
    private val recipient = Base58.decode("4514nRYcbFMiHP3zcJphMCqpceps8uGV3geRqn6Pas5i")
    private val vault = Base58.decode("4DKubqYmFiXNbWDWMersXVVoynoHpvtuXAunLSrBc1ek")

    /** Same first and last 4 characters as [desk], different address. */
    private fun lookalike(of: ByteArray): ByteArray {
        val t = Base58.encode(of)
        for (pos in 10 until t.length - 10) for (c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") {
            if (c == t[pos]) continue
            val cand = t.substring(0, pos) + c + t.substring(pos + 1)
            val b = try { Base58.decode(cand) } catch (e: Exception) { continue }
            if (b.size == 32 && Base58.encode(b) == cand) return b
        }
        error("none")
    }

    @Test
    fun roundTrips() {
        val s = VaultSettings().withEntry("Desk wallet", desk).withEntry("  Exchange  ", recipient).withThreshold(BigInteger.valueOf(50_000_000))
        val back = VaultSettings.decode(s.encode())
        assertEquals(listOf("Desk wallet", "Exchange"), back.addressBook.map { it.label })
        assertContentEquals(recipient, back.addressBook[1].address)
        assertEquals(BigInteger.valueOf(50_000_000), back.highFeeThresholdLamports)
        assertEquals(Acceptance.DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS, VaultSettings.decode(VaultSettings().encode()).highFeeThresholdLamports)
    }

    @Test
    fun rejectsBadEntries() {
        val s = VaultSettings().withEntry("Desk wallet", desk)
        assertNotNull(s.checkNewEntry("Other", desk).error, "duplicate address")
        assertNotNull(s.checkNewEntry("desk WALLET", recipient).error, "duplicate name")
        assertNotNull(s.checkNewEntry("", recipient).error)
        assertNotNull(s.checkNewEntry("x".repeat(33), recipient).error)
        assertNotNull(s.checkNewEntry("Dеsk", recipient).error, "Cyrillic е")
        assertNotNull(s.checkNewEntry("a‮b", recipient).error, "direction override")
        assertNotNull(s.checkNewEntry("This Vault", recipient).error)
        assertNotNull(s.checkNewEntry("Me", vault, ownAddresses = listOf(vault)).error)
        assertNull(s.checkNewEntry("Exchange", recipient).error)
    }

    @Test
    fun warnsAboutLookalikes() {
        val s = VaultSettings().withEntry("Desk wallet", desk)
        val c = s.checkNewEntry("New", lookalike(desk))
        assertNull(c.error)
        assertEquals(1, c.warnings.size)
        assertTrue("Desk wallet" in c.warnings[0])
        assertEquals(1, VaultSettings().checkNewEntry("New", lookalike(vault), listOf(vault)).warnings.size)
    }

    @Test
    fun evaluatorUsesTheBook() {
        val st = VaultSettings().withEntry("Desk wallet", desk).vaultState(listOf(vault))
        assertEquals(1, st.addressBook.size)
        assertEquals("Desk wallet", st.addressBook[0].first)
    }

    @Test
    fun evaluatorAllowsIsol8FeesOnly() {
        val st = VaultSettings().vaultState(listOf(vault))
        assertEquals(Acceptance.ISOL8_FEE_OWNER, Base58.encode(st.swapFeeOwner!!))
        assertEquals(32, st.swapFeeOwner!!.size)
        assertEquals(50, st.maxSwapFeeBps)
    }

    @Test
    fun strictDecoding() {
        val good = VaultSettings().withEntry("Desk wallet", desk).encode()
        assertFailsWith<ProtocolException> { VaultSettings.decode(good + 0) }
        assertFailsWith<ProtocolException> { VaultSettings.decode(good.copyOf(good.size - 1)) }
        assertFailsWith<ProtocolException> { VaultSettings.decode(good.copyOf().also { it[4] = 2 }) }
        assertFailsWith<ProtocolException> { VaultSettings.decode(good.copyOf().also { it[5] = 7 }) } // threshold not offered
        // Two entries with the same address are refused on load too.
        val dup = VaultSettings().withEntry("A", desk).encode()
        val header = 4 + 1 + 8 // magic, version, threshold; then the u16 count
        val entry = dup.copyOfRange(header + 2, dup.size) // address 32 | length 1 | "A"
        assertEquals(34, entry.size)
        val twice = concat(dup.copyOfRange(0, header), u16le(2), entry, entry.copyOf().also { it[33] = 'B'.code.toByte() })
        assertFailsWith<ProtocolException> { VaultSettings.decode(twice) }
    }

    @Test
    fun parsesAddressInput() {
        val a = "icrGKa8xXzoqyADEbTQTzehtbXasoNDnvA5eetr6Q5C"
        assertContentEquals(desk, VaultSettings.parseAddress(a))
        assertContentEquals(desk, VaultSettings.parseAddress("  $a\n"))
        assertContentEquals(desk, VaultSettings.parseAddress("solana:$a?amount=1&label=x"))
        assertNull(VaultSettings.parseAddress(a.dropLast(1) + "0")) // 0 isn't Base58
        assertNull(VaultSettings.parseAddress(a.drop(5)))
        assertNull(VaultSettings.parseAddress("https://evil.example/$a"))
        assertNull(VaultSettings.parseAddress("ISOL8:ABC"))
    }
}
