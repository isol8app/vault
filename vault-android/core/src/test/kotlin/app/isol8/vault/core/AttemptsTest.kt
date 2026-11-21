package app.isol8.vault.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AttemptsTest {
    @Test
    fun fiveFreeTriesThenEscalatingWaits() {
        var a = PassphraseAttempts()
        val waits = (1..10).map { a = a.failed(); a.waitSeconds }
        assertEquals(listOf(0L, 0, 0, 0, 0, 60, 300, 1800, 3600, 3600), waits)
        assertEquals(10, a.failures)
    }

    @Test
    fun theWaitCountsDownOnlyAsServed() {
        val a = PassphraseAttempts(failures = 7, waitSeconds = 300)
        assertTrue(a.mustWait)
        assertEquals(240, a.waited(60).waitSeconds)
        assertFalse(a.waited(301).mustWait)
        assertEquals(0, a.waited(301).waitSeconds)
        assertEquals(7, a.waited(301).failures) // serving the wait doesn't forgive the failures
    }

    @Test
    fun roundTripsAndRejectsDamage() {
        val a = PassphraseAttempts(failures = 8, waitSeconds = 1234)
        assertEquals(a, PassphraseAttempts.decode(a.encode()))
        assertFailsWith<ProtocolException> { PassphraseAttempts.decode(byteArrayOf(2, 0, 0, 0, 0, 0, 0, 0, 0)) }
        assertFailsWith<ProtocolException> { PassphraseAttempts.decode(a.encode() + 0) }
        assertFailsWith<ProtocolException> { PassphraseAttempts.decode(a.encode().copyOf(5)) }
    }
}
