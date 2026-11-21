package app.isol8.vault.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AmountsTest {
    @Test
    fun formatsExactly() {
        assertEquals("1,250 SOL", Amounts.sol("1250000000000"))
        assertEquals("0.000005 SOL", Amounts.sol("5000"))
        assertEquals("0 SOL", Amounts.sol("0"))
        assertEquals("0.000000001 SOL", Amounts.sol("1"))
        assertEquals("1.5 SOL", Amounts.sol("1500000000"))
        assertEquals("40,000,000", Amounts.format("40000000000000", 6))
        assertEquals("0.123456789", Amounts.format("123456789", 9))
        assertEquals("123", Amounts.format("123", 0))
        assertEquals("18,446,744,073.709551615", Amounts.format("18446744073709551615", 9)) // u64 max
        assertEquals("1,000", Amounts.format("1000", 0))
        assertEquals("100", Amounts.format("100", 0))
    }

    @Test
    fun rejectsBadInput() {
        assertFailsWith<IllegalArgumentException> { Amounts.format("-1", 0) }
        assertFailsWith<NumberFormatException> { Amounts.format("1e9", 0) }
    }
}
