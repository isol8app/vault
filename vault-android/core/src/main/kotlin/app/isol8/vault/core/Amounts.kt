package app.isol8.vault.core

import java.math.BigInteger

/** Exact amount formatting for review screens: no floating point, no rounding, no hidden digits. */
object Amounts {
    const val SOL_DECIMALS = 9

    /** [base] units with [decimals] places, grouped with thin separators: "1,250", "0.000005", "40,000,000". */
    fun format(base: String, decimals: Int): String {
        require(decimals in 0..255) { "decimals out of range" }
        val v = BigInteger(base)
        require(v.signum() >= 0) { "negative amount" }
        val digits = v.toString().padStart(decimals + 1, '0')
        val whole = digits.dropLast(decimals).ifEmpty { "0" }
        val fraction = digits.takeLast(decimals).trimEnd('0')
        val grouped = whole.reversed().chunked(3).joinToString(",").reversed()
        return if (fraction.isEmpty()) grouped else "$grouped.$fraction"
    }

    fun sol(lamports: String): String = format(lamports, SOL_DECIMALS) + " SOL"
}
