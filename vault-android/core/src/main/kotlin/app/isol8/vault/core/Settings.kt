package app.isol8.vault.core

import java.math.BigInteger

/** A saved destination. Only the user can add, rename or remove these, on the vault. */
class AddressBookEntry(val label: String, val address: ByteArray) {
    val base58: String get() = Base58.encode(address)
}

/**
 * The vault's own settings, used by the acceptance rules (PROTOCOL.md §6, rules 5 and 6).
 *
 * Stored format: "I8ST" | version 1 | high-fee threshold u64 | entry count u16 | entries,
 * each entry = address (32) | label length u8 | label (printable ASCII). All integers little-endian;
 * no trailing bytes. The app encrypts it with the vault's Keystore key.
 */
class VaultSettings(
    val addressBook: List<AddressBookEntry> = emptyList(),
    val highFeeThresholdLamports: BigInteger = Acceptance.DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS,
) {
    fun vaultState(heldSigners: List<ByteArray>): VaultState =
        VaultState(heldSigners, addressBook.map { it.label to it.address }, highFeeThresholdLamports, Base58.address(Acceptance.ISOL8_FEE_OWNER))

    /** The result of checking a new entry: an error that blocks saving, and warnings the user must see. */
    class Check(val error: String?, val warnings: List<String>)

    fun checkNewEntry(label: String, address: ByteArray, ownAddresses: List<ByteArray> = emptyList()): Check {
        labelError(label)?.let { return Check(it, emptyList()) }
        if (address.size != 32) return Check("An address is 32 bytes.", emptyList())
        if (addressBook.size >= MAX_ENTRIES) return Check("The address book is full ($MAX_ENTRIES entries).", emptyList())
        addressBook.firstOrNull { it.address.contentEquals(address) }?.let { return Check("This address is already saved as \"${it.label}\".", emptyList()) }
        addressBook.firstOrNull { it.label.equals(label.trim(), ignoreCase = true) }?.let { return Check("The name \"${it.label}\" is already used.", emptyList()) }
        if (ownAddresses.any { it.contentEquals(address) }) return Check("That's this vault's own address. It's always shown as \"this vault\".", emptyList())
        return Check(null, lookalikeWarnings(address, ownAddresses))
    }

    /** Warnings for an address that resembles a saved one or this vault's own (same first and last 4 characters). */
    fun lookalikeWarnings(address: ByteArray, ownAddresses: List<ByteArray> = emptyList()): List<String> {
        val b58 = Base58.encode(address)
        val known = addressBook.map { it.label to it.base58 } + ownAddresses.map { "this vault" to Base58.encode(it) }
        return known.filter { (_, a) -> Acceptance.looksAlike(b58, a) }.map { (l, a) ->
            "This address looks like \"$l\" ($a): same first and last 4 characters, but a different address. " +
                "Scammers create lookalike addresses on purpose (address poisoning). Only save it if you're sure it's right."
        }
    }

    fun withEntry(label: String, address: ByteArray): VaultSettings =
        VaultSettings(addressBook + AddressBookEntry(label.trim(), address.copyOf()), highFeeThresholdLamports)

    fun withoutEntry(address: ByteArray): VaultSettings =
        VaultSettings(addressBook.filterNot { it.address.contentEquals(address) }, highFeeThresholdLamports)

    fun withThreshold(lamports: BigInteger): VaultSettings {
        require(lamports in THRESHOLD_CHOICES) { "unsupported threshold" }
        return VaultSettings(addressBook, lamports)
    }

    fun encode(): ByteArray {
        val parts = mutableListOf(MAGIC, u8(VERSION), u64le(highFeeThresholdLamports.toLong().toULong()), u16le(addressBook.size))
        for (e in addressBook) {
            val label = e.label.toByteArray(Charsets.US_ASCII)
            parts += e.address
            parts += u8(label.size)
            parts += label
        }
        return concat(*parts.toTypedArray())
    }

    companion object {
        const val VERSION = 1
        const val MAX_ENTRIES = 200
        const val MAX_LABEL = 32
        private val MAGIC = "I8ST".toByteArray(Charsets.US_ASCII)

        /** Printable ASCII only: no direction overrides or lookalike Unicode letters in labels. */
        private val LABEL = Regex("^[\\x20-\\x7e]+$")

        /** Fee-warning thresholds offered on the vault: 0.001, 0.005, 0.01 (default), 0.05 and 0.1 SOL. */
        val THRESHOLD_CHOICES: List<BigInteger> = listOf(1_000_000L, 5_000_000L, 10_000_000L, 50_000_000L, 100_000_000L).map(BigInteger::valueOf)

        fun labelError(label: String): String? {
            val t = label.trim()
            return when {
                t.isEmpty() -> "Enter a name."
                t.length > MAX_LABEL -> "Use at most $MAX_LABEL characters."
                !LABEL.matches(t) -> "Use plain letters, digits, spaces and punctuation (no accents or emoji), so names can't imitate each other."
                t.equals("this vault", ignoreCase = true) -> "\"this vault\" is reserved for this vault's own address."
                else -> null
            }
        }

        fun decode(bytes: ByteArray): VaultSettings {
            val r = Reader(bytes)
            if (!r.take(4).contentEquals(MAGIC)) throw ProtocolException("BAD_SETTINGS", "not a settings file")
            if (r.u8() != VERSION) throw ProtocolException("BAD_SETTINGS", "unsupported settings version")
            val threshold = r.u64().toBigInteger()
            if (threshold !in THRESHOLD_CHOICES) throw ProtocolException("BAD_SETTINGS", "unsupported fee threshold")
            val count = r.u16()
            if (count > MAX_ENTRIES) throw ProtocolException("BAD_SETTINGS", "too many entries")
            var s = VaultSettings(emptyList(), threshold)
            repeat(count) {
                val address = r.take(32)
                val label = String(r.take(r.u8()), Charsets.US_ASCII)
                val check = s.checkNewEntry(label, address)
                if (check.error != null || label != label.trim()) throw ProtocolException("BAD_SETTINGS", "invalid entry: ${check.error ?: "untrimmed label"}")
                s = s.withEntry(label, address)
            }
            r.end()
            return s
        }

        /**
         * Reads an address from what a wallet's receive QR code or the user provides: a bare Base58 address,
         * or a Solana Pay link ("solana:<address>?..."), with surrounding spaces ignored. Null if it isn't one.
         */
        fun parseAddress(input: String): ByteArray? {
            var t = input.trim()
            if (t.startsWith("solana:", ignoreCase = true)) t = t.substring(7).substringBefore('?')
            if (t.length !in 32..44) return null
            return try {
                Base58.decode(t).takeIf { it.size == 32 && Base58.encode(it) == t }
            } catch (e: Exception) {
                null
            }
        }
    }
}
