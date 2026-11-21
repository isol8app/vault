package app.isol8.vault.core

/**
 * Wrong vault passphrases and the wait they've earned (docs/SECURITY.md, "The key"). It slows down someone who has
 * the phone and its screen lock and is guessing the vault passphrase.
 *
 * The wait counts down only while the vault app is open, measured by the app, not the clock. Changing the date or
 * restarting the phone doesn't skip it. There's no auto-wipe: wiping only helps someone who wants to destroy, and the
 * recovery phrase is the real backup.
 *
 * Stored under the vault's Keystore key, as "attempts.bin": version=1 | failures u32 | waitSeconds u32.
 */
data class PassphraseAttempts(val failures: Int = 0, val waitSeconds: Long = 0) {
    init {
        require(failures >= 0 && waitSeconds >= 0)
    }

    /** A wrong passphrase: one more failure, and the wait it earns. */
    fun failed(): PassphraseAttempts = PassphraseAttempts(failures + 1, waitFor(failures + 1))

    /** [seconds] of the wait served with the app open. */
    fun waited(seconds: Long): PassphraseAttempts = copy(waitSeconds = maxOf(0, waitSeconds - seconds))

    val mustWait: Boolean get() = waitSeconds > 0

    fun encode(): ByteArray = concat(u8(VERSION), u32le(failures.toLong()), u32le(waitSeconds))

    companion object {
        private const val VERSION = 1
        /** Wrong passphrases allowed without any wait: typos happen. */
        const val FREE_TRIES = 5
        private val WAITS = longArrayOf(60, 5 * 60, 30 * 60, 60 * 60)

        /** No wait for the first [FREE_TRIES] failures, then 1, 5 and 30 minutes, then an hour after each one. */
        fun waitFor(failures: Int): Long =
            if (failures <= FREE_TRIES) 0 else WAITS[minOf(failures - FREE_TRIES, WAITS.size) - 1]

        fun decode(bytes: ByteArray): PassphraseAttempts {
            val r = Reader(bytes)
            if (r.u8() != VERSION) throw ProtocolException("BAD_FIELD", "unknown attempts version")
            val failures = r.u32()
            val wait = r.u32()
            r.end()
            if (failures > Int.MAX_VALUE) throw ProtocolException("BAD_FIELD", "failure count out of range")
            return PassphraseAttempts(failures.toInt(), wait)
        }
    }
}
