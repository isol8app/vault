package app.isol8.vault.core

/**
 * Strict parser for Solana transaction messages (legacy, v0 and v1 / SIMD-0385).
 * Anything malformed throws ProtocolException("MALFORMED_MESSAGE"). Bounds are checked before every read.
 */
class ParsedMessage(
    val version: Int, // -1 = legacy, 0 = v0, 1 = v1
    val numRequiredSignatures: Int,
    val numReadonlySigned: Int,
    val numReadonlyUnsigned: Int,
    val staticKeys: List<ByteArray>,
    val lifetime: ByteArray,
    val instructions: List<Instruction>,
    val lookups: List<Lookup>,
    /** v1 only: what legacy transactions set with ComputeBudget instructions. */
    val config: V1Config? = null,
) {
    class V1Config(
        val priorityFeeLamports: ULong? = null,
        val computeUnitLimit: Long? = null,
        val loadedAccountsDataSizeLimit: Long? = null,
        val heapSize: Long? = null,
    )

    class Instruction(val programIdIndex: Int, val accounts: IntArray, val data: ByteArray)
    class Lookup(val table: ByteArray, val writable: IntArray, val readonly: IntArray)

    companion object {
        const val LEGACY = -1

        private fun malformed(why: String): Nothing = throw ProtocolException("MALFORMED_MESSAGE", why)

        /** Solana short_vec: at most 3 bytes, canonical encoding only, value at most 0xffff. */
        fun readCompactU16(r: Reader): Int {
            var value = 0
            for (i in 0 until 3) {
                val byte = r.u8()
                value = value or ((byte and 0x7f) shl (7 * i))
                if ((byte and 0x80) == 0) {
                    if (i > 0 && byte == 0) malformed("non-canonical compact-u16")
                    if (value > 0xffff) malformed("compact-u16 out of range")
                    return value
                }
            }
            malformed("compact-u16 longer than 3 bytes")
        }

        private fun readIndexes(r: Reader): IntArray {
            val n = readCompactU16(r)
            if (n > r.remaining) malformed("index list longer than the message")
            val b = r.take(n)
            return IntArray(n) { b.u8At(it) }
        }

        fun parse(bytes: ByteArray): ParsedMessage = try {
            parseInner(bytes)
        } catch (e: ProtocolException) {
            if (e.code == "MALFORMED_MESSAGE") throw e
            malformed(e.message ?: e.code)
        }

        const val V1 = 1
        const val V1_MAX_ACCOUNTS = 64
        const val V1_MAX_INSTRUCTIONS = 64
        private const val V1_CONFIG_BITS = 0b11111L // priority fee (bits 0+1), CU limit, loaded data size, heap size

        /** SIMD-0385: version byte 0x81, fixed-width fields (little-endian), config in the header, no lookup tables. */
        private fun parseV1(r: Reader): ParsedMessage {
            val numRequired = r.u8()
            val numReadonlySigned = r.u8()
            val numReadonlyUnsigned = r.u8()
            val mask = r.u32()
            if (mask and V1_CONFIG_BITS.inv() != 0L) malformed("unknown v1 config bits ${mask.toString(2)}")
            if (((mask and 1L) == 0L) != ((mask and 2L) == 0L)) malformed("the v1 priority fee needs both of its config bits")
            val lifetime = r.take(32)
            val ixCount = r.u8()
            val keyCount = r.u8()
            if (keyCount == 0 || keyCount > V1_MAX_ACCOUNTS) malformed("account count $keyCount")
            if (ixCount > V1_MAX_INSTRUCTIONS) malformed("instruction count $ixCount")
            val keys = ArrayList<ByteArray>(keyCount)
            val seen = HashSet<String>()
            repeat(keyCount) {
                val key = r.take(32)
                if (!seen.add(hex(key))) malformed("duplicate account key")
                keys.add(key)
            }
            if (numRequired < 1) malformed("no required signatures")
            if (numReadonlySigned >= numRequired) malformed("the fee payer must be writable")
            if (numRequired + numReadonlyUnsigned > keyCount) malformed("header counts exceed the account list")

            val fee = if (mask and 1L != 0L) {
                val low = r.u32().toULong()
                val high = r.u32().toULong()
                (high shl 32) or low
            } else null
            val cu = if (mask and 4L != 0L) r.u32() else null
            val loaded = if (mask and 8L != 0L) r.u32() else null
            val heap = if (mask and 16L != 0L) r.u32().also { if (it % 1024 != 0L || it < 32 * 1024 || it > 256 * 1024) malformed("heap size $it") } else null

            val headers = List(ixCount) { Triple(r.u8(), r.u8(), r.u16()) }
            val instructions = headers.map { (program, n, len) -> Instruction(program, IntArray(n) { r.u8() }, r.take(len)) }
            r.end()
            for (ix in instructions) {
                if (ix.programIdIndex == 0 || ix.programIdIndex >= keyCount) malformed("invalid program index ${ix.programIdIndex}")
                for (a in ix.accounts) if (a >= keyCount) malformed("account index $a out of range")
            }
            return ParsedMessage(V1, numRequired, numReadonlySigned, numReadonlyUnsigned, keys, lifetime, instructions, emptyList(), V1Config(fee, cu, loaded, heap))
        }

        private fun parseInner(bytes: ByteArray): ParsedMessage {
            val r = Reader(bytes)
            if (bytes.isNotEmpty() && (bytes[0].toInt() and 0xff) == 0x81) {
                r.u8()
                return parseV1(r)
            }
            var version = LEGACY
            var first = r.u8()
            if ((first and 0x80) != 0) {
                val v = first and 0x7f
                if (v != 0) malformed("unsupported message version $v")
                version = 0
                first = r.u8()
            }
            val numRequired = first
            val numReadonlySigned = r.u8()
            val numReadonlyUnsigned = r.u8()

            val keyCount = readCompactU16(r)
            if (keyCount == 0 || keyCount > 256) malformed("account count $keyCount")
            if (keyCount.toLong() * 32 > r.remaining) malformed("account list longer than the message")
            val keys = ArrayList<ByteArray>(keyCount)
            val seen = HashSet<String>()
            repeat(keyCount) {
                val key = r.take(32)
                if (!seen.add(hex(key))) malformed("duplicate account key")
                keys.add(key)
            }
            if (numRequired < 1) malformed("no required signatures")
            if (numReadonlySigned >= numRequired) malformed("the fee payer must be writable")
            if (numRequired + numReadonlyUnsigned > keyCount) malformed("header counts exceed the account list")

            val lifetime = r.take(32)

            val ixCount = readCompactU16(r)
            if (ixCount > r.remaining) malformed("instruction count longer than the message")
            val instructions = ArrayList<Instruction>(ixCount)
            repeat(ixCount) {
                val programIdIndex = r.u8()
                val accounts = readIndexes(r)
                val dataLen = readCompactU16(r)
                instructions.add(Instruction(programIdIndex, accounts, r.take(dataLen)))
            }

            val lookups = ArrayList<Lookup>()
            if (version == 0) {
                val n = readCompactU16(r)
                if (n.toLong() * 34 > r.remaining) malformed("lookup list longer than the message")
                repeat(n) { lookups.add(Lookup(r.take(32), readIndexes(r), readIndexes(r))) }
            }
            r.end()

            val totalKeys = keyCount + lookups.sumOf { it.writable.size + it.readonly.size }
            if (totalKeys > 256) malformed("too many accounts")
            for (ix in instructions) {
                if (ix.programIdIndex == 0 || ix.programIdIndex >= keyCount) malformed("invalid program index ${ix.programIdIndex}")
                for (a in ix.accounts) if (a >= totalKeys) malformed("account index $a out of range")
            }
            return ParsedMessage(version, numRequired, numReadonlySigned, numReadonlyUnsigned, keys, lifetime, instructions, lookups)
        }
    }
}
