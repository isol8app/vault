package app.isol8.vault.core

import java.math.BigInteger

/** What the vault shows for an accepted transaction (PROTOCOL.md §6.1). */
sealed class Action {
    data class SolTransfer(val to: String, val lamports: String, val toLabel: String? = null) : Action()
    data class CreateTokenAccount(val owner: String, val mint: String, val account: String, val rentPayer: String, val mintSymbol: String? = null) : Action()
    data class TokenTransfer(
        val mint: String,
        val amount: String,
        val decimals: Int,
        val toOwner: String,
        val toAccount: String,
        val mintSymbol: String? = null,
        val toLabel: String? = null,
    ) : Action()
    data class Memo(val text: String) : Action()
    data class CreateNonceAccount(val account: String, val seed: String, val lamports: String, val authority: String) : Action()
    /** SOL moved into the vault's own wSOL account for a swap: not a send. */
    data class WrapSol(val lamports: String) : Action()
    /** The vault's own wSOL account closed back to the vault after a swap. */
    object UnwrapSol : Action()
    /** An empty token account closed, its rent back to the vault (the token program refuses if it holds tokens). */
    data class CloseTokenAccount(val account: String) : Action()
    /** SOL withdrawn from a nonce account back to the vault; withdrawing all of it closes the account. */
    data class WithdrawNonceAccount(val account: String, val lamports: String) : Action()
    /** A Jupiter route_v2 swap (docs/SWAPS.md): amounts in base units, decimals proven on chain or known offline. */
    data class Swap(
        val inMint: String,
        val inAmount: String,
        val inDecimals: Int,
        val outMint: String,
        val quotedOutAmount: String,
        val minOutAmount: String,
        val outDecimals: Int,
        val slippageBps: Int,
        val feeBps: Int,
        val feeMint: String? = null,
        val inSymbol: String? = null,
        val outSymbol: String? = null,
    ) : Action()
}

sealed class Warning {
    data class HighFee(val maxFeeLamports: String, val thresholdLamports: String) : Warning()
    data class LookalikeAddress(val address: String, val resembles: String, val label: String) : Warning()
    /** A few characters from a known address: almost always a typo. Solana addresses have no checksum. */
    data class NearMissAddress(val address: String, val resembles: String, val label: String, val differences: Int) : Warning()
    data class HighSlippage(val slippageBps: Int, val thresholdBps: Int) : Warning()
}

sealed class Decision {
    data class Accept(
        val durableNonce: Boolean,
        val nonceAccount: String?,
        val maxFeeLamports: String,
        val actions: List<Action>,
        val warnings: List<Warning>,
    ) : Decision()

    data class Decline(val reason: Int, val why: String) : Decision()
}

class VaultState(
    /** Keys this vault can sign with. */
    val heldSigners: List<ByteArray>,
    /** Entries only the user can edit, on the vault. */
    val addressBook: List<Pair<String, ByteArray>>,
    val highFeeThresholdLamports: BigInteger = Acceptance.DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS,
    /** isol8's fee owner, built into the app: swap fees may only go to its token accounts. Null: no swap fee allowed. */
    val swapFeeOwner: ByteArray? = null,
    /** Highest swap fee the vault signs, in basis points. */
    val maxSwapFeeBps: Int = Acceptance.DEFAULT_MAX_SWAP_FEE_BPS,
)

/**
 * Vault acceptance rules (PROTOCOL.md §6). Pure function, mirrors protocol/src/acceptance.ts.
 * Never throws: anything unexpected becomes a decline.
 */
object Acceptance {
    const val DECLINE_USER = 0x01
    const val DECLINE_UNSUPPORTED = 0x02
    const val DECLINE_LOOKUP_TABLES = 0x03
    const val DECLINE_UNKNOWN_SIGNER = 0x04
    const val DECLINE_MALFORMED = 0x05
    const val DECLINE_RULE = 0x06
    const val DECLINE_DEVICE_ONLINE = 0x07

    const val MAX_COMPUTE_UNITS = 1_400_000L
    val DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS: BigInteger = BigInteger.valueOf(10_000_000) // 0.01 SOL
    private val NONCE_SEED = Regex("^isol8-nonce-(0|[1-9][0-9]{0,5})$")

    /** Jupiter's swap program and the only instruction of it the vault signs (docs/SWAPS.md). */
    const val JUPITER_PROGRAM = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
    const val ROUTE_V2_DISCRIMINATOR = "bb64facc31c4af14"
    /** The same swap through Jupiter's own token accounts (multi-hop routes often come back this way). */
    const val SHARED_ACCOUNTS_ROUTE_V2_DISCRIMINATOR = "d19853937cfed8e9"
    const val WSOL_MINT = "So11111111111111111111111111111111111111112"
    /** isol8's swap fee cap: 0.5%. */
    const val DEFAULT_MAX_SWAP_FEE_BPS = 50
    /**
     * isol8's fee vault (docs/SWAPS.md, "Fees"): swap fees may only go to its token accounts.
     * Its key was generated offline and is kept cold; the server's SWAP_FEE_OWNER must match.
     */
    const val ISOL8_FEE_OWNER = "oEGXn2LVvr43XTGtdh1JZzD3e8FAutjFzyBgCa7R7iw"
    /** Swaps with more slippage than this get a warning: 3%. */
    const val HIGH_SLIPPAGE_BPS = 300
    /** Longest memo the vault shows, in bytes. */
    const val MAX_MEMO_BYTES = 256

    /** Decimals the vault knows offline, for its named mints. Other mints need an on-chain decimals check. */
    val KNOWN_DECIMALS: Map<String, Int> = mapOf(
        "So11111111111111111111111111111111111111112" to 9,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" to 6,
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" to 6,
        "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" to 6,
    )

    /** Mints the vault can name offline. Everything else is shown by address only. */
    val KNOWN_MINTS: Map<String, String> = mapOf(
        "So11111111111111111111111111111111111111112" to "wSOL",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" to "USDC",
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" to "USDT",
        "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" to "JUP",
    )

    private class DeclineException(val reason: Int, why: String) : Exception(why)

    private fun decline(reason: Int, why: String): Nothing = throw DeclineException(reason, why)

    private fun rule(ok: Boolean, why: String) {
        if (!ok) decline(DECLINE_RULE, why)
    }

    private sealed class Item {
        class Advance(val index: Int, val nonce: ByteArray) : Item()
        class SolTransfer(val to: ByteArray, val lamports: ULong) : Item()
        class CreateWithSeed(val created: ByteArray, val seed: String, val lamports: ULong) : Item()
        class InitNonce(val nonce: ByteArray) : Item()
        class CuLimit(val units: Long) : Item()
        class CuPrice(val microLamports: ULong) : Item()
        class TransferChecked(val program: ByteArray, val mint: ByteArray, val dest: ByteArray, val amount: ULong, val decimals: Int) : Item()
        class CreateAta(val program: ByteArray, val ata: ByteArray, val owner: ByteArray, val mint: ByteArray) : Item()
        class Memo(val text: String) : Item()
        class Wrap(val lamports: ULong) : Item()
        object Sync : Item()
        /** CloseAccount, rent to the vault: "unwrap" when it's the vault's own wSOL account, else a close. */
        class Close(val account: ByteArray, val wsol: Boolean) : Item()
        class WithdrawNonce(val nonce: ByteArray, val lamports: ULong) : Item()
        class Decimals(val program: ByteArray, val mint: ByteArray, val decimals: Int) : Item()
        class Swap(
            val inMint: ByteArray,
            val outMint: ByteArray,
            val inAmount: ULong,
            val quotedOut: ULong,
            val slippageBps: Int,
            val feeBps: Int,
            val feeMint: ByteArray?,
        ) : Item()
    }

    fun evaluate(request: Payload.SignTxRequest, state: VaultState): Decision = try {
        evaluateInner(request, state)
    } catch (e: DeclineException) {
        Decision.Decline(e.reason, e.message ?: "")
    } catch (e: Exception) {
        // Any unexpected failure is treated as malformed input, never as an accept.
        Decision.Decline(DECLINE_MALFORMED, e.message ?: e.javaClass.simpleName)
    }

    private fun evaluateInner(request: Payload.SignTxRequest, state: VaultState): Decision {
        val signer = request.signer
        if (state.heldSigners.none { bytesEqual(it, signer) }) decline(DECLINE_UNKNOWN_SIGNER, "the vault doesn't hold this key")

        val msg = try {
            ParsedMessage.parse(request.message)
        } catch (e: ProtocolException) {
            decline(DECLINE_MALFORMED, e.message ?: "malformed message")
        }
        if (msg.version == 0) {
            if (msg.lookups.isNotEmpty()) decline(DECLINE_LOOKUP_TABLES, "address lookup tables present")
            decline(DECLINE_RULE, "only legacy messages are accepted in version 1")
        }
        rule(msg.numRequiredSignatures == 1, "exactly one required signer (the vault) in version 1")
        rule(bytesEqual(msg.staticKeys[0], signer), "the fee payer and only signer must be the requested signer")
        // v1 (SIMD-0385) sets the compute budget in its header; ComputeBudget instructions there would be ignored no-ops.
        if (msg.version == ParsedMessage.V1 && msg.instructions.any { bytesEqual(msg.staticKeys[it.programIdIndex], Solana.COMPUTE_BUDGET_PROGRAM) }) {
            decline(DECLINE_RULE, "a v1 transaction sets its compute budget in its header, not with instructions")
        }

        fun key(i: Int) = msg.staticKeys[i]
        fun isVault(i: Int) = i == 0 // index 0 is the only signer, and equals `signer`

        val wsolAccount = Solana.associatedTokenAddress(signer, Base58.address(WSOL_MINT), Solana.TOKEN_PROGRAM)
        val items = msg.instructions.mapIndexed { index, ix -> decode(index, ix, signer, state, wsolAccount, ::key, ::isVault) }

        // ---- rules across instructions ----
        for (it in items) rule(it !is Item.Advance || it.index == 0, "AdvanceNonceAccount must be the first instruction")
        val first = items.firstOrNull()
        val durable = first is Item.Advance
        rule(items.count { it is Item.CuLimit } <= 1 && items.count { it is Item.CuPrice } <= 1, "duplicate compute budget instruction")
        val swaps = items.filterIsInstance<Item.Swap>()
        rule(swaps.size <= 1, "at most one swap per transaction")
        val swap = swaps.firstOrNull()
        val swapUsesSol = swap != null && (Base58.encode(swap.inMint) == WSOL_MINT || Base58.encode(swap.outMint) == WSOL_MINT)
        rule(swapUsesSol || items.none { it is Item.Wrap || it is Item.Sync }, "wrapping SOL only as part of a swap involving SOL")
        // Decimals come from the vault's own list or an on-chain check in this transaction, never from the hot side alone.
        fun decimalsOf(mint: ByteArray): Int {
            KNOWN_DECIMALS[Base58.encode(mint)]?.let { return it }
            val check = items.filterIsInstance<Item.Decimals>().firstOrNull { bytesEqual(it.mint, mint) }
            return check?.decimals ?: decline(DECLINE_RULE, "the swap needs a decimals check for ${Base58.encode(mint)}")
        }

        val signerB58 = Base58.encode(signer)
        val actions = ArrayList<Action>()
        val createdAtas = ArrayList<Item.CreateAta>()
        var i = 0
        while (i < items.size) {
            when (val item = items[i]) {
                is Item.Advance, is Item.CuLimit, is Item.CuPrice -> {}
                is Item.SolTransfer -> actions.add(Action.SolTransfer(Base58.encode(item.to), item.lamports.toString()))
                is Item.CreateWithSeed -> {
                    val next = items.getOrNull(i + 1)
                    rule(next is Item.InitNonce && bytesEqual(next.nonce, item.created), "a created account must be initialized as a nonce account right after")
                    actions.add(Action.CreateNonceAccount(Base58.encode(item.created), item.seed, item.lamports.toString(), signerB58))
                    i++ // the InitNonce is part of this action
                }
                is Item.InitNonce -> rule(false, "InitializeNonceAccount must follow CreateAccountWithSeed")
                is Item.CreateAta -> {
                    createdAtas.add(item)
                    val mint = Base58.encode(item.mint)
                    actions.add(Action.CreateTokenAccount(Base58.encode(item.owner), mint, Base58.encode(item.ata), signerB58, KNOWN_MINTS[mint]))
                }
                is Item.TransferChecked -> {
                    val named = createdAtas.firstOrNull { c -> bytesEqual(c.ata, item.dest) && bytesEqual(c.mint, item.mint) && bytesEqual(c.program, item.program) }
                    rule(named != null, "every token destination needs a CreateIdempotent naming its owner")
                    val mint = Base58.encode(item.mint)
                    actions.add(
                        Action.TokenTransfer(mint, item.amount.toString(), item.decimals, Base58.encode(named!!.owner), Base58.encode(item.dest), KNOWN_MINTS[mint]),
                    )
                }
                is Item.Memo -> actions.add(Action.Memo(item.text))
                is Item.Wrap -> actions.add(Action.WrapSol(item.lamports.toString()))
                // In a swap, closing the vault's wSOL account is the unwrap after it; anywhere else it's a plain close.
                is Item.WithdrawNonce -> actions.add(Action.WithdrawNonceAccount(Base58.encode(item.nonce), item.lamports.toString()))
                // Closing the vault's own wSOL account is an unwrap: its wrapped SOL and rent come back as SOL.
                is Item.Close -> actions.add(if (item.wsol) Action.UnwrapSol else Action.CloseTokenAccount(Base58.encode(item.account)))
                is Item.Sync, is Item.Decimals -> {}
                is Item.Swap -> {
                    val minOut = item.quotedOut.toBigInteger().multiply(BigInteger.valueOf(10_000L - item.slippageBps))
                        .add(BigInteger.valueOf(9_999)).divide(BigInteger.valueOf(10_000))
                    val inMint = Base58.encode(item.inMint)
                    val outMint = Base58.encode(item.outMint)
                    actions.add(
                        Action.Swap(
                            inMint, item.inAmount.toString(), decimalsOf(item.inMint),
                            outMint, item.quotedOut.toString(), minOut.toString(), decimalsOf(item.outMint),
                            item.slippageBps, item.feeBps, item.feeMint?.let(Base58::encode), KNOWN_MINTS[inMint], KNOWN_MINTS[outMint],
                        ),
                    )
                }
            }
            i++
        }

        // One send per transaction, so a second can't hide below the one the user asked for.
        rule(actions.count { it is Action.SolTransfer || it is Action.TokenTransfer } <= 1, "at most one send per transaction")
        // A token account for someone else costs rent that never comes back: only for this transaction's send.
        for (c in createdAtas) {
            rule(
                bytesEqual(c.owner, signer) || items.any { it is Item.TransferChecked && bytesEqual(it.dest, c.ata) },
                "a token account for someone else may only be opened for this transaction's send",
            )
        }

        // ---- fee and warnings ----
        val limit = items.filterIsInstance<Item.CuLimit>().firstOrNull()
        val price = items.filterIsInstance<Item.CuPrice>().firstOrNull()
        val units = BigInteger.valueOf(minOf(limit?.units ?: MAX_COMPUTE_UNITS, MAX_COMPUTE_UNITS))
        val micro = price?.microLamports?.toBigInteger() ?: BigInteger.ZERO
        // v1 states its priority fee as a total in lamports; legacy as a price per compute unit.
        val priority = if (msg.version == ParsedMessage.V1) (msg.config?.priorityFeeLamports ?: 0UL).toBigInteger()
        else units.multiply(micro).add(BigInteger.valueOf(999_999)).divide(BigInteger.valueOf(1_000_000))
        val maxFee = BigInteger.valueOf(Solana.LAMPORTS_PER_SIGNATURE * msg.numRequiredSignatures).add(priority)

        val warnings = ArrayList<Warning>()
        if (swap != null && swap.slippageBps > HIGH_SLIPPAGE_BPS) warnings.add(Warning.HighSlippage(swap.slippageBps, HIGH_SLIPPAGE_BPS))
        if (maxFee > state.highFeeThresholdLamports) warnings.add(Warning.HighFee(maxFee.toString(), state.highFeeThresholdLamports.toString()))

        val known = state.heldSigners.map { "this vault" to Base58.encode(it) } + state.addressBook.map { (label, addr) -> label to Base58.encode(addr) }
        fun checkDestination(address: String): String? {
            known.firstOrNull { it.second == address }?.let { return it.first }
            for ((label, addr) in known) {
                // A few edits away is a typo (whatever the ends); same ends with a different middle is poisoning.
                val differences = editDistance(address, addr, NEAR_MISS_EDITS)
                if (differences <= NEAR_MISS_EDITS) warnings.add(Warning.NearMissAddress(address, addr, label, differences))
                else if (looksAlike(address, addr)) warnings.add(Warning.LookalikeAddress(address, addr, label))
            }
            return null
        }
        val labelled = actions.map { a ->
            when (a) {
                is Action.SolTransfer -> a.copy(toLabel = checkDestination(a.to))
                is Action.TokenTransfer -> a.copy(toLabel = checkDestination(a.toOwner))
                else -> a
            }
        }

        val nonceAccount = (first as? Item.Advance)?.let { Base58.encode(it.nonce) }
        return Decision.Accept(durable, nonceAccount, maxFee.toString(), labelled, warnings)
    }

    /** Unicode Cc, Cf, Zl and Zp: the characters a memo may not contain (mirrors acceptance.ts). */
    private fun Int.isHiddenOrControl(): Boolean = when (Character.getType(this).toByte()) {
        Character.CONTROL, Character.FORMAT, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR -> true
        else -> false
    }

    private fun isTokenProgram(p: ByteArray) = bytesEqual(p, Solana.TOKEN_PROGRAM) || bytesEqual(p, Solana.TOKEN_2022_PROGRAM)

    private fun decode(
        index: Int,
        ix: ParsedMessage.Instruction,
        signer: ByteArray,
        state: VaultState,
        wsolAccount: ByteArray,
        key: (Int) -> ByteArray,
        isVault: (Int) -> Boolean,
    ): Item {
        val program = key(ix.programIdIndex)
        val acc = ix.accounts
        val r = Reader(ix.data)
        fun <T : Item> done(item: T): T {
            r.end()
            return item
        }

        if (bytesEqual(program, Solana.SYSTEM_PROGRAM)) {
            if (ix.data.size < 4) decline(DECLINE_MALFORMED, "system instruction too short")
            return when (val kind = r.u32()) {
                2L -> {
                    rule(acc.size == 2 && isVault(acc[0]), "SOL transfers must come from the vault")
                    val to = key(acc[1])
                    // Into the vault's own wSOL account: wrapping SOL for a swap, not a send.
                    if (bytesEqual(to, wsolAccount)) done(Item.Wrap(r.u64())) else done(Item.SolTransfer(to, r.u64()))
                }
                5L -> {
                    // WithdrawNonceAccount: only back to the vault, on the vault's authority. Withdrawing everything closes it.
                    rule(acc.size == 5, "WithdrawNonceAccount needs 5 accounts")
                    rule(
                        bytesEqual(key(acc[2]), Solana.SYSVAR_RECENT_BLOCKHASHES) && bytesEqual(key(acc[3]), Solana.SYSVAR_RENT),
                        "WithdrawNonceAccount must use the sysvars",
                    )
                    rule(isVault(acc[1]) && isVault(acc[4]), "a nonce account may only be withdrawn to the vault, by the vault")
                    done(Item.WithdrawNonce(key(acc[0]), r.u64()))
                }
                4L -> {
                    rule(acc.size == 3, "AdvanceNonceAccount needs 3 accounts")
                    rule(bytesEqual(key(acc[1]), Solana.SYSVAR_RECENT_BLOCKHASHES), "AdvanceNonceAccount must use the RecentBlockhashes sysvar")
                    rule(isVault(acc[2]), "the nonce authority must be the vault")
                    done(Item.Advance(index, key(acc[0])))
                }
                3L -> {
                    val base = r.take(32)
                    val seedLen = r.u64()
                    rule(seedLen <= 32UL, "seed longer than 32 bytes")
                    val seed = strictUtf8(r.take(seedLen.toInt()))
                    val lamports = r.u64()
                    val space = r.u64()
                    val owner = r.take(32)
                    rule(acc.size == 2 || acc.size == 3, "CreateAccountWithSeed needs 2 or 3 accounts")
                    rule(isVault(acc[0]) && bytesEqual(base, signer) && (acc.size == 2 || isVault(acc[2])), "the nonce account must be funded and based on the vault")
                    rule(bytesEqual(owner, Solana.SYSTEM_PROGRAM) && space == Solana.NONCE_ACCOUNT_SPACE.toULong(), "accounts may only be created as nonce accounts")
                    rule(NONCE_SEED.matches(seed), "nonce account seeds must be isol8-nonce-<n>")
                    val created = key(acc[1])
                    rule(bytesEqual(created, Solana.createWithSeed(signer, seed, Solana.SYSTEM_PROGRAM)), "created address doesn't match the seed")
                    done(Item.CreateWithSeed(created, seed, lamports))
                }
                6L -> {
                    val authority = r.take(32)
                    rule(acc.size == 3, "InitializeNonceAccount needs 3 accounts")
                    rule(
                        bytesEqual(key(acc[1]), Solana.SYSVAR_RECENT_BLOCKHASHES) && bytesEqual(key(acc[2]), Solana.SYSVAR_RENT),
                        "InitializeNonceAccount must use the sysvars",
                    )
                    rule(bytesEqual(authority, signer), "new nonce accounts must have the vault as authority")
                    done(Item.InitNonce(key(acc[0])))
                }
                else -> decline(DECLINE_UNSUPPORTED, "unsupported System instruction $kind")
            }
        }

        if (bytesEqual(program, Solana.COMPUTE_BUDGET_PROGRAM)) {
            rule(acc.isEmpty(), "compute budget instructions take no accounts")
            return when (val kind = r.u8()) {
                2 -> done(Item.CuLimit(r.u32()))
                3 -> done(Item.CuPrice(r.u64()))
                else -> decline(DECLINE_UNSUPPORTED, "unsupported compute budget instruction $kind")
            }
        }

        if (bytesEqual(program, Solana.TOKEN_PROGRAM) || bytesEqual(program, Solana.TOKEN_2022_PROGRAM)) {
            val kind = r.u8()
            if (kind == 17) {
                // SyncNative, after wrapping SOL into the vault's own wSOL account.
                rule(bytesEqual(program, Solana.TOKEN_PROGRAM) && acc.size == 1 && bytesEqual(key(acc[0]), wsolAccount), "SyncNative only on the vault's own wSOL account")
                return done(Item.Sync)
            }
            if (kind == 9) {
                // CloseAccount: the rent (and, for wSOL, the wrapped SOL) goes back to the vault, on the vault's authority.
                // The vault can't see balances offline; it doesn't need to: the token program refuses to close an account
                // that still holds tokens, so the worst a lying dashboard can do is make the transaction fail.
                rule(acc.size == 3, "CloseAccount needs 3 accounts")
                rule(isVault(acc[1]) && isVault(acc[2]), "a closed token account must pay back to the vault, by the vault")
                val account = key(acc[0])
                return done(Item.Close(account, bytesEqual(program, Solana.TOKEN_PROGRAM) && bytesEqual(account, wsolAccount)))
            }
            if (kind != 12) decline(DECLINE_UNSUPPORTED, if (kind == 3) "plain token Transfer is not supported" else "unsupported token instruction $kind")
            rule(acc.size == 4, "TransferChecked with extra accounts (multisig or transfer hooks) is not supported")
            rule(isVault(acc[3]), "token transfers must be authorized by the vault")
            val mint = key(acc[1])
            rule(bytesEqual(key(acc[0]), Solana.associatedTokenAddress(signer, mint, program)), "tokens must come from the vault's own token account")
            val amount = r.u64()
            val decimals = r.u8()
            // Zero tokens from the vault's account to itself: an on-chain check that `decimals` is right (it fails otherwise).
            if (amount == 0UL && acc[2] == acc[0]) return done(Item.Decimals(program, mint, decimals))
            return done(Item.TransferChecked(program, mint, key(acc[2]), amount, decimals))
        }

        if (bytesEqual(program, Solana.ASSOCIATED_TOKEN_PROGRAM)) {
            val kind = if (ix.data.isEmpty()) 0 else r.u8()
            if (kind != 0 && kind != 1) decline(DECLINE_UNSUPPORTED, "unsupported associated token instruction $kind")
            rule(acc.size == 6, "associated token account creation needs 6 accounts")
            rule(isVault(acc[0]), "the vault must pay for token account creation")
            val ata = key(acc[1])
            val owner = key(acc[2])
            val mint = key(acc[3])
            val tokenProgram = key(acc[5])
            rule(bytesEqual(key(acc[4]), Solana.SYSTEM_PROGRAM), "associated token account creation must use the System program")
            rule(bytesEqual(tokenProgram, Solana.TOKEN_PROGRAM) || bytesEqual(tokenProgram, Solana.TOKEN_2022_PROGRAM), "unknown token program")
            rule(bytesEqual(ata, Solana.associatedTokenAddress(owner, mint, tokenProgram)), "token account address doesn't match its owner and mint")
            return done(Item.CreateAta(tokenProgram, ata, owner, mint))
        }

        if (bytesEqual(program, Solana.MEMO_PROGRAM)) {
            rule(acc.isEmpty(), "memos with signer accounts are not supported")
            val text = try {
                strictUtf8(ix.data)
            } catch (e: ProtocolException) {
                decline(DECLINE_RULE, "memo is not valid UTF-8")
            }
            // Line breaks, direction overrides or invisible characters could make a memo look like more of the review screen.
            rule(ix.data.size <= MAX_MEMO_BYTES, "memos longer than $MAX_MEMO_BYTES bytes are not supported")
            rule(text.codePoints().noneMatch { it.isHiddenOrControl() }, "memos with control or formatting characters are not supported")
            return Item.Memo(text)
        }

        if (Base58.encode(program) == JUPITER_PROGRAM) {
            // route_v2 and shared_accounts_route_v2 (Jupiter's IDL). Same arguments, except shared starts with an id byte;
            // shared moves the tokens through Jupiter's program-authority accounts, which are pinned below.
            val discriminator = if (ix.data.size >= 8) hex(ix.data.copyOfRange(0, 8)) else ""
            val shared = discriminator == SHARED_ACCOUNTS_ROUTE_V2_DISCRIMINATOR
            rule(shared || discriminator == ROUTE_V2_DISCRIMINATOR, "the only Jupiter instructions the vault signs are route_v2 and shared_accounts_route_v2")
            rule(ix.data.size >= (if (shared) 35 else 34), "Jupiter swap data is too short")
            r.take(8)
            val id = if (shared) r.u8() else 0
            val inAmount = r.u64()
            val quotedOut = r.u64()
            val slippageBps = r.u16()
            val feeBps = r.u16()
            val positiveSlippageBps = r.u16()
            // The route plan follows; the vault doesn't need it (Jupiter enforces the minimum on chain).
            // Slots: route_v2 = authority 0, source 1, destination 2, mints 3/4, token programs 5/6, optional
            // destination override 7, then fee account 10. Shared = program authority 0, authority 1, source 2,
            // Jupiter's source and destination 3/4, destination 5, mints 6/7, token programs 8/9, then fee account 12.
            val vaultSlot = if (shared) 1 else 0
            val sourceSlot = if (shared) 2 else 1
            val destSlot = if (shared) 5 else 2
            val mintSlot = if (shared) 6 else 3
            val programSlot = if (shared) 8 else 5
            val feeSlot = if (shared) 12 else 10
            val name = if (shared) "shared_accounts_route_v2" else "route_v2"
            rule(acc.size >= (if (feeBps > 0) feeSlot + 1 else feeSlot), "$name has too few accounts")
            rule(isVault(acc[vaultSlot]), "the swap must be authorized by the vault")
            val inMint = key(acc[mintSlot])
            val outMint = key(acc[mintSlot + 1])
            val inProgram = key(acc[programSlot])
            val outProgram = key(acc[programSlot + 1])
            rule(isTokenProgram(inProgram) && isTokenProgram(outProgram), "unknown token program in the swap")
            rule(!bytesEqual(inMint, outMint), "a swap needs two different tokens")
            rule(bytesEqual(key(acc[sourceSlot]), Solana.associatedTokenAddress(signer, inMint, inProgram)), "a swap must spend from the vault's own token account")
            rule(bytesEqual(key(acc[destSlot]), Solana.associatedTokenAddress(signer, outMint, outProgram)), "a swap must pay into the vault's own token account")
            if (shared) {
                val authority = Solana.findProgramAddress(listOf("authority".toByteArray(Charsets.US_ASCII), byteArrayOf(id.toByte())), Base58.decode(JUPITER_PROGRAM))
                rule(bytesEqual(key(acc[0]), authority), "shared_accounts_route_v2 must use Jupiter's program authority for its id")
                rule(
                    bytesEqual(key(acc[3]), Solana.associatedTokenAddress(authority, inMint, inProgram)) &&
                        bytesEqual(key(acc[4]), Solana.associatedTokenAddress(authority, outMint, outProgram)),
                    "shared_accounts_route_v2 must route through Jupiter's own token accounts",
                )
            } else {
                // An account here would receive the output instead of the vault's own token account.
                rule(Base58.encode(key(acc[7])) == JUPITER_PROGRAM, "a swap must not redirect its output to another account")
            }
            rule(positiveSlippageBps == 0, "a swap must not give away positive slippage")
            rule(inAmount > 0UL && quotedOut > 0UL, "a swap needs amounts above zero")
            rule(slippageBps < 10_000, "slippage must be below 100%")
            var feeMint: ByteArray? = null
            if (feeBps > 0) {
                rule(feeBps <= state.maxSwapFeeBps, "the swap fee is above the vault's limit of ${state.maxSwapFeeBps} basis points")
                val owner = state.swapFeeOwner ?: decline(DECLINE_RULE, "this vault doesn't allow swap fees")
                val feeAccount = key(acc[feeSlot])
                feeMint = when {
                    bytesEqual(feeAccount, Solana.associatedTokenAddress(owner, inMint, inProgram)) -> inMint
                    bytesEqual(feeAccount, Solana.associatedTokenAddress(owner, outMint, outProgram)) -> outMint
                    else -> decline(DECLINE_RULE, "the swap fee must go to isol8's fee account for one of the two tokens")
                }
            }
            return Item.Swap(inMint, outMint, inAmount, quotedOut, slippageBps, feeBps, feeMint)
        }

        decline(DECLINE_UNSUPPORTED, "unknown program ${Base58.encode(program)}")
    }

    /**
     * Up to this many character edits from a known address is a near miss. Unrelated addresses differ in about 43 of
     * 44 characters, so this only happens through a typo, a bad edit or a deliberate lookalike: never by chance.
     */
    const val NEAR_MISS_EDITS = 4

    /** Levenshtein distance (changed, missing or extra characters), or limit + 1 once it's known to exceed limit. */
    fun editDistance(a: String, b: String, limit: Int): Int {
        if (kotlin.math.abs(a.length - b.length) > limit) return limit + 1
        var prev = IntArray(b.length + 1) { it }
        for (i in 1..a.length) {
            val cur = IntArray(b.length + 1)
            cur[0] = i
            var rowMin = i
            for (j in 1..b.length) {
                cur[j] = minOf(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + if (a[i - 1] == b[j - 1]) 0 else 1)
                rowMin = minOf(rowMin, cur[j])
            }
            if (rowMin > limit) return limit + 1
            prev = cur
        }
        return prev[b.length]
    }

    /** Address poisoning: different addresses whose first 4 and last 4 Base58 characters match. */
    fun looksAlike(a: String, b: String): Boolean = a != b && a.take(4) == b.take(4) && a.takeLast(4) == b.takeLast(4)
}
