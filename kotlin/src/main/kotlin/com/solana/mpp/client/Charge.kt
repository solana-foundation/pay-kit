package com.solana.mpp.client

import com.solana.mpp.protocol.*
import com.solana.mpp.crypto.*

import java.util.Base64

/** Builds a signed Solana transaction for a decoded MPP charge request. */
fun interface ChargeTransactionProvider {
    /** Returns the signed base64 transaction for the provided charge request. */
    fun buildTransaction(request: ChargeRequest): String
}

/**
 * Creates MPP Authorization credentials from Solana charge challenges.
 *
 * This is the simplest entry point: callers inject a
 * [ChargeTransactionProvider] that owns the wallet integration. For an
 * out-of-the-box client that signs locally via Ed25519 use
 * [Charge.buildCredentialHeader].
 */
class ChargeCredentialBuilder(private val transactionProvider: ChargeTransactionProvider) {
    /** Builds an `Authorization: Payment ...` header for a Solana charge challenge. */
    fun authorizationHeader(challenge: PaymentChallenge): String {
        challenge.requireSolanaCharge()

        val transaction = transactionProvider.buildTransaction(challenge.chargeRequest())
        return MppHeaders.formatAuthorization(
            PaymentCredential(
                challenge = challenge.echo(),
                payload = CredentialPayload.transaction(transaction),
            )
        )
    }
}

/**
 * Provides recent blockhashes to the charge builder. The interop adapter
 * supplies one that proxies a JSON-RPC `getLatestBlockhash` call. Tests
 * pin a fixed blockhash for determinism.
 */
fun interface BlockhashProvider {
    /** Returns 32 byte recent blockhash. */
    fun fetchRecentBlockhash(): ByteArray
}

/** Full charge transaction build pipeline. Mirrors the Rust spine. */
object Charge {
    private const val MAX_SPLITS = 8
    private const val DEFAULT_COMPUTE_UNIT_LIMIT = 200_000
    private const val DEFAULT_COMPUTE_UNIT_PRICE = 1L

    /**
     * Builds and signs a Solana charge transaction. Returns the standard
     * base64-encoded wire bytes (matching the Rust spine which uses
     * `base64::engine::general_purpose::STANDARD`).
     *
     * Behaviour mirrors `build_charge_transaction_with_options` at
     * `rust/src/client/charge.rs:62`:
     *
     * 1. Parse amounts, derive primary = total minus splits.
     * 2. Reject more than 8 splits or splits exceeding the total.
     * 3. Resolve mint from currency + network; SOL is native.
     * 4. Insert compute-budget prefix (price 1, limit 200_000) in that
     *    order so the wire bytes match Rust's instruction ordering.
     * 5. Build SPL or SOL instruction sequence.
     * 6. Compile to a legacy Solana message with the recent blockhash.
     * 7. Sign the message bytes with the signer's Ed25519 key. When a
     *    fee payer is set, the local signer's signature slot is
     *    populated and the fee-payer slot is left zero so the server
     *    can countersign before broadcast.
     */
    fun buildChargeTransaction(
        signer: SolanaSigner,
        request: ChargeRequest,
        blockhashProvider: BlockhashProvider,
        computeUnitLimit: Int = DEFAULT_COMPUTE_UNIT_LIMIT,
        computeUnitPrice: Long = DEFAULT_COMPUTE_UNIT_PRICE,
    ): String {
        val built = buildUnsignedChargeMessage(
            walletPublicKey = PublicKey(signer.publicKeyBytes),
            request = request,
            blockhashProvider = blockhashProvider,
            computeUnitLimit = computeUnitLimit,
            computeUnitPrice = computeUnitPrice,
        )
        val signature = signer.sign(built.messageBytes)
        val signerIndex = built.message.accountKeys.indexOfFirst {
            it.bytes.contentEquals(built.walletPublicKey.bytes)
        }
        if (signerIndex < 0) {
            throw MppException.InvalidTransaction("Signer not found in transaction accounts")
        }
        val signatures = MutableList<ByteArray?>(built.message.header.numRequiredSignatures) { null }
        signatures[signerIndex] = signature
        val txBytes = Transaction.serializeLegacyTransaction(built.message, signatures)
        return Base64.getEncoder().encodeToString(txBytes)
    }

    /**
     * Builds the unsigned transaction wire bytes for a charge request,
     * for callers that delegate signing to an external wallet (e.g.
     * Mobile Wallet Adapter). The returned bytes are the canonical legacy
     * Solana transaction wire format with zeroed signature slots; the
     * caller is responsible for handing them to the wallet, replacing
     * the slot for `walletPublicKey` with the wallet's signature, and
     * base64-encoding the result for the MPP Authorization header.
     *
     * Shares the instruction composition and message build path with
     * [buildChargeTransaction] so the unsigned wire bytes a wallet
     * receives match the bytes the local-signer path would have produced
     * before signing.
     */
    fun buildUnsignedChargeTransaction(
        walletPublicKey: PublicKey,
        request: ChargeRequest,
        blockhashProvider: BlockhashProvider,
        computeUnitLimit: Int = DEFAULT_COMPUTE_UNIT_LIMIT,
        computeUnitPrice: Long = DEFAULT_COMPUTE_UNIT_PRICE,
    ): ByteArray {
        val built = buildUnsignedChargeMessage(
            walletPublicKey = walletPublicKey,
            request = request,
            blockhashProvider = blockhashProvider,
            computeUnitLimit = computeUnitLimit,
            computeUnitPrice = computeUnitPrice,
        )
        val signatures = MutableList<ByteArray?>(built.message.header.numRequiredSignatures) { null }
        return Transaction.serializeLegacyTransaction(built.message, signatures)
    }

    /**
     * Internal carrier for the compiled message, its serialized bytes,
     * and the wallet public key so [buildChargeTransaction] and
     * [buildUnsignedChargeTransaction] share a single composition path
     * without re-deriving any wire-affecting state.
     */
    private data class UnsignedChargeMessage(
        val message: Transaction.LegacyMessage,
        val messageBytes: ByteArray,
        val walletPublicKey: PublicKey,
    )

    private fun buildUnsignedChargeMessage(
        walletPublicKey: PublicKey,
        request: ChargeRequest,
        blockhashProvider: BlockhashProvider,
        computeUnitLimit: Int,
        computeUnitPrice: Long,
    ): UnsignedChargeMessage {
        val totalAmount = request.amount.toLongOrNull()
            ?: throw MppException.InvalidTransaction("Invalid amount: ${request.amount}")
        if (totalAmount <= 0L) {
            throw MppException.InvalidTransaction("Amount must be positive: ${request.amount}")
        }
        val splits = request.methodDetails.splits ?: emptyList()
        if (splits.size > MAX_SPLITS) {
            throw MppException.InvalidTransaction("Too many splits (got ${splits.size}, max $MAX_SPLITS)")
        }
        // Reject negative split amounts up front so they cannot slip past
        // the `splitsTotal <= 0` arithmetic and reach the wire encoder as
        // a negative lamport count. `toLongOrNull` happily parses "-100"
        // into -100L, which would make splitsTotal negative and let
        // primaryAmount = totalAmount - (-100) clear the <= 0 guard; the
        // downstream `Instructions.transferChecked` / `systemTransfer`
        // require(lamports >= 0) would then throw an unchecked
        // IllegalArgumentException from deep in the stack instead of the
        // structured MppException.InvalidTransaction callers expect.
        // Use checked addition so a hostile or compromised challenge
        // cannot craft splits whose individual amounts each fit in Long
        // but whose sum wraps. `sumOf { Long }` is plain `+`, so an
        // overflow silently produces a small/negative `splitsTotal`
        // that would clear the `primaryAmount <= 0L` guard while each
        // per-split transfer still emits its huge positive amount on
        // the wire. `Math.addExact` throws ArithmeticException on
        // overflow, which we surface as a structured
        // MppException.InvalidTransaction. Mirrors the Go #101 fix.
        val splitsTotal = splits.fold(0L) { acc, split ->
            val v = split.amount.toLongOrNull()
                ?: throw MppException.InvalidTransaction("Invalid split amount: ${split.amount}")
            if (v < 0L) {
                throw MppException.InvalidTransaction("Split amount cannot be negative: ${split.amount}")
            }
            try {
                Math.addExact(acc, v)
            } catch (_: ArithmeticException) {
                throw MppException.InvalidTransaction("Splits sum overflows Long")
            }
        }
        val primaryAmount = totalAmount - splitsTotal
        if (primaryAmount <= 0L) {
            throw MppException.InvalidTransaction("Splits consume the entire amount")
        }

        val signerKey = walletPublicKey
        val recipientKey = PublicKey.fromBase58(request.recipient)
        val md = request.methodDetails
        val useFeePayer = md.feePayer == true && md.feePayerKey != null
        val feePayerKey = if (useFeePayer) PublicKey.fromBase58(md.feePayerKey ?: "") else null

        val instructions = mutableListOf<Instruction>()

        // Compute budget. Order matches Rust spine: price first, then limit.
        instructions.add(Instructions.setComputeUnitPrice(computeUnitPrice))
        instructions.add(Instructions.setComputeUnitLimit(computeUnitLimit))

        val mint = resolveStablecoinMint(request.currency, md.network)
        val hasAtaCreationSplits = splits.any { it.ataCreationRequired == true }
        if (hasAtaCreationSplits) {
            if (mint == null) {
                throw MppException.InvalidTransaction(
                    "ataCreationRequired requires an SPL token charge",
                )
            }
            // The previous `mint != request.currency` guard rejected
            // every well-known symbol (USDC/USDT/USDG/PYUSD/CASH)
            // because resolveStablecoinMint maps those symbols to the
            // mint address, so `mint` and `request.currency` necessarily
            // differ. Match the Rust/Swift/Lua spine: accept either
            // (a) a symbol that resolved to a different mint, or
            // (b) a base58 mint address passed through verbatim.
            val isSymbol = mint != request.currency
            val isPassThrough = mint == request.currency && isLikelyBase58MintAddress(mint)
            if (!isSymbol && !isPassThrough) {
                throw MppException.InvalidTransaction(
                    "ataCreationRequired requires currency to be an SPL token mint address or known symbol",
                )
            }
        }

        if (mint != null) {
            buildSplInstructions(
                instructions = instructions,
                signerKey = signerKey,
                recipientKey = recipientKey,
                mint = mint,
                currency = request.currency,
                network = md.network,
                methodDetails = md,
                primaryAmount = primaryAmount,
                externalId = request.externalId,
                splits = splits,
                feePayer = feePayerKey,
            )
        } else {
            buildSolInstructions(
                instructions = instructions,
                signerKey = signerKey,
                recipientKey = recipientKey,
                primaryAmount = primaryAmount,
                externalId = request.externalId,
                splits = splits,
            )
        }

        val recentBlockhash = if (md.recentBlockhash != null) {
            try {
                Base58.decode(md.recentBlockhash).also {
                    if (it.size != 32) {
                        throw MppException.InvalidTransaction(
                            "Invalid recentBlockhash length: ${it.size}",
                        )
                    }
                }
            } catch (e: MppException.InvalidBase58) {
                throw MppException.InvalidTransaction("Invalid recentBlockhash: ${e.message}")
            }
        } else {
            blockhashProvider.fetchRecentBlockhash().also {
                require(it.size == 32) { "blockhash provider must return 32 bytes" }
            }
        }

        val actualFeePayer = feePayerKey ?: signerKey
        val message = Transaction.buildLegacyMessage(
            feePayer = actualFeePayer,
            recentBlockhash = recentBlockhash,
            instructions = instructions,
        )

        val messageBytes = message.serialize()
        return UnsignedChargeMessage(
            message = message,
            messageBytes = messageBytes,
            walletPublicKey = walletPublicKey,
        )
    }

    /**
     * High-level entry point: parses the challenge, builds + signs the
     * Solana transaction, and returns the canonical
     * `Authorization: Payment ...` header value.
     */
    fun buildCredentialHeader(
        signer: SolanaSigner,
        challenge: PaymentChallenge,
        blockhashProvider: BlockhashProvider,
        computeUnitLimit: Int = DEFAULT_COMPUTE_UNIT_LIMIT,
        computeUnitPrice: Long = DEFAULT_COMPUTE_UNIT_PRICE,
    ): String {
        challenge.requireSolanaCharge()
        val request = challenge.chargeRequest()
        val transaction = buildChargeTransaction(
            signer = signer,
            request = request,
            blockhashProvider = blockhashProvider,
            computeUnitLimit = computeUnitLimit,
            computeUnitPrice = computeUnitPrice,
        )
        return MppHeaders.formatAuthorization(
            PaymentCredential(
                challenge = challenge.echo(),
                payload = CredentialPayload.transaction(transaction),
            ),
        )
    }

    /**
     * Resolves the default SPL token program for a currency / network.
     *
     * Token-2022 mints (PYUSD, USDG, CASH) live under the Token-2022
     * program and need a different ATA derivation than legacy SPL. The
     * challenge methodDetails.tokenProgram override always wins; this
     * helper is the fallback when the server does not pin one.
     *
     * Mirrors `rust/src/protocol/solana.rs::default_token_program_for_currency`.
     */
    fun defaultTokenProgramFor(currency: String, network: String?): String {
        val mint = resolveStablecoinMint(currency, network)
            ?: return Programs.TOKEN_PROGRAM
        return when (mint) {
            Mints.PYUSD_MAINNET,
            Mints.PYUSD_DEVNET,
            Mints.USDG_MAINNET,
            Mints.USDG_DEVNET,
            Mints.CASH_MAINNET -> Programs.TOKEN_2022_PROGRAM
            else -> Programs.TOKEN_PROGRAM
        }
    }

    /**
     * Resolves a currency identifier (symbol or mint) to a mint address.
     * Returns null for native SOL.
     *
     * Mirrors `rust/src/protocol/solana.rs::resolve_stablecoin_mint`.
     */
    fun resolveStablecoinMint(currency: String, network: String?): String? = when (currency.uppercase()) {
        "SOL" -> null
        "USDC" -> when (network) {
            "devnet" -> Mints.USDC_DEVNET
            "testnet" -> Mints.USDC_DEVNET
            else -> Mints.USDC_MAINNET
        }
        "USDT" -> Mints.USDT_MAINNET
        "USDG" -> when (network) {
            "devnet" -> Mints.USDG_DEVNET
            "testnet" -> Mints.USDG_DEVNET
            else -> Mints.USDG_MAINNET
        }
        "PYUSD" -> when (network) {
            "devnet" -> Mints.PYUSD_DEVNET
            "testnet" -> Mints.PYUSD_DEVNET
            else -> Mints.PYUSD_MAINNET
        }
        "CASH" -> Mints.CASH_MAINNET
        else -> currency
    }

    /**
     * Cheap structural check for a base58 Solana pubkey (length 32-44,
     * base58 alphabet). Lets the ataCreationRequired guard accept a
     * pass-through mint address without doing a full PublicKey decode.
     */
    private fun isLikelyBase58MintAddress(value: String): Boolean {
        if (value.length < 32 || value.length > 44) return false
        val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        return value.all { it in alphabet }
    }

    private fun buildSolInstructions(
        instructions: MutableList<Instruction>,
        signerKey: PublicKey,
        recipientKey: PublicKey,
        primaryAmount: Long,
        externalId: String?,
        splits: List<SolanaChargeSplit>,
    ) {
        instructions.add(
            Instructions.systemTransfer(signerKey.toBase58(), recipientKey.toBase58(), primaryAmount),
        )
        addMemo(instructions, externalId)
        for (split in splits) {
            val splitDest = PublicKey.fromBase58(split.recipient)
            val splitAmount = split.amount.toLongOrNull()
                ?: throw MppException.InvalidTransaction("Invalid split amount: ${split.amount}")
            instructions.add(
                Instructions.systemTransfer(signerKey.toBase58(), splitDest.toBase58(), splitAmount),
            )
            addMemo(instructions, split.memo)
        }
    }

    private fun buildSplInstructions(
        instructions: MutableList<Instruction>,
        signerKey: PublicKey,
        recipientKey: PublicKey,
        mint: String,
        currency: String,
        network: String?,
        methodDetails: SolanaChargeMethodDetails,
        primaryAmount: Long,
        externalId: String?,
        splits: List<SolanaChargeSplit>,
        feePayer: PublicKey?,
    ) {
        val mintKey = PublicKey.fromBase58(mint)
        val tokenProgram = PublicKey.fromBase58(
            methodDetails.tokenProgram ?: defaultTokenProgramFor(currency, network),
        )
        val decimals = methodDetails.decimals ?: 6
        val sourceAta = Pda.associatedTokenAddress(signerKey, mintKey, tokenProgram)
        val payer = feePayer ?: signerKey

        fun addSplTransfer(destOwner: PublicKey, amount: Long, createAta: Boolean) {
            val destAta = Pda.associatedTokenAddress(destOwner, mintKey, tokenProgram)
            if (createAta) {
                instructions.add(
                    Instructions.createAssociatedTokenAccountIdempotent(
                        payer = payer.toBase58(),
                        ata = destAta.toBase58(),
                        owner = destOwner.toBase58(),
                        mint = mintKey.toBase58(),
                        tokenProgram = tokenProgram.toBase58(),
                    ),
                )
            }
            instructions.add(
                Instructions.transferChecked(
                    tokenProgram = tokenProgram.toBase58(),
                    source = sourceAta.toBase58(),
                    mint = mintKey.toBase58(),
                    destination = destAta.toBase58(),
                    authority = signerKey.toBase58(),
                    amount = amount,
                    decimals = decimals,
                ),
            )
        }

        addSplTransfer(recipientKey, primaryAmount, createAta = false)
        addMemo(instructions, externalId)
        for (split in splits) {
            val splitDest = PublicKey.fromBase58(split.recipient)
            val splitAmount = split.amount.toLongOrNull()
                ?: throw MppException.InvalidTransaction("Invalid split amount: ${split.amount}")
            val createAta = feePayer == null || split.ataCreationRequired == true
            addSplTransfer(splitDest, splitAmount, createAta)
            addMemo(instructions, split.memo)
        }
    }

    private fun addMemo(instructions: MutableList<Instruction>, memo: String?) {
        if (memo == null) return
        instructions.add(Instructions.memo(memo))
    }
}

/** Well-known Solana stablecoin mint addresses. */
object Mints {
    const val USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    const val USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    const val USDT_MAINNET = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
    const val USDG_MAINNET = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
    const val USDG_DEVNET = "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
    const val PYUSD_MAINNET = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
    const val PYUSD_DEVNET = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
    const val CASH_MAINNET = "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"
}
