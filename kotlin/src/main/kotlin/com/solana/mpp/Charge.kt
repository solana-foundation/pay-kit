package com.solana.mpp

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
        val totalAmount = request.amount.toLongOrNull()
            ?: throw MppException.InvalidTransaction("Invalid amount: ${request.amount}")
        val splits = request.methodDetails.splits ?: emptyList()
        if (splits.size > MAX_SPLITS) {
            throw MppException.InvalidTransaction("Too many splits (got ${splits.size}, max $MAX_SPLITS)")
        }
        val splitsTotal = splits.sumOf {
            it.amount.toLongOrNull()
                ?: throw MppException.InvalidTransaction("Invalid split amount: ${it.amount}")
        }
        val primaryAmount = totalAmount - splitsTotal
        if (primaryAmount <= 0L) {
            throw MppException.InvalidTransaction("Splits consume the entire amount")
        }

        val signerKey = PublicKey(signer.publicKeyBytes)
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
            if (mint != request.currency) {
                throw MppException.InvalidTransaction(
                    "ataCreationRequired requires currency to be an SPL token mint address",
                )
            }
        }

        if (mint != null) {
            buildSplInstructions(
                instructions = instructions,
                signerKey = signerKey,
                recipientKey = recipientKey,
                mint = mint,
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
        val signature = signer.sign(messageBytes)
        val signerIndex = message.accountKeys.indexOfFirst { it.bytes.contentEquals(signerKey.bytes) }
        if (signerIndex < 0) {
            throw MppException.InvalidTransaction("Signer not found in transaction accounts")
        }
        val signatures = MutableList<ByteArray?>(message.header.numRequiredSignatures) { null }
        signatures[signerIndex] = signature

        val txBytes = Transaction.serializeLegacyTransaction(message, signatures)
        return Base64.getEncoder().encodeToString(txBytes)
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
        methodDetails: SolanaChargeMethodDetails,
        primaryAmount: Long,
        externalId: String?,
        splits: List<SolanaChargeSplit>,
        feePayer: PublicKey?,
    ) {
        val mintKey = PublicKey.fromBase58(mint)
        val tokenProgram = PublicKey.fromBase58(
            methodDetails.tokenProgram ?: Programs.TOKEN_PROGRAM,
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
