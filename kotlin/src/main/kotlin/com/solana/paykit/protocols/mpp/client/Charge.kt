package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.protocols.mpp.core.*
import com.solana.paykit.paycore.*

import java.math.BigInteger
import java.time.Instant
import java.util.Base64

/** Builds a signed Solana transaction for a decoded MPP charge request. */
fun interface ChargeTransactionProvider {
    /** Returns the signed base64 transaction for the provided charge request. */
    fun buildTransaction(request: ChargeRequest): String
}

/**
 * Resolves the owning program of an SPL mint account.
 *
 * The charge builder uses this to determine the token program for a mint when
 * the challenge omits `methodDetails.tokenProgram` (mirrors the rust client
 * `resolve_token_program`, which reads the mint account owner, and the swift
 * `resolveTokenProgram` RPC path). [JsonRpcClient] implements this against a
 * Solana `getAccountInfo` call. When no resolver is supplied the builder fails
 * closed rather than guessing the token program from a static table.
 */
fun interface MintOwnerResolver {
    /** Returns the base58 program id that owns the given mint account. */
    fun fetchMintOwner(mintBase58: String): String
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
 * Provides recent blockhashes to the charge builder. The harness adapter
 * supplies one that proxies a JSON-RPC `getLatestBlockhash` call. Tests
 * pin a fixed blockhash for determinism.
 */
fun interface BlockhashProvider {
    /** Returns 32 byte recent blockhash. */
    fun fetchRecentBlockhash(): ByteArray
}

/**
 * Client-side policy gates for what the builder is willing to sign (audit #10,
 * #26). All fields default to "no constraint" so a UI caller that reviews the
 * challenge before signing is unaffected; auto-pay callers (e.g.
 * [com.solana.paykit.client.ChargeInterceptor]) bind what may be signed against
 * the user's wallet without a human in the loop.
 *
 * Mirrors the rust `BuildChargeTransactionOptions` policy fields:
 * - [maxAmountBaseUnits] — refuse when the charge amount (base units) exceeds
 *   this cap. Equal-to-cap is allowed.
 * - [expectedNetwork] — refuse when `methodDetails.network` does not match.
 * - [allowUnknownToken2022] — opt in to signing arbitrary (non-stablecoin)
 *   Token-2022 mints, which can carry transfer hooks (default: refuse).
 *
 * Note: the always-on expired-challenge refusal is NOT an option here — it is
 * enforced unconditionally in [buildCredentialHeader] (there is no opt-out).
 */
data class ChargePolicy(
    val maxAmountBaseUnits: BigInteger? = null,
    val expectedNetwork: String? = null,
    val allowUnknownToken2022: Boolean = false,
) {
    companion object {
        /** A policy with no constraints — the builder signs whatever it gets. */
        val NONE = ChargePolicy()
    }
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
        mintOwnerResolver: MintOwnerResolver? = null,
        policy: ChargePolicy = ChargePolicy.NONE,
    ): String {
        val built = buildUnsignedChargeMessage(
            walletPublicKey = PublicKey(signer.publicKeyBytes),
            request = request,
            blockhashProvider = blockhashProvider,
            computeUnitLimit = computeUnitLimit,
            computeUnitPrice = computeUnitPrice,
            mintOwnerResolver = mintOwnerResolver,
            policy = policy,
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
        mintOwnerResolver: MintOwnerResolver? = null,
        policy: ChargePolicy = ChargePolicy.NONE,
    ): ByteArray {
        val built = buildUnsignedChargeMessage(
            walletPublicKey = walletPublicKey,
            request = request,
            blockhashProvider = blockhashProvider,
            computeUnitLimit = computeUnitLimit,
            computeUnitPrice = computeUnitPrice,
            mintOwnerResolver = mintOwnerResolver,
            policy = policy,
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
        mintOwnerResolver: MintOwnerResolver?,
        policy: ChargePolicy,
    ): UnsignedChargeMessage {
        // Base-unit amounts are u64 on the wire (Solana lamports / SPL token
        // amounts). A signed Long tops out at 2^63-1, so a legitimate amount
        // in [2^63, 2^64) would overflow `toLongOrNull` (returns null →
        // spurious "invalid amount") or, worse, parse a crafted value that
        // wraps. Parse through BigInteger and bound to the unsigned u64 range
        // so the full token space is representable without truncation. The
        // instruction encoders still take Long; values are converted only at
        // the encode boundary (see toU64Long), which preserves the exact
        // little-endian u64 bit pattern via ULong.
        val totalAmount = parseU64(request.amount)
            ?: throw MppException.InvalidTransaction("Invalid amount: ${request.amount}")
        if (totalAmount.signum() <= 0) {
            throw MppException.InvalidTransaction("Amount must be positive: ${request.amount}")
        }
        // Audit #10: opt-in max-amount cap. Auto-pay callers bind the largest
        // charge they will sign without human review; UI callers leave it null.
        // Equal-to-cap is allowed (mirrors the rust `request.amount > cap`).
        policy.maxAmountBaseUnits?.let { cap ->
            if (totalAmount > cap) {
                throw MppException.InvalidTransaction(
                    "Charge amount $totalAmount exceeds max allowed $cap",
                )
            }
        }
        // Default a missing methodDetails to an empty block, matching the rust
        // client (`charge.rs` `unwrap_or_default`): an absent methodDetails is
        // a valid charge, not an error.
        val md = request.methodDetails ?: SolanaChargeMethodDetails()
        // Audit #10: opt-in expected-network pin. Refuse when the challenge's
        // declared network does not match what the auto-pay caller expects.
        // A null `md.network` cannot satisfy a concrete expectation, so it is
        // rejected too (the caller asked us to bind a specific network).
        policy.expectedNetwork?.let { expected ->
            if (md.network != expected) {
                throw MppException.InvalidTransaction(
                    "Challenge network ${md.network ?: "<none>"} does not match expected $expected",
                )
            }
        }
        val splits = md.splits ?: emptyList()
        if (splits.size > MAX_SPLITS) {
            throw MppException.InvalidTransaction("Too many splits (got ${splits.size}, max $MAX_SPLITS)")
        }
        // Reject negative split amounts up front so they cannot slip past
        // the `splitsTotal <= 0` arithmetic and reach the wire encoder as
        // a negative lamport count. With BigInteger arithmetic the sum can
        // never silently wrap, but we still bound each split to the u64
        // range and bound the running total so the eventual per-split
        // u64 encode cannot overflow.
        var splitsTotal = BigInteger.ZERO
        for (split in splits) {
            val v = parseU64(split.amount)
                ?: throw MppException.InvalidTransaction("Invalid split amount: ${split.amount}")
            if (v.signum() < 0) {
                throw MppException.InvalidTransaction("Split amount cannot be negative: ${split.amount}")
            }
            splitsTotal = splitsTotal.add(v)
            if (splitsTotal > U64_MAX) {
                throw MppException.InvalidTransaction("Splits sum exceeds u64 range")
            }
        }
        val primaryAmount = totalAmount.subtract(splitsTotal)
        if (primaryAmount.signum() <= 0) {
            throw MppException.InvalidTransaction("Splits consume the entire amount")
        }

        val signerKey = walletPublicKey
        // Error on a missing recipient only at the point it is needed to build
        // the transfer, matching the rust client (`charge.rs` "No recipient in
        // challenge"). The wire type allows it to be absent.
        val recipient = request.recipient
            ?: throw MppException.InvalidTransaction("No recipient in challenge")
        val recipientKey = PublicKey.fromBase58(recipient)
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
            // Match the rust spine (`client/charge.rs` `if mint_str !=
            // currency { reject }`), TypeScript, and Swift: when any split
            // requires ATA creation the request `currency` MUST itself be the
            // resolved base58 mint address. A symbol that resolves to a
            // different mint is REJECTED, because a fee-sponsored server pays
            // the ATA rent and must bind the exact mint it sponsors rather
            // than trusting a symbol→mint mapping that could diverge across
            // SDKs. (The previous build accepted the symbol branch, which let
            // Kotlin construct credentials the reference servers reject.)
            if (mint != request.currency || !isLikelyBase58MintAddress(mint)) {
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
                mintOwnerResolver = mintOwnerResolver,
                allowUnknownToken2022 = policy.allowUnknownToken2022,
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
        mintOwnerResolver: MintOwnerResolver? = null,
        policy: ChargePolicy = ChargePolicy.NONE,
        now: Instant = Instant.now(),
    ): String {
        challenge.requireSolanaCharge()
        // Audit #10: ALWAYS-on expired-challenge refusal — there is no opt-out.
        // The protocol's working trust model assumes a human reviews a challenge
        // before signing; auto-pay agents break that, so we refuse to sign a
        // challenge that has already expired. A challenge with no `expires` is
        // still accepted (the spec allows omitting it; we have no anchor to
        // check against). `now` is injectable for deterministic tests.
        if (challenge.isExpired(now)) {
            throw MppException.InvalidTransaction(
                "refusing to sign expired challenge (expires=${challenge.expires})",
            )
        }
        val request = challenge.chargeRequest()
        val transaction = buildChargeTransaction(
            signer = signer,
            request = request,
            blockhashProvider = blockhashProvider,
            computeUnitLimit = computeUnitLimit,
            computeUnitPrice = computeUnitPrice,
            mintOwnerResolver = mintOwnerResolver,
            policy = policy,
        )
        return MppHeaders.formatAuthorization(
            PaymentCredential(
                challenge = challenge.echo(),
                payload = CredentialPayload.transaction(transaction),
            ),
        )
    }

    /**
     * Resolves the default SPL token program for a currency / network from the
     * static known-stablecoin table.
     *
     * Token-2022 mints (PYUSD, USDG, CASH) live under the Token-2022 program
     * and need a different ATA derivation than legacy SPL.
     *
     * WARNING: this is the static-table path only. It returns
     * [Programs.TOKEN_PROGRAM] for any mint outside the known table, which
     * silently mis-derives ATAs for an arbitrary Token-2022 mint. The charge
     * builder no longer falls back to this helper for arbitrary mints; it
     * resolves the program from the mint account owner via
     * [MintOwnerResolver] (see [resolveTokenProgram]). Kept for callers that
     * only ever pay known stablecoins and for parity testing against
     * `rust/src/protocol/solana.rs::default_token_program_for_currency`.
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
     * Resolves the SPL token program for [mint], mirroring the rust client
     * `resolve_token_program` and swift `resolveTokenProgram`:
     *
     * 1. When the challenge pins `methodDetails.tokenProgram`, validate it
     *    against {Token, Token-2022} ONLY and reject anything else.
     * 2. Otherwise, when [mint] is a known stablecoin mint, answer from the
     *    static table (no RPC needed; the owner is well-known).
     * 3. Otherwise (arbitrary mint, no pinned program) read the mint account
     *    owner via [mintOwnerResolver] and validate it against
     *    {Token, Token-2022}. Fail closed when no resolver is available rather
     *    than guessing the legacy Token program (which would mis-derive ATAs
     *    for a Token-2022 mint and bind the wrong program on the wire).
     *
     * Audit #26: whenever the resolved program is Token-2022 AND [mint] is not
     * a known stablecoin mint, REFUSE to sign unless [allowUnknownToken2022] is
     * set. Token-2022 mints can carry transfer hooks that execute arbitrary
     * code on every transfer, and a client signing an arbitrary Token-2022 mint
     * has no way to know what those hooks do. The vanilla Token program has no
     * hooks, so arbitrary Token-program mints stay first-class. The gate is on
     * the Token-2022 axis, matching the rust client.
     */
    private fun resolveTokenProgram(
        mint: String,
        methodDetails: SolanaChargeMethodDetails,
        mintOwnerResolver: MintOwnerResolver?,
        allowUnknownToken2022: Boolean,
    ): String {
        val explicit = methodDetails.tokenProgram
        if (explicit != null) {
            if (explicit != Programs.TOKEN_PROGRAM && explicit != Programs.TOKEN_2022_PROGRAM) {
                throw MppException.InvalidTransaction("Unsupported token program: $explicit")
            }
            gateUnknownToken2022(mint, explicit, allowUnknownToken2022)
            return explicit
        }
        // Known stablecoin mints carry a deterministic owner; answer from the
        // table so callers paying stablecoins do not need to wire an RPC.
        if (stablecoinSymbol(mint) != null) {
            return if (stablecoinUsesToken2022(mint)) {
                Programs.TOKEN_2022_PROGRAM
            } else {
                Programs.TOKEN_PROGRAM
            }
        }
        val resolver = mintOwnerResolver
            ?: throw MppException.InvalidTransaction(
                "methodDetails.tokenProgram omitted and no MintOwnerResolver " +
                    "was provided to resolve mint $mint",
            )
        val owner = resolver.fetchMintOwner(mint)
        if (owner != Programs.TOKEN_PROGRAM && owner != Programs.TOKEN_2022_PROGRAM) {
            throw MppException.InvalidTransaction(
                "mint $mint is owned by unsupported program $owner",
            )
        }
        gateUnknownToken2022(mint, owner, allowUnknownToken2022)
        return owner
    }

    /**
     * Refuses an unknown (non-stablecoin) Token-2022 mint unless the caller
     * opted in (audit #26). A no-op for the legacy Token program and for known
     * stablecoin mints (which we already trust). Known stablecoins are
     * recognised via [stablecoinSymbol]; their token program is well-known and
     * they carry no hostile transfer hooks.
     */
    private fun gateUnknownToken2022(
        mint: String,
        tokenProgram: String,
        allowUnknownToken2022: Boolean,
    ) {
        if (tokenProgram != Programs.TOKEN_2022_PROGRAM) return
        if (stablecoinSymbol(mint) != null) return
        if (allowUnknownToken2022) return
        throw MppException.InvalidTransaction(
            "refusing to sign unknown Token-2022 mint $mint (transfer-hook risk); " +
                "set allowUnknownToken2022 = true to opt in",
        )
    }

    /**
     * Resolves a currency identifier (symbol or mint address) to a canonical
     * mint address, or null for native SOL. Exposed here so callers that
     * hold a reference to the [Charge] object can call it without importing
     * the paycore package directly.
     *
     * Delegates to [com.solana.paykit.paycore.resolveStablecoinMint].
     */
    fun resolveStablecoinMint(currency: String, network: String?): String? =
        com.solana.paykit.paycore.resolveStablecoinMint(currency, network)

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

    /** Maximum unsigned u64, the wire upper bound for base-unit amounts. */
    private val U64_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)

    /**
     * Parses a decimal string into an unsigned u64 ([BigInteger]) base-unit
     * amount, or null when it is not a non-negative integer in [0, 2^64).
     * Signed Long would reject or wrap legitimate amounts in [2^63, 2^64).
     */
    private fun parseU64(text: String): BigInteger? {
        val value = text.toBigIntegerOrNull() ?: return null
        if (value.signum() < 0 || value > U64_MAX) return null
        return value
    }

    private fun buildSolInstructions(
        instructions: MutableList<Instruction>,
        signerKey: PublicKey,
        recipientKey: PublicKey,
        primaryAmount: BigInteger,
        externalId: String?,
        splits: List<SolanaChargeSplit>,
    ) {
        instructions.add(
            Instructions.systemTransfer(
                signerKey.toBase58(),
                recipientKey.toBase58(),
                primaryAmount,
            ),
        )
        addMemo(instructions, externalId)
        for (split in splits) {
            val splitDest = PublicKey.fromBase58(split.recipient)
            val splitAmount = parseU64(split.amount)
                ?: throw MppException.InvalidTransaction("Invalid split amount: ${split.amount}")
            instructions.add(
                Instructions.systemTransfer(
                    signerKey.toBase58(),
                    splitDest.toBase58(),
                    splitAmount,
                ),
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
        primaryAmount: BigInteger,
        externalId: String?,
        splits: List<SolanaChargeSplit>,
        feePayer: PublicKey?,
        mintOwnerResolver: MintOwnerResolver?,
        allowUnknownToken2022: Boolean,
    ) {
        val mintKey = PublicKey.fromBase58(mint)
        val tokenProgram = PublicKey.fromBase58(
            resolveTokenProgram(mint, methodDetails, mintOwnerResolver, allowUnknownToken2022),
        )
        // Audit #42: spec §7.2 marks `decimals` as conditionally required —
        // MUST be present for SPL (this branch). Defaulting a missing value to
        // 6 silently signs a wrong `transferChecked` decimals byte / wrong
        // divisor for any non-6-decimal mint, the worst failure mode for a
        // signed transaction. Error instead of guessing (mirrors the rust
        // client `ok_or(... "decimals is required for SPL")`).
        val decimals = methodDetails.decimals
            ?: throw MppException.InvalidTransaction(
                "methodDetails.decimals is required for SPL charges (spec §7.2)",
            )
        val sourceAta = Pda.associatedTokenAddress(signerKey, mintKey, tokenProgram)
        val payer = feePayer ?: signerKey

        fun addSplTransfer(destOwner: PublicKey, amount: BigInteger, createAta: Boolean) {
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
            val splitAmount = parseU64(split.amount)
                ?: throw MppException.InvalidTransaction("Invalid split amount: ${split.amount}")
            // Audit #20: create a split ATA only when the challenge explicitly
            // flags it, in BOTH client-paid and fee-sponsored modes. The prior
            // `feePayer == null || ...` auto-created an ATA for every split in
            // client-paid mode regardless of the flag, letting a hostile server
            // attach N dust splits to drain ~N×0.002 SOL of rent from the
            // client. Mirrors the rust fix (`split.ata_creation_required ==
            // Some(true)`, flag-only).
            val createAta = split.ataCreationRequired == true
            addSplTransfer(splitDest, splitAmount, createAta)
            addMemo(instructions, split.memo)
        }
    }

    private fun addMemo(instructions: MutableList<Instruction>, memo: String?) {
        if (memo == null) return
        instructions.add(Instructions.memo(memo))
    }
}
