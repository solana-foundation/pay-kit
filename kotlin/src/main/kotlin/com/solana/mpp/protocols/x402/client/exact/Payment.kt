package com.solana.mpp.protocols.x402.client.exact

import com.solana.mpp._paycore.*
import com.solana.mpp.protocols.x402.exact.*

import kotlinx.serialization.json.Json
import java.util.Base64

/**
 * x402 ``exact`` client: challenge parsing and payment-transaction building.
 *
 * Mirrors the Rust spine client
 * (``rust/crates/x402/src/client/exact/payment.rs``) and the Go client
 * (``go/protocols/x402/client/client.go``) byte-for-behavior. The Kotlin client
 * operates on the [X402AcceptsEntry] wire shape the pay_kit x402 server emits.
 *
 * The built transaction is a v0 VersionedTransaction whose fee payer is the
 * offer's ``extra.feePayer`` (the facilitator, which cosigns server-side) and
 * whose transfer authority is the client signer. Instructions are laid out
 * exactly as the verifier expects: ComputeBudget SetComputeUnitLimit(20000) +
 * SetComputeUnitPrice(1), then a transferChecked (SPL) or System transfer
 * (native SOL), then a Memo carrying ``extra.memo``.
 */

private val json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = false
    explicitNulls = false
}

/**
 * x402 protocol version stamped in the envelope. INVARIANT: 2 — the spine
 * (rust ``X402_VERSION_V2``, go ``x402Version = 2``, python) emits v2
 * envelopes. Do NOT revert to 1 (legacy ``X-PAYMENT`` shape).
 */
private const val X402_VERSION = 2

/**
 * ComputeBudget SetComputeUnitLimit. INVARIANT: 20_000 (matches rust spine +
 * go client). Do NOT change this to the MPP value (200_000).
 */
private const val COMPUTE_UNIT_LIMIT = 20_000

/** ComputeBudget SetComputeUnitPrice microlamports. */
private const val COMPUTE_UNIT_PRICE = 1L

/** Default SPL decimals when the offer omits ``extra.decimals``. */
private const val DEFAULT_DECIMALS = 6

/**
 * x402 memo byte cap. INVARIANT: 256 (rust ``MAX_MEMO_BYTES``). This is
 * NOT the MPP charge cap (566) — the x402 verifier rejects longer memos.
 */
private const val X402_MAX_MEMO_BYTES = 256

/** Solana CAIP-2 ids recognised by this client. */
private val SOLANA_MAINNET_CAIP2 = Network.SOLANA_MAINNET
private val SOLANA_DEVNET_CAIP2 = Network.SOLANA_DEVNET
private val SOLANA_CAIP2 = setOf(SOLANA_MAINNET_CAIP2, SOLANA_DEVNET_CAIP2)

// ── Challenge parsing ─────────────────────────────────────────────────────────

/**
 * Parses an x402 ``exact`` challenge from response headers and/or body.
 *
 * Decodes the standard-base64 JSON ``payment-required`` header first, then
 * falls back to a JSON body carrying ``{"accepts": [...]}``. Filters to
 * ``scheme == "exact"`` offers on the preferred network, then picks by
 * [ChallengeSelection.currencies] preference order, else the cheapest
 * ``amount``. Returns ``null`` when no supported offer matches.
 *
 * Mirrors rust ``parse_x402_challenge_with_selection`` and Python
 * ``parse_x402_challenge``.
 */
fun parseX402Challenge(
    headers: Map<String, String>,
    body: String?,
    selection: ChallengeSelection,
): X402AcceptsEntry? {
    val headerValue = lookupHeader(headers, "payment-required")
    if (headerValue != null) {
        val offer = selectFromHeader(headerValue, selection)
        if (offer != null) return offer
    }
    if (body != null) {
        val offer = selectFromBody(body, selection)
        if (offer != null) return offer
    }
    return null
}

private fun lookupHeader(headers: Map<String, String>, name: String): String? {
    val target = name.lowercase()
    return headers.entries.firstOrNull { it.key.lowercase() == target }?.value
}

private fun selectFromHeader(headerValue: String, selection: ChallengeSelection): X402AcceptsEntry? =
    try {
        val decoded = Base64.getDecoder().decode(headerValue)
        val challenge = json.decodeFromString<X402Challenge>(decoded.decodeToString())
        selectRequirement(challenge.accepts, selection)
    } catch (_: Exception) {
        null
    }

private fun selectFromBody(body: String, selection: ChallengeSelection): X402AcceptsEntry? =
    try {
        val challenge = json.decodeFromString<X402Challenge>(body)
        selectRequirement(challenge.accepts, selection)
    } catch (_: Exception) {
        null
    }

private fun isSolanaExact(offer: X402AcceptsEntry): Boolean {
    val protocol = offer.protocol
    if (protocol != null && protocol != "x402") return false
    return offer.scheme == "exact" && offer.network in SOLANA_CAIP2
}

private fun amountOf(offer: X402AcceptsEntry): Long {
    val raw = offer.amount ?: offer.maxAmountRequired
    return raw?.toLongOrNull() ?: Long.MAX_VALUE
}

private fun currencyOf(offer: X402AcceptsEntry): String = offer.asset ?: ""

private fun currenciesMatch(offered: String, accepted: String, label: String): Boolean {
    val offeredMint = resolveStablecoinMint(offered, label) ?: offered
    val acceptedMint = resolveStablecoinMint(accepted, label) ?: accepted
    return offeredMint == acceptedMint
}

private fun caip2ForSelection(network: String?): String = Network.toCaip2(network)

private fun selectRequirement(
    accepts: List<X402AcceptsEntry>,
    selection: ChallengeSelection,
): X402AcceptsEntry? {
    val preferred = caip2ForSelection(selection.network)
    val label = Network.label(preferred)

    val solana = accepts.filter { isSolanaExact(it) }
    val onPreferred = solana.filter { it.network == preferred }

    if (selection.currencies != null) {
        for (wanted in selection.currencies) {
            for (offer in onPreferred) {
                if (currenciesMatch(currencyOf(offer), wanted, label)) return offer
            }
        }
        // The client explicitly listed currencies; do not fall back (mirror rust).
        return null
    }

    val candidates = onPreferred.ifEmpty { solana }
    if (candidates.isEmpty()) return null
    return candidates.minByOrNull { amountOf(it) }
}

// ── Payment building ──────────────────────────────────────────────────────────

/**
 * Builds a signed x402 ``exact`` payment transaction for [requirement].
 *
 * Lays out the instructions the verifier expects, compiles a v0
 * VersionedTransaction with the offer's ``extra.feePayer`` as fee payer
 * (cosigned server-side) and the client [signer] as transfer authority,
 * signs the client's signature slot, and returns the [X402Envelope]
 * carrying the standard-base64 transaction. Mirrors rust ``build_payment``.
 *
 * The blockhash comes from ``requirement.extra.recentBlockhash`` when present,
 * else [rpcBlockhashProvider] (the RPC `getLatestBlockhash` fallback).
 */
fun buildPayment(
    signer: SolanaSigner,
    requirement: X402AcceptsEntry,
    rpcBlockhashProvider: () -> ByteArray,
): X402Envelope {
    val asset = requirement.asset
        ?: throw IllegalArgumentException("x402 offer is missing `asset`")
    val payTo = requirement.payTo
        ?: throw IllegalArgumentException("x402 offer is missing `payTo`")
    val amountRaw = requirement.amount ?: requirement.maxAmountRequired
    val amount = amountRaw?.toLongOrNull()
        ?: throw IllegalArgumentException("x402 offer has an invalid amount: $amountRaw")

    val extra = requirement.extra
    val feePayerStr = extra?.feePayer
    val feePayerKey = if (feePayerStr != null) PublicKey.fromBase58(feePayerStr) else PublicKey(signer.publicKeyBytes)

    val instructions = mutableListOf<Instruction>()
    instructions.add(Instructions.setComputeUnitLimit(COMPUTE_UNIT_LIMIT))
    instructions.add(Instructions.setComputeUnitPrice(COMPUTE_UNIT_PRICE))

    val signerKey = PublicKey(signer.publicKeyBytes)
    val recipientKey = PublicKey.fromBase58(payTo)

    val isNativeSol = asset.uppercase() == "SOL" || asset == "11111111111111111111111111111111"
    if (isNativeSol) {
        instructions.add(Instructions.systemTransfer(signerKey.toBase58(), recipientKey.toBase58(), amount))
    } else {
        val tokenProgramStr = extra?.tokenProgram
            ?: throw IllegalArgumentException("x402 SPL offer is missing `extra.tokenProgram`")
        val decimals = extra.decimals ?: DEFAULT_DECIMALS
        val tokenProgramKey = PublicKey.fromBase58(tokenProgramStr)
        val mintKey = PublicKey.fromBase58(asset)
        val sourceAta = Pda.associatedTokenAddress(signerKey, mintKey, tokenProgramKey)
        val destAta = Pda.associatedTokenAddress(recipientKey, mintKey, tokenProgramKey)
        instructions.add(
            Instructions.transferChecked(
                tokenProgram = tokenProgramStr,
                source = sourceAta.toBase58(),
                mint = mintKey.toBase58(),
                destination = destAta.toBase58(),
                authority = signerKey.toBase58(),
                amount = amount,
                decimals = decimals,
            )
        )
    }

    val memo = extra?.memo
    if (memo != null) {
        // x402 caps the memo at 256 bytes (rust MAX_MEMO_BYTES), tighter than
        // the MPP 566 byte cap that Instructions.memo enforces. Check here so
        // an over-long x402 memo fails fast rather than producing a tx the
        // verifier rejects.
        val memoBytes = memo.encodeToByteArray().size
        require(memoBytes <= X402_MAX_MEMO_BYTES) {
            "extra.memo exceeds maximum $X402_MAX_MEMO_BYTES bytes (got $memoBytes)"
        }
        instructions.add(Instructions.memo(memo))
    }

    val recentBlockhash: ByteArray = if (extra?.recentBlockhash != null) {
        Base58.decode(extra.recentBlockhash)
    } else {
        rpcBlockhashProvider()
    }
    require(recentBlockhash.size == 32) { "blockhash must be 32 bytes" }

    val v0Msg = Transaction.buildV0Message(feePayerKey, recentBlockhash, instructions)
    val msgBytes = v0Msg.serialize()
    val numSigners = v0Msg.header.numRequiredSignatures
    val signatures = MutableList<ByteArray?>(numSigners) { null }

    val sig = signer.sign(msgBytes)
    val signerIndex = v0Msg.accountKeys.indexOfFirst { it.bytes.contentEquals(signerKey.bytes) }
    if (signerIndex < 0) throw IllegalArgumentException("signer not found in transaction accounts")
    signatures[signerIndex] = sig

    val txBytes = Transaction.serializeV0Transaction(v0Msg, signatures)
    val encoded = Base64.getEncoder().encodeToString(txBytes)

    return X402Envelope(
        x402Version = X402_VERSION,
        accepted = requirement,
        payload = X402PayloadField(transaction = encoded),
    )
}

/**
 * Builds the standard-base64 ``Payment-Signature`` header value.
 *
 * Wraps [buildPayment] and standard-base64-encodes the [X402Envelope] JSON.
 * Mirrors rust ``build_payment_header`` and Python ``build_payment_header``.
 *
 * Envelope encoding uses STANDARD base64 (not base64url). Header name is
 * ``Payment-Signature``.
 */
fun buildPaymentHeader(
    signer: SolanaSigner,
    requirement: X402AcceptsEntry,
    rpcBlockhashProvider: () -> ByteArray,
): String {
    val envelope = buildPayment(signer, requirement, rpcBlockhashProvider)
    val payload = json.encodeToString(X402Envelope.serializer(), envelope)
    return Base64.getEncoder().encodeToString(payload.encodeToByteArray())
}
