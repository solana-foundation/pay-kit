package com.solana.paykit.protocols.x402.client.exact

import com.solana.paykit.paycore.*
import com.solana.paykit.protocols.x402.exact.*

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64

/** Maximum unsigned u64, the wire upper bound for x402 base-unit amounts. */
private val U64_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)

/**
 * Parses a decimal string into an unsigned u64 ([BigInteger]) base-unit
 * amount, or null when it is not a non-negative integer in [0, 2^64).
 *
 * Mirrors the rust spine ``build_payment`` which parses ``amount`` as a full
 * ``u64`` and the round-1 MPP fix (`Charge.parseU64`). A signed-`Long`
 * `toLongOrNull()` rejects every legitimate amount in [2^63, 2^64), so this
 * keeps the x402 client parity with the MPP charge path.
 */
private fun parseX402U64(text: String): BigInteger? {
    val value = text.toBigIntegerOrNull() ?: return null
    if (value.signum() < 0 || value > U64_MAX) return null
    return value
}

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

/**
 * Nonce length in bytes when the offer carries no ``extra.memo``. INVARIANT:
 * 16 (rust spine ``let mut nonce = [0u8; 16]``). Hex-encoding 16 bytes yields
 * a 32-character (32-byte UTF-8) Memo, well under [X402_MAX_MEMO_BYTES].
 */
private const val X402_NONCE_BYTES = 16

/**
 * Process-wide secure RNG used to mint the per-payment uniqueness nonce when
 * the offer omits ``extra.memo``. [SecureRandom] is thread-safe.
 */
private val secureRandom = SecureRandom()

/**
 * Default nonce source: 16 secure-random bytes, hex-encoded to a 32-character
 * UTF-8 string. Mirrors the rust spine ``memo_instruction`` nonce branch
 * (``getrandom::fill(&mut [0u8;16])`` then ``{byte:02x}``). Injectable through
 * [buildPayment]'s ``nonceProvider`` parameter so golden-vector / deterministic
 * tests can pin a fixed value.
 */
private fun defaultMemoNonce(): String {
    val nonce = ByteArray(X402_NONCE_BYTES)
    secureRandom.nextBytes(nonce)
    return nonce.joinToString("") { "%02x".format(it) }
}

/** Solana CAIP-2 ids recognised by this client. */
private val SOLANA_MAINNET_CAIP2 = Network.SOLANA_MAINNET
private val SOLANA_DEVNET_CAIP2 = Network.SOLANA_DEVNET
private val SOLANA_TESTNET_CAIP2 = Network.SOLANA_TESTNET
private val SOLANA_CAIP2 = setOf(SOLANA_MAINNET_CAIP2, SOLANA_DEVNET_CAIP2, SOLANA_TESTNET_CAIP2)

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
        selectFromJsonText(Base64.getDecoder().decode(headerValue).decodeToString(), selection)
    } catch (_: Exception) {
        null
    }

private fun selectFromBody(body: String, selection: ChallengeSelection): X402AcceptsEntry? =
    selectFromJsonText(body, selection)

/**
 * Decodes the challenge JSON and selects an offer, attaching each offer's
 * verbatim wire object as [X402AcceptsEntry.raw] so the selected entry can be
 * echoed back unchanged (the rust verifier structurally compares the echoed
 * `accepted` against its offered options).
 */
private fun selectFromJsonText(text: String, selection: ChallengeSelection): X402AcceptsEntry? =
    try {
        val accepts = json.parseToJsonElement(text).jsonObject["accepts"]?.jsonArray
        if (accepts == null) {
            null
        } else {
            val entries = accepts.map { element ->
                json.decodeFromJsonElement(X402AcceptsEntry.serializer(), element).copy(raw = element)
            }
            selectRequirement(entries, selection)
        }
    } catch (_: Exception) {
        null
    }

private fun isSolanaExact(offer: X402AcceptsEntry): Boolean {
    val protocol = offer.protocol
    if (protocol != null && protocol != "x402") return false
    return offer.scheme == "exact" && offer.network in SOLANA_CAIP2
}

private fun amountOf(offer: X402AcceptsEntry): BigInteger {
    val raw = offer.amount ?: offer.maxAmountRequired
    // Parse as a full unsigned u64 so amounts in [2^63, 2^64) are ranked
    // correctly. Invalid or unparseable values sort last (U64_MAX fallback),
    // mirroring the rust spine which ranks on the full u64 range.
    return raw?.let { parseX402U64(it) } ?: U64_MAX
}

private fun currencyOf(offer: X402AcceptsEntry): String = offer.effectiveAsset ?: ""

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
    nonceProvider: () -> String = ::defaultMemoNonce,
): X402Envelope {
    val asset = requirement.effectiveAsset
        ?: throw IllegalArgumentException("x402 offer is missing `asset`")
    val payTo = requirement.effectivePayTo
        ?: throw IllegalArgumentException("x402 offer is missing `payTo`")
    val amountRaw = requirement.amount ?: requirement.maxAmountRequired
    val amount = amountRaw?.let { parseX402U64(it) }
        ?: throw IllegalArgumentException("x402 offer has an invalid amount: $amountRaw")

    val extra = requirement.extra
    // Honor the top-level managed-fee-payer offer shape (feePayer toggle +
    // feePayerKey), not just the nested extra.feePayer alias, matching the
    // rust spine parser. effectiveFeePayerKey returns null when no managed
    // fee payer is requested, in which case the signer pays its own fee.
    val feePayerStr = requirement.effectiveFeePayerKey
    val feePayerKey = if (feePayerStr != null) PublicKey.fromBase58(feePayerStr) else PublicKey(signer.publicKeyBytes)

    val instructions = mutableListOf<Instruction>()
    instructions.add(Instructions.setComputeUnitLimit(COMPUTE_UNIT_LIMIT))
    instructions.add(Instructions.setComputeUnitPrice(COMPUTE_UNIT_PRICE))

    val signerKey = PublicKey(signer.publicKeyBytes)
    val recipientKey = PublicKey.fromBase58(payTo)

    // Native SOL is ONLY the case-insensitive symbol "SOL", matching the rust
    // spine `is_native_sol` (types.rs:86-88, `currency.eq_ignore_ascii_case
    // ("SOL")`). Any other value (including the System Program pubkey string
    // "11111111111111111111111111111111") passes through as an SPL mint via
    // resolve_mint, so it must NOT be treated as native SOL here. Treating the
    // System Program string as native SOL would build a System transfer where
    // rust builds an SPL transferChecked, diverging on the canonical wire.
    val isNativeSol = asset.uppercase() == "SOL"
    if (isNativeSol) {
        // BigInteger overload encodes the full unsigned u64 range; the Long
        // overload would truncate amounts in [2^63, 2^64).
        instructions.add(Instructions.systemTransfer(signerKey.toBase58(), recipientKey.toBase58(), amount))
    } else {
        // The offer's currency may be a symbol ("USDC") rather than a mint
        // address, and the token program may be omitted (the reference server
        // defaults both from the currency). Resolve the mint and default the
        // token program from the currency, mirroring the rust client.
        val label = Network.label(Network.toCaip2(requirement.network))
        val mintStr = resolveStablecoinMint(asset, label) ?: asset
        val tokenProgramStr = requirement.effectiveTokenProgram
            ?: defaultTokenProgramForCurrency(asset, label)
        val decimals = requirement.effectiveDecimals ?: DEFAULT_DECIMALS
        val tokenProgramKey = PublicKey.fromBase58(tokenProgramStr)
        val mintKey = PublicKey.fromBase58(mintStr)
        val sourceAta = Pda.associatedTokenAddress(signerKey, mintKey, tokenProgramKey)
        val destAta = Pda.associatedTokenAddress(recipientKey, mintKey, tokenProgramKey)
        // Build the SPL transferChecked through web3-solana (the SPL wire
        // layout comes from the maintained Solana Mobile library); see
        // Web3Solana for the adopted-vs-hand-rolled split.
        instructions.add(
            Web3Solana.transferChecked(
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

    // The x402 SVM exact scheme REQUIRES the client to always append exactly
    // one Memo instruction so otherwise-identical concurrent payments stay
    // unique on-chain: the value of ``extra.memo`` when the offer carries one,
    // else a random >=16-byte nonce hex-encoded as UTF-8 (rust spine
    // ``memo_instruction``). Without this an offer with no ``extra.memo`` would
    // produce a fully deterministic transaction that two concurrent payments
    // collide on.
    val sellerMemo = extra?.memo
    val memoData: String = if (sellerMemo != null) {
        // x402 caps the seller memo at 256 bytes (rust MAX_MEMO_BYTES), tighter
        // than the MPP 566 byte cap that Instructions.memo enforces. Check here
        // so an over-long x402 memo fails fast rather than producing a tx the
        // verifier rejects.
        val memoBytes = sellerMemo.encodeToByteArray().size
        require(memoBytes <= X402_MAX_MEMO_BYTES) {
            "extra.memo exceeds maximum $X402_MAX_MEMO_BYTES bytes (got $memoBytes)"
        }
        sellerMemo
    } else {
        // No seller memo: mint a uniqueness nonce. The default hex-encodes 16
        // secure-random bytes (32 UTF-8 chars); tests inject a fixed value.
        val nonce = nonceProvider()
        require(nonce.encodeToByteArray().size <= X402_MAX_MEMO_BYTES) {
            "generated nonce memo exceeds maximum $X402_MAX_MEMO_BYTES bytes"
        }
        nonce
    }
    instructions.add(Instructions.memo(memoData))

    val pinnedBlockhash = requirement.effectiveRecentBlockhash
    val recentBlockhash: ByteArray = if (pinnedBlockhash != null) {
        Base58.decode(pinnedBlockhash)
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
    nonceProvider: () -> String = ::defaultMemoNonce,
): String {
    val envelope = buildPayment(signer, requirement, rpcBlockhashProvider, nonceProvider)
    // Echo the offered object verbatim when it was parsed off the wire so the
    // rust verifier's structural match sees every server-specific field; fall
    // back to the typed entry for offers built in code.
    val acceptedJson = requirement.raw
        ?: json.encodeToJsonElement(X402AcceptsEntry.serializer(), envelope.accepted)
    val envelopeJson = buildJsonObject {
        put("x402Version", JsonPrimitive(envelope.x402Version))
        put("accepted", acceptedJson)
        put("payload", json.encodeToJsonElement(X402PayloadField.serializer(), envelope.payload))
    }
    val payload = json.encodeToString(JsonObject.serializer(), envelopeJson)
    return Base64.getEncoder().encodeToString(payload.encodeToByteArray())
}
