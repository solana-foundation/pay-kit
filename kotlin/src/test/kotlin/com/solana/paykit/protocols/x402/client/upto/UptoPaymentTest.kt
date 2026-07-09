package com.solana.paykit.protocols.x402.client.upto

import com.solana.paykit.paycore.Base58
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.PaymentChannels
import com.solana.paykit.paycore.Programs
import com.solana.paykit.paycore.PublicKey
import com.solana.paykit.paycore.SolanaNetwork
import com.solana.paykit.protocols.x402.upto.UPTO_SCHEME
import com.solana.paykit.protocols.x402.upto.UptoExtra
import com.solana.paykit.protocols.x402.upto.UptoRequiredEnvelope
import com.solana.paykit.protocols.x402.upto.UptoRequirements
import com.solana.paykit.protocols.x402.upto.UptoSettlementResponse
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UptoPaymentTest {
    private val json = Json { ignoreUnknownKeys = true }
    private val encoder = Json { encodeDefaults = false; explicitNulls = false }

    // Fixed CSPRNG-free signer seed so the channel payer (and thus channel PDA)
    // is deterministic across runs.
    private val signer = MemorySigner.fromSeed(ByteArray(32) { (it + 1).toByte() })

    private val feePayer = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
    private val receiverAuthorizer = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
    private val mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    private val beneficiary = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
    private val network = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"

    // base58("11111111111111111111111111111111") decodes to 32 zero bytes.
    private val blockhash = "11111111111111111111111111111111"

    private val fixedSalt: ULong = 0x0102030405060708uL

    // Deterministic slot standing in for the server-prefetched extra.recentSlot.
    private val recentSlot: ULong = 424_242uL

    private fun extra(
        feePayer: String? = this.feePayer,
        receiverAuthorizer: String? = this.receiverAuthorizer,
        withdrawDelay: Int = 900,
        recentBlockhash: String? = blockhash,
        recentSlot: ULong? = this.recentSlot,
        validAfter: Long? = null,
        tokenProgram: String? = null,
    ) = UptoExtra(
        tokenProgram = tokenProgram,
        feePayer = feePayer,
        receiverAuthorizer = receiverAuthorizer,
        withdrawDelay = withdrawDelay,
        recentBlockhash = recentBlockhash,
        recentSlot = recentSlot,
        validAfter = validAfter,
    )

    private fun requirements(
        amount: String = "1000000",
        payTo: String = beneficiary,
        asset: String = mint,
        extra: UptoExtra = extra(),
    ) = UptoRequirements(
        scheme = UPTO_SCHEME,
        network = SolanaNetwork.Devnet,
        amount = amount,
        asset = asset,
        payTo = payTo,
        maxTimeoutSeconds = 300,
        extra = extra,
    )

    // ── parse decode helpers ────────────────────────────────────────────────

    // Extracts the single open instruction's data from a legacy transaction
    // base64. All shortvec counts in the open transaction fixtures fit in one
    // byte, so a single-byte reader is sufficient.
    private fun openInstructionData(txB64: String): ByteArray {
        val tx = Base64.getDecoder().decode(txB64)
        var p = 0
        val sigCount = tx[p++].toInt()
        p += sigCount * 64
        p += 3 // message header
        val acctCount = tx[p++].toInt()
        p += acctCount * 32
        p += 32 // blockhash
        p++ // instruction count
        p++ // program id index
        val acctIdxCount = tx[p++].toInt()
        p += acctIdxCount
        val dataLen = tx[p++].toInt()
        return tx.copyOfRange(p, p + dataLen)
    }

    private fun firstAccountKey(txB64: String): ByteArray {
        val tx = Base64.getDecoder().decode(txB64)
        var p = 0
        val sigCount = tx[p++].toInt()
        p += sigCount * 64
        p += 3 // header
        p++ // account count
        return tx.copyOfRange(p, p + 32)
    }

    private fun u32Le(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xff) or
            ((data[offset + 1].toInt() and 0xff) shl 8) or
            ((data[offset + 2].toInt() and 0xff) shl 16) or
            ((data[offset + 3].toInt() and 0xff) shl 24)

    // ── adversarial: build-time errors ──────────────────────────────────────

    @Test
    fun rejects_missing_fee_payer() {
        val req = requirements(extra = extra(feePayer = null))
        val error = assertFailsWith<IllegalArgumentException> {
            buildUptoPayload(signer, req, expiresAt = 4_102_444_800L)
        }
        assertContains(error.message!!, "missing extra.feePayer")
    }

    @Test
    fun rejects_missing_receiver_authorizer() {
        val req = requirements(extra = extra(receiverAuthorizer = null))
        val error = assertFailsWith<IllegalArgumentException> {
            buildUptoPayload(signer, req, expiresAt = 4_102_444_800L)
        }
        assertContains(error.message!!, "missing extra.receiverAuthorizer")
    }

    @Test
    fun rejects_missing_recent_blockhash() {
        val req = requirements(extra = extra(recentBlockhash = null))
        val error = assertFailsWith<IllegalArgumentException> {
            buildUptoPayload(signer, req, expiresAt = 4_102_444_800L)
        }
        assertContains(error.message!!, "missing extra.recentBlockhash")
    }

    @Test
    fun rejects_missing_recent_slot() {
        val req = requirements(extra = extra(recentSlot = null))
        val error = assertFailsWith<IllegalArgumentException> {
            buildUptoPayload(signer, req, expiresAt = 4_102_444_800L)
        }
        assertContains(error.message!!, "missing extra.recentSlot")
    }

    @Test
    fun rejects_missing_withdraw_delay() {
        val req = requirements(extra = extra(withdrawDelay = 0))
        val error = assertFailsWith<IllegalArgumentException> {
            buildUptoPayload(signer, req, expiresAt = 4_102_444_800L)
        }
        assertContains(error.message!!, "missing extra.withdrawDelay")
    }

    @Test
    fun rejects_invalid_amount() {
        val req = requirements(amount = "not-a-number")
        val error = assertFailsWith<IllegalArgumentException> {
            buildUptoPayload(signer, req, expiresAt = 4_102_444_800L)
        }
        assertContains(error.message!!, "invalid upto amount")
    }

    @Test
    fun rejects_amount_above_u64() {
        val req = requirements(amount = "18446744073709551616") // 2^64
        assertFailsWith<IllegalArgumentException> {
            buildUptoPayload(signer, req, expiresAt = 4_102_444_800L)
        }
    }

    @Test
    fun rejects_invalid_asset_mint() {
        val req = requirements(asset = "not-base58!!")
        val error = assertFailsWith<IllegalArgumentException> {
            buildUptoPayload(signer, req, expiresAt = 4_102_444_800L)
        }
        assertContains(error.message!!, "invalid asset mint")
    }

    @Test
    fun rejects_invalid_pay_to() {
        val req = requirements(payTo = "not-base58!!")
        val error = assertFailsWith<IllegalArgumentException> {
            buildUptoPayload(signer, req, expiresAt = 4_102_444_800L)
        }
        assertContains(error.message!!, "invalid payTo")
    }

    // ── payload shape ───────────────────────────────────────────────────────

    @Test
    fun deposit_equals_max_amount() {
        val payload = buildUptoPayload(signer, requirements(), expiresAt = 123L)
        assertEquals("1000000", payload.maxAmount)
        assertEquals("1000000", payload.deposit)
        assertEquals(payload.maxAmount, payload.deposit)
    }

    @Test
    fun valid_after_defaults_to_zero() {
        val payload = buildUptoPayload(signer, requirements(), expiresAt = 123L)
        assertEquals(0L, payload.validAfter)
    }

    @Test
    fun valid_after_honored_from_extra() {
        val req = requirements(extra = extra(validAfter = 555L))
        val payload = buildUptoPayload(signer, req, expiresAt = 123L)
        assertEquals(555L, payload.validAfter)
    }

    @Test
    fun from_and_authorized_signer_and_expires() {
        val payload = buildUptoPayload(signer, requirements(), expiresAt = 999L)
        assertEquals(signer.address, payload.from)
        assertEquals(receiverAuthorizer, payload.authorizedSigner)
        assertEquals(999L, payload.expiresAt)
        assertTrue(payload.openTransaction != null)
        assertEquals(payload.openSlot, recentSlot.toString())
    }

    // ── nonce / salt binding ────────────────────────────────────────────────

    @Test
    fun nonce_is_open_salt_decimal() {
        val a = buildUptoPayload(signer, requirements(), 1L, saltProvider = { fixedSalt })
        assertEquals(fixedSalt.toString(), a.nonce)
    }

    @Test
    fun explicit_nonce_is_ignored() {
        val payload = buildUptoPayload(signer, requirements(), 1L, nonce = "my-nonce")
        assertNotEquals("my-nonce", payload.nonce)
        assertTrue(payload.nonce.toULongOrNull() != null)
    }

    // ── channel PDA + recipients ────────────────────────────────────────────

    @Test
    fun channel_id_matches_find_channel_pda_for_chosen_salt() {
        val payload = buildUptoPayload(signer, requirements(), 1L, saltProvider = { fixedSalt })
        val expected = PaymentChannels.findChannelPda(
            payer = PublicKey(signer.publicKeyBytes),
            payee = PublicKey.fromBase58(receiverAuthorizer),
            mint = PublicKey.fromBase58(mint),
            authorizedSigner = PublicKey.fromBase58(receiverAuthorizer),
            salt = fixedSalt,
            openSlot = recentSlot,
            programId = PublicKey.fromBase58(PaymentChannels.PROGRAM_ID),
        )
        assertEquals(expected.toBase58(), payload.channelId)
    }

    @Test
    fun open_transaction_fee_payer_is_advertised_fee_payer() {
        val payload = buildUptoPayload(signer, requirements(), 1L, saltProvider = { fixedSalt })
        val feePayer = firstAccountKey(payload.openTransaction!!)
        assertTrue(feePayer.contentEquals(PublicKey.fromBase58(this.feePayer).bytes))
    }

    @Test
    fun pay_to_equals_receiver_authorizer_yields_empty_recipients() {
        val req = requirements(payTo = receiverAuthorizer)
        val payload = buildUptoPayload(signer, req, 1L, saltProvider = { fixedSalt })
        val data = openInstructionData(payload.openTransaction!!)
        // discriminator(1)+salt(8)+deposit(8)+gracePeriod(4)+openSlot(8) = 29,
        // then u32 count.
        assertEquals(0, u32Le(data, 29))
    }

    @Test
    fun open_args_carry_open_slot_after_grace_period() {
        val payload = buildUptoPayload(signer, requirements(payTo = receiverAuthorizer), 1L, saltProvider = { fixedSalt })
        val data = openInstructionData(payload.openTransaction!!)
        // The wire recentSlot lands as the borsh openSlot u64 LE at offset 21
        // (after discriminator+salt+deposit+gracePeriod).
        var decoded = 0uL
        for (i in 0..7) decoded = decoded or ((data[21 + i].toULong() and 0xffuL) shl (8 * i))
        assertEquals(recentSlot, decoded)
    }

    @Test
    fun pay_to_not_receiver_authorizer_yields_one_distribution_with_full_bps() {
        val req = requirements(payTo = beneficiary)
        val payload = buildUptoPayload(signer, req, 1L, saltProvider = { fixedSalt })
        val data = openInstructionData(payload.openTransaction!!)
        assertEquals(1, u32Le(data, 29))
        // entry: recipient(32) at offset 33, then bps(u16 LE).
        val recipient = data.copyOfRange(33, 65)
        assertTrue(recipient.contentEquals(PublicKey.fromBase58(beneficiary).bytes))
        val bps = (data[65].toInt() and 0xff) or ((data[66].toInt() and 0xff) shl 8)
        assertEquals(10_000, bps)
    }

    @Test
    fun recipients_branch_changes_open_transaction() {
        val opAsBeneficiary = buildUptoPayload(
            signer, requirements(payTo = receiverAuthorizer), 1L, saltProvider = { fixedSalt },
        )
        val split = buildUptoPayload(
            signer, requirements(payTo = beneficiary), 1L, saltProvider = { fixedSalt },
        )
        assertNotEquals(opAsBeneficiary.openTransaction, split.openTransaction)
    }

    @Test
    fun honors_custom_token_program() {
        val req = requirements(
            extra = extra(
                tokenProgram = Programs.TOKEN_2022_PROGRAM,
            ),
        )
        // Must not throw; channel program is canonical and not supplied on the wire.
        val payload = buildUptoPayload(signer, req, 1L, saltProvider = { fixedSalt })
        assertTrue(payload.channelId.isNotEmpty())
    }

    // ── extra JSON shape ────────────────────────────────────────────────────

    @Test
    fun removed_wire_fields_are_omitted_from_requirement_json() {
        val encoded = encoder.encodeToString(UptoRequirements.serializer(), requirements())
        val extraObj = json.parseToJsonElement(encoded).jsonObject["extra"]!!.jsonObject
        assertTrue(extraObj["feePayer"] != null)
        assertTrue(extraObj["receiverAuthorizer"] != null)
        assertTrue(extraObj["withdrawDelay"] != null)
        assertNull(extraObj["assetTransferMethod"])
        assertNull(extraObj["facilitatorFee"])
        assertNull(extraObj["channelProgram"])
        // scheme is always emitted.
        assertEquals(
            "upto",
            json.parseToJsonElement(encoded).jsonObject["scheme"]!!.jsonPrimitive.content,
        )
    }

    // ── envelope encoding / round-trip ──────────────────────────────────────

    @Test
    fun envelope_round_trips_with_standard_base64() {
        val header = buildUptoHeader(signer, requirements(), expiresAt = 4_102_444_800L)
        val decoded = Base64.getDecoder().decode(header).decodeToString()
        val obj = json.parseToJsonElement(decoded).jsonObject
        assertEquals(2, obj["x402Version"]!!.jsonPrimitive.int)
        val accepted = obj["accepted"]!!.jsonObject
        assertEquals("upto", accepted["scheme"]!!.jsonPrimitive.content)
        assertEquals(network, accepted["network"]!!.jsonPrimitive.content)
        val payload = obj["payload"]!!.jsonObject
        assertEquals("1000000", payload["maxAmount"]!!.jsonPrimitive.content)
        assertEquals("1000000", payload["deposit"]!!.jsonPrimitive.content)
        // The new wire carries no signature / profile field.
        assertNull(payload["signature"])
        assertNull(payload["profile"])
    }

    @Test
    fun encode_header_echoes_raw_accepted_verbatim() {
        // A wire object carrying a server-specific field the typed model omits;
        // it must survive into the echoed accepted object.
        val wire = """
            {"x402Version":2,"accepts":[{"scheme":"upto","network":"$network",
            "amount":"1000000","asset":"$mint","payTo":"$beneficiary",
            "maxTimeoutSeconds":300,"serverOnlyField":"keep-me",
            "extra":{"feePayer":"$feePayer","receiverAuthorizer":"$receiverAuthorizer",
            "withdrawDelay":900,"recentBlockhash":"$blockhash",
            "recentSlot":"$recentSlot"}}]}
        """.trimIndent().replace("\n", "")
        val req = parseUptoChallenge(mapOf("content-type" to "application/json"), wire)!!
        val header = buildUptoHeader(signer, req, expiresAt = 1L)
        val accepted = json.parseToJsonElement(
            Base64.getDecoder().decode(header).decodeToString(),
        ).jsonObject["accepted"]!!.jsonObject
        assertEquals("keep-me", accepted["serverOnlyField"]!!.jsonPrimitive.content)
    }

    // ── challenge parsing ───────────────────────────────────────────────────

    private fun challengeEnvelope(accepts: String): String =
        """{"x402Version":2,"accepts":[$accepts]}"""

    private fun uptoEntry(scheme: String = "upto", asset: String = mint): String =
        """{"scheme":"$scheme","network":"$network","amount":"1000000",
            "asset":"$asset","payTo":"$beneficiary","maxTimeoutSeconds":300,
            "extra":{"feePayer":"$feePayer","receiverAuthorizer":"$receiverAuthorizer",
            "withdrawDelay":900,"recentBlockhash":"$blockhash",
            "recentSlot":"$recentSlot"}}"""
            .replace("\n", "").replace("  ", "")

    @Test
    fun parse_reads_recent_slot_from_string_or_number() {
        val fromString = parseUptoChallenge(emptyMap(), challengeEnvelope(uptoEntry()))
        assertEquals(recentSlot, fromString!!.extra.recentSlot)
        // A server emitting the slot as a bare JSON number must parse too.
        val numberEntry = uptoEntry().replace(""""recentSlot":"$recentSlot"""", """"recentSlot":$recentSlot""")
        val fromNumber = parseUptoChallenge(emptyMap(), challengeEnvelope(numberEntry))
        assertEquals(recentSlot, fromNumber!!.extra.recentSlot)
    }

    @Test
    fun parse_reads_base64_payment_required_header() {
        val body = challengeEnvelope(uptoEntry())
        val headerValue = Base64.getEncoder().encodeToString(body.encodeToByteArray())
        val req = parseUptoChallenge(mapOf("Payment-Required" to headerValue))
        assertEquals("1000000", req!!.amount)
        assertEquals(feePayer, req.extra.feePayer)
        assertEquals(receiverAuthorizer, req.extra.receiverAuthorizer)
    }

    @Test
    fun parse_header_lookup_is_case_insensitive() {
        val body = challengeEnvelope(uptoEntry())
        val headerValue = Base64.getEncoder().encodeToString(body.encodeToByteArray())
        val req = parseUptoChallenge(mapOf("PAYMENT-REQUIRED" to headerValue))
        assertEquals("1000000", req!!.amount)
    }

    @Test
    fun parse_falls_back_to_body() {
        val req = parseUptoChallenge(emptyMap(), challengeEnvelope(uptoEntry()))
        assertEquals(mint, req!!.asset)
    }

    @Test
    fun parse_returns_null_without_upto_offer() {
        assertNull(parseUptoChallenge(emptyMap(), null))
        assertNull(parseUptoChallenge(emptyMap(), challengeEnvelope(uptoEntry(scheme = "exact"))))
    }

    @Test
    fun parse_invalid_base64_header_returns_empty() {
        assertNull(parseUptoChallenge(mapOf("payment-required" to "!!!not base64!!!")))
    }

    @Test
    fun parse_accepts_returns_all_upto_and_skips_non_upto() {
        val accepts = listOf(
            uptoEntry(scheme = "exact"),
            uptoEntry(asset = mint),
            uptoEntry(asset = "So11111111111111111111111111111111111111112"),
        ).joinToString(",")
        val all = parseUptoAccepts(emptyMap(), challengeEnvelope(accepts))
        assertEquals(2, all.size)
        assertTrue(all.all { it.scheme == "upto" })
    }

    @Test
    fun parse_malformed_json_returns_empty() {
        assertTrue(parseUptoAccepts(emptyMap(), "{not json").isEmpty())
        assertTrue(parseUptoAccepts(emptyMap(), """{"no":"accepts"}""").isEmpty())
    }

    @Test
    fun parse_header_base64_but_invalid_json_falls_back_to_body() {
        // Header is well-formed base64 yet decodes to non-envelope text; the
        // body carries the real challenge. Matches the rust spine's
        // `from_header.or_else(body)` fallback.
        val header = Base64.getEncoder().encodeToString("{not an envelope".encodeToByteArray())
        val req = parseUptoChallenge(
            mapOf("payment-required" to header),
            challengeEnvelope(uptoEntry()),
        )
        assertEquals("1000000", req!!.amount)
        assertEquals(feePayer, req.extra.feePayer)
    }

    @Test
    fun parse_header_envelope_without_accepts_key_resolves_empty() {
        // A header that decodes to a valid envelope (has x402Version) but omits
        // `accepts` resolves to no offers; the body is NOT consulted, matching the
        // rust spine where accepts is serde(default) and from_header wins.
        val header = Base64.getEncoder().encodeToString("""{"x402Version":2}""".encodeToByteArray())
        val all = parseUptoAccepts(
            mapOf("payment-required" to header),
            challengeEnvelope(uptoEntry()),
        )
        assertTrue(all.isEmpty())
    }

    @Test
    fun parse_header_not_an_envelope_falls_back_to_body() {
        // A header that decodes to JSON without x402Version is not an envelope, so
        // the body is consulted next.
        val header = Base64.getEncoder().encodeToString("""{"foo":1}""".encodeToByteArray())
        val req = parseUptoChallenge(
            mapOf("payment-required" to header),
            challengeEnvelope(uptoEntry()),
        )
        assertEquals(mint, req!!.asset)
    }

    @Test
    fun parse_header_envelope_with_no_upto_offers_does_not_fall_back() {
        // The header parses as a valid envelope whose only offer is non-upto;
        // the rust spine treats this as a resolved (empty) result and does NOT
        // consult the body, so a body upto offer must be ignored.
        val header = Base64.getEncoder().encodeToString(
            challengeEnvelope(uptoEntry(scheme = "exact")).encodeToByteArray(),
        )
        val all = parseUptoAccepts(
            mapOf("payment-required" to header),
            challengeEnvelope(uptoEntry()),
        )
        assertTrue(all.isEmpty())
    }

    // ── other wire types (serialization coverage) ───────────────────────────

    @Test
    fun settlement_response_round_trips() {
        val resp = UptoSettlementResponse(
            success = true,
            payer = "Payer",
            transaction = "sig",
            network = SolanaNetwork.Devnet,
            amount = "500000",
        )
        val encoded = encoder.encodeToString(UptoSettlementResponse.serializer(), resp)
        assertTrue(!encoded.contains("errorReason"))
        // The typed network serializes to its bare CAIP-2 string.
        assertContains(encoded, "\"network\":\"$network\"")
        val back = json.decodeFromString(UptoSettlementResponse.serializer(), encoded)
        assertTrue(back.success)
        assertEquals("500000", back.amount)
        assertEquals(SolanaNetwork.Devnet, back.network)
    }

    @Test
    fun unknown_network_parses_as_other_and_round_trips_verbatim() {
        // A CAIP-2 id the SDK does not special-case must not fail to parse and
        // must survive re-serialization byte-identical.
        val exotic = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z-fork"
        val entry = uptoEntry().replace(network, exotic)
        val req = parseUptoChallenge(mapOf("content-type" to "application/json"), challengeEnvelope(entry))!!
        assertEquals(SolanaNetwork.Other(exotic), req.network)
        val header = buildUptoHeader(signer, req, expiresAt = 4_102_444_800L)
        val accepted = json.parseToJsonElement(
            Base64.getDecoder().decode(header).decodeToString(),
        ).jsonObject["accepted"]!!.jsonObject
        assertEquals(exotic, accepted["network"]!!.jsonPrimitive.content)
    }

    @Test
    fun settlement_failure_response_without_optional_fields_parses() {
        // A generic failure response may omit transaction, network, and amount;
        // deserializing it must not throw a MissingFieldException.
        val body = """{"success":false,"errorReason":"blockhash_expired"}"""
        val back = json.decodeFromString(UptoSettlementResponse.serializer(), body)
        assertTrue(!back.success)
        assertEquals("blockhash_expired", back.errorReason)
        assertEquals(null, back.transaction)
        assertEquals(null, back.network)
        assertEquals(null, back.amount)
    }

    @Test
    fun required_envelope_round_trips() {
        val env = UptoRequiredEnvelope(x402Version = 2, accepts = listOf(requirements()))
        val encoded = encoder.encodeToString(UptoRequiredEnvelope.serializer(), env)
        val back = json.decodeFromString(UptoRequiredEnvelope.serializer(), encoded)
        assertEquals(2, back.x402Version)
        assertEquals(1, back.accepts.size)
        assertEquals(UPTO_SCHEME, back.accepts.first().scheme)
    }
}
