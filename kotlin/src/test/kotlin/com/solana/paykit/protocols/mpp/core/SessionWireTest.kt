package com.solana.paykit.protocols.mpp.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionWireTest {
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun openActionFlattensTagAndSerializesSaltAndRecentSlotAsStrings() {
        val action = SessionAction.Open(
            OpenPayload.paymentChannel(
                SessionMode.PULL, "Chan", "1000", "Payer", "Payee", "Mint", 42uL, 900u, 777uL, "Auth", "Sig"
            )
        )
        val obj = SessionActionCodec.toJsonObject(action)
        assertEquals("open", obj["action"]?.jsonPrimitive?.content)
        assertEquals("pull", obj["mode"]?.jsonPrimitive?.content)
        assertEquals("Chan", obj["channelId"]?.jsonPrimitive?.content)
        // salt and recentSlot are decimal strings, not numbers.
        val salt = obj["salt"]?.jsonPrimitive
        assertEquals("42", salt?.content)
        assertTrue(salt?.isString == true)
        val recentSlot = obj["recentSlot"]?.jsonPrimitive
        assertEquals("777", recentSlot?.content)
        assertTrue(recentSlot?.isString == true)
        assertEquals("Auth", obj["authorizedSigner"]?.jsonPrimitive?.content)
    }

    @Test
    fun topUpActionUsesCamelCaseTag() {
        val obj = SessionActionCodec.toJsonObject(SessionAction.TopUp(TopUpPayload("Chan", "500", "Sig")))
        assertEquals("topUp", obj["action"]?.jsonPrimitive?.content)
        assertEquals("500", obj["newDeposit"]?.jsonPrimitive?.content)
    }

    @Test
    fun sessionActionRoundTrips() {
        val voucher = SignedVoucher(VoucherData("Chan", "250", 4_102_444_800L, 3L), "Sig")
        val actions = listOf(
            SessionAction.Open(OpenPayload.push("Chan", "1000", "Auth", "Sig")),
            SessionAction.Voucher(VoucherPayload(voucher)),
            SessionAction.Commit(CommitPayload("d1", voucher)),
            SessionAction.TopUp(TopUpPayload("Chan", "500", "Sig")),
            SessionAction.Close(ClosePayload("Chan", voucher)),
        )
        for (action in actions) {
            assertEquals(action, SessionActionCodec.decodeFromString(SessionActionCodec.encodeToString(action)))
        }
    }

    @Test
    fun voucherDataEncodesCumulativeAmountAndReadsAlias() {
        val encoded = json.encodeToString(VoucherData.serializer(), VoucherData("Chan", "250", 100L))
        val tree = json.parseToJsonElement(encoded)
        assertEquals("250", (tree as kotlinx.serialization.json.JsonObject)["cumulativeAmount"]?.jsonPrimitive?.content)
        assertNull(tree["cumulative"])

        val canonical = json.decodeFromString(VoucherData.serializer(), """{"channelId":"Chan","cumulativeAmount":"7","expiresAt":1}""")
        assertEquals("7", canonical.cumulative)
        val alias = json.decodeFromString(VoucherData.serializer(), """{"channelId":"Chan","cumulative":"9","expiresAt":1}""")
        assertEquals("9", alias.cumulative)
    }

    @Test
    fun openPayloadReadsSaltFromStringOrNumber() {
        val fromString = json.decodeFromString(
            OpenPayload.serializer(), """{"mode":"pull","salt":"42","authorizedSigner":"A","signature":"S"}"""
        )
        assertEquals(42uL, fromString.salt)
        val fromNumber = json.decodeFromString(
            OpenPayload.serializer(), """{"mode":"pull","salt":42,"authorizedSigner":"A","signature":"S"}"""
        )
        assertEquals(42uL, fromNumber.salt)
    }

    @Test
    fun openPayloadReadsRecentSlotFromStringOrNumber() {
        val fromString = json.decodeFromString(
            OpenPayload.serializer(), """{"mode":"pull","recentSlot":"777","authorizedSigner":"A","signature":"S"}"""
        )
        assertEquals(777uL, fromString.recentSlot)
        val fromNumber = json.decodeFromString(
            OpenPayload.serializer(), """{"mode":"pull","recentSlot":777,"authorizedSigner":"A","signature":"S"}"""
        )
        assertEquals(777uL, fromNumber.recentSlot)
    }

    @Test
    fun sessionRequestReadsRecentSlotFromStringOrNumber() {
        val base = """"cap":"1000","currency":"USDC","operator":"Op","recipient":"Rec""""
        val fromString = json.decodeFromString(
            SessionRequest.serializer(), """{$base,"recentSlot":"777"}"""
        )
        assertEquals(777uL, fromString.recentSlot)
        val fromNumber = json.decodeFromString(
            SessionRequest.serializer(), """{$base,"recentSlot":777}"""
        )
        assertEquals(777uL, fromNumber.recentSlot)
        // Absent recentSlot stays null (older servers).
        val absent = json.decodeFromString(SessionRequest.serializer(), """{$base}""")
        assertNull(absent.recentSlot)
    }
}
