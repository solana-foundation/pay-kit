package com.solana.paykit.conformance

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class MainTest {
    private val json = Json

    @Test
    fun `replays every checked-in session voucher vector with both identities`() {
        val vectors = json.parseToJsonElement(Files.readString(sessionVectorsPath())).jsonArray
        assertTrue(vectors.isNotEmpty(), "session voucher vectors must not be empty")

        for (vector in vectors) {
            val expected = vector.jsonObject
            val result = json.parseToJsonElement(renderVectorResult(vector.toString())).jsonObject
            val expectedBytes = expected["expect"]?.jsonObject?.get("exactBytes")?.jsonObject
            val actualBytes = result["exactBytes"]?.jsonObject

            assertEquals(expected["id"]?.jsonPrimitive?.content, result["id"]?.jsonPrimitive?.content)
            assertEquals("kotlin", result["language"]?.jsonPrimitive?.content)
            assertEquals("kotlin", result["implementation"]?.jsonPrimitive?.content)
            assertEquals("accept", result["outcome"]?.jsonPrimitive?.content)
            assertNotNull(expectedBytes)
            assertNotNull(actualBytes)
            assertEquals(expectedBytes["bytes"], actualBytes["bytes"])
            expectedBytes["base64Url"]?.let { base64Url ->
                assertEquals(base64Url, actualBytes["base64Url"])
            }
        }
    }

    @Test
    fun `rejected vectors retain both runner identities`() {
        val result = json.parseToJsonElement(
            renderVectorResult(
                """
                {
                  "id": "session-voucher-invalid-cumulative",
                  "intent": "session",
                  "mode": "canonical-bytes",
                  "input": {
                    "voucherPreimage": {
                      "channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN",
                      "cumulativeAmount": "not-a-u64",
                      "expiresAt": 1234
                    }
                  }
                }
                """.trimIndent(),
            ),
        ).jsonObject

        assertEquals("session-voucher-invalid-cumulative", result["id"]?.jsonPrimitive?.content)
        assertEquals("kotlin", result["language"]?.jsonPrimitive?.content)
        assertEquals("kotlin", result["implementation"]?.jsonPrimitive?.content)
        assertEquals("reject", result["outcome"]?.jsonPrimitive?.content)
        assertTrue(result["error"]?.jsonPrimitive?.content?.contains("invalid cumulativeAmount") == true)
    }

    private fun sessionVectorsPath(): Path {
        var directory = Path.of(System.getProperty("user.dir")).toAbsolutePath()
        while (true) {
            val candidate = directory.resolve("harness/vectors/session-voucher.json")
            if (Files.isRegularFile(candidate)) return candidate
            directory = directory.parent ?: error("could not find harness/vectors/session-voucher.json")
        }
    }
}
