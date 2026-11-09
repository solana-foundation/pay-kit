package com.solana.paykit.protocols.mpp.core

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Table over the shared RFC 3339 `expires` conformance corpus and the §5.8
 * examples. Validity reads back as `!isExpired` at [Instant.MIN], since an
 * `expires` that is not a `date-time` is expired.
 */
class ExpiresRfc3339Test {
    private fun challenge(expires: String) =
        PaymentChallenge(
            id = "i",
            realm = "r",
            method = "solana",
            intent = "charge",
            request = "q",
            expires = expires,
        )

    @Test
    fun corpusVerdicts() {
        for (input in ACCEPTED) {
            assertFalse(challenge(input).isExpired(Instant.MIN), input)
        }
        for (input in REJECTED) {
            assertTrue(challenge(input).isExpired(Instant.MIN), input)
        }
    }

    @Test
    fun offsetPastJavaTimeBoundStillShiftsTheInstant() {
        val challenge = challenge("2026-01-29T12:00:00+23:00")
        assertTrue(challenge.isExpired(Instant.parse("2026-01-28T13:00:00Z")))
        assertFalse(challenge.isExpired(Instant.parse("2026-01-28T12:59:59Z")))
    }

    @Test
    fun offsetMinutesShiftTheInstant() {
        val challenge = challenge("1937-01-01T12:00:27.87+00:20")
        assertTrue(challenge.isExpired(Instant.parse("1937-01-01T11:40:27.87Z")))
        assertFalse(challenge.isExpired(Instant.parse("1937-01-01T11:40:27.869999999Z")))
    }

    @Test
    fun leapSecondClampsToTheLastRepresentableNanosecond() {
        val challenge = challenge("1990-12-31T15:59:60-08:00")
        assertTrue(challenge.isExpired(Instant.parse("1990-12-31T23:59:59.999999999Z")))
        assertFalse(challenge.isExpired(Instant.parse("1990-12-31T23:59:59.999999998Z")))
    }
}

private val ACCEPTED = listOf(
    "1985-04-12T23:20:50.52Z",
    "1996-12-19T16:39:57-08:00",
    "1937-01-01T12:00:27.87+00:20",
    "1990-12-31T23:59:60Z",
    "1990-12-31T15:59:60-08:00",
    "1998-12-31T23:59:60Z",
    "1998-12-31T15:59:60.123-08:00",
    "1972-06-30T23:59:60Z",
    "1999-01-01T00:59:60+01:00",
    "2021-09-29T16:04:33.0000000000Z",
    "2021-09-29T16:04:33.0000000001Z",
    "2021-09-29T16:04:33.0123456789Z",
    "2021-09-29T16:04:33.1000000000Z",
    "2021-09-29T16:04:33.1000000009Z",
    "2021-09-29T16:04:33.9999999999Z",
    "2021-09-29T16:04:33.00123456789Z",
    "2021-09-29T16:04:33.10000000000Z",
    "2021-09-29T16:04:33.000123456789Z",
    "2021-09-29T16:04:33.9999999999999999Z",
    "1985-04-12T00:59:59.999999999999999Z",
    "2026-01-29T12:00:00.1234567890Z",
    "2026-01-29T12:00:00.9999999999999999999Z",
    "2026-01-29T12:00:00+23:00",
    "2026-01-29T12:00:00-23:00",
    "1963-06-19t08:30:06.283185z",
    "0000-01-01T00:00:00Z",
)

private val REJECTED = listOf(
    "",
    "+12026-01-29T12:00:00Z",
    "2026-01-29T12:00:00+01",
    "1996-12-19T16:39:57-08",
    "2021-09-29T16:04:33.Z",
    "2021-09-29T16:04:33,5Z",
    "2026-01-29T12:00Z",
    "2026-01-29T12:00:00",
    "2026-01-29T12:00:00+0000",
    "2026-01-29T24:00:00Z",
    "2026-02-29T00:00:00Z",
    "2026-02-30T00:00:00Z",
    "2026-04-31T00:00:00Z",
    "2026-01-29",
    "23:59:60Z",
    "06/19/1963 08:30:06 PST",
    "2026-01-29T12:00:00+24:00",
    "2026-01-29T12:00:00-24:00",
    "2026-01-29T12:00:00+00:60",
    "1990-12-31T10:00:00+10:60",
    "1998-12-30T23:59:60Z",
    "1998-12-31T23:58:60Z",
    "1998-12-31T22:59:60Z",
    "1999-01-01T00:59:60+02:00",
)
