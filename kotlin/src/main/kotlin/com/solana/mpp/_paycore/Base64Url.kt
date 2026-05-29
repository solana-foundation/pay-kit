package com.solana.mpp._paycore

// MppException lives in the same package (_paycore)

import java.util.Base64

internal object Base64Url {
    fun encode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun decode(value: String): ByteArray =
        try {
            Base64.getUrlDecoder().decode(value)
        } catch (error: IllegalArgumentException) {
            throw MppException.InvalidBase64Url(error)
        }
}
