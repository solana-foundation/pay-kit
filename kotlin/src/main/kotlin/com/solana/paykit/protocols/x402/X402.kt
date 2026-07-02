package com.solana.paykit.protocols.x402

/**
 * x402 protocol version stamped in the ``PAYMENT-SIGNATURE`` / ``PAYMENT-REQUIRED``
 * envelopes (rust ``X402_VERSION_V2``, go ``x402Version = 2``). Shared by the
 * exact and upto builders. Do NOT revert to 1 (the legacy ``X-PAYMENT`` shape).
 */
internal const val X402_VERSION = 2
