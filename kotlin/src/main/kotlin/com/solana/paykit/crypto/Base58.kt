/**
 * Backward-compatible re-export shim.
 *
 * All crypto primitives have moved to com.solana.paykit.paycore. These shims
 * keep existing client code and tests compiling without modification while the
 * Kotlin SDK ships the unified layout.
 */
@file:Suppress("unused", "NOTHING_TO_INLINE")
package com.solana.paykit.crypto

/** @see com.solana.paykit.paycore.Base58 */
val Base58 get() = com.solana.paykit.paycore.Base58
