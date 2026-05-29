/**
 * Backward-compatible re-export shim.
 *
 * All crypto primitives have moved to com.solana.mpp._paycore. These shims
 * keep existing client code and tests compiling without modification while the
 * Kotlin SDK ships the unified layout.
 */
@file:Suppress("unused", "NOTHING_TO_INLINE")
package com.solana.mpp.crypto

/** @see com.solana.mpp._paycore.Base58 */
val Base58 get() = com.solana.mpp._paycore.Base58
