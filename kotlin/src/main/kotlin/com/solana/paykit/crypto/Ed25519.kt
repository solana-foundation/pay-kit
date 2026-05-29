@file:Suppress("unused")
package com.solana.paykit.crypto

/** @see com.solana.paykit.paycore.Ed25519 */
val Ed25519 get() = com.solana.paykit.paycore.Ed25519

/** @see com.solana.paykit.paycore.PublicKey */
typealias PublicKey = com.solana.paykit.paycore.PublicKey

/** @see com.solana.paykit.paycore.Pda */
val Pda get() = com.solana.paykit.paycore.Pda
