@file:Suppress("unused")
package com.solana.paykit.crypto

/** @see com.solana.paykit.paycore.Transaction */
val Transaction get() = com.solana.paykit.paycore.Transaction

/** @see com.solana.paykit.paycore.Transaction.CompiledInstruction */
typealias CompiledInstruction = com.solana.paykit.paycore.Transaction.CompiledInstruction
