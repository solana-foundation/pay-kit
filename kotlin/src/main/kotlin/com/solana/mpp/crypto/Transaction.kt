@file:Suppress("unused")
package com.solana.mpp.crypto

/** @see com.solana.mpp._paycore.Transaction */
val Transaction get() = com.solana.mpp._paycore.Transaction

/** @see com.solana.mpp._paycore.Transaction.CompiledInstruction */
typealias CompiledInstruction = com.solana.mpp._paycore.Transaction.CompiledInstruction
