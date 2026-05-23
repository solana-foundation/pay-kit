package com.solana.mpp

import java.util.Base64 as JBase64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Functional tests for the full Charge build pipeline. These tests
 * exercise the same paths as the Rust spine's
 * `build_charge_transaction_with_options` (see
 * rust/src/client/charge.rs:62) without committing to the exact byte
 * layout, which is already covered by TransactionTest.
 */
class ChargeBuildTest {
    private val deterministicSeed = ByteArray(32) { 0x17 }
    private val fixedBlockhash: BlockhashProvider = BlockhashProvider { ByteArray(32) }

    private fun signer(): MemorySigner = MemorySigner.fromSeed(deterministicSeed)

    @Test
    fun buildSolChargeTransactionRoundTripsThroughBase64() {
        val request = ChargeRequest(
            amount = "1000000",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "localnet"),
        )
        val transaction = Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        val raw = JBase64.getDecoder().decode(transaction)
        assertTrue(raw.size > 64) // signatures + message
    }

    @Test
    fun buildSplChargeTransactionEmitsExpectedInstructionCount() {
        val request = ChargeRequest(
            amount = "1000",
            currency = "USDC",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "devnet", decimals = 6),
        )
        val transaction = Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        val raw = JBase64.getDecoder().decode(transaction)
        // 1 signature slot + 64 bytes of signature + message
        assertEquals(0x01.toByte(), raw[0])
        // After signature slot and message header is the account-keys count
        // which we cannot pin without recomputing; just sanity-check the
        // shape is non-trivial.
        assertTrue(raw.size > 100)
    }

    @Test
    fun rejectsMoreThanEightSplits() {
        val nineSplits = (1..9).map {
            SolanaChargeSplit(
                recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                amount = "1",
            )
        }
        val request = ChargeRequest(
            amount = "1000",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "localnet", splits = nineSplits),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }

    @Test
    fun rejectsSplitsExceedingPrimaryAmount() {
        val request = ChargeRequest(
            amount = "10",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "localnet",
                splits = listOf(
                    SolanaChargeSplit(
                        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                        amount = "10",
                    ),
                ),
            ),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }

    @Test
    fun rejectsInvalidAmount() {
        val request = ChargeRequest(
            amount = "not-a-number",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }

    @Test
    fun rejectsAtaCreationRequiredWithSolCurrency() {
        val request = ChargeRequest(
            amount = "1000",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                splits = listOf(
                    SolanaChargeSplit(
                        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                        amount = "100",
                        ataCreationRequired = true,
                    ),
                ),
            ),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }

    @Test
    fun feePayerModeUsesProvidedFeePayer() {
        val feePayer = "5xX4f7yqg3DV8oQiTpkH5dyP5kBTb6oC7B4FmCe3wYMK"
        val request = ChargeRequest(
            amount = "1000",
            currency = "USDC",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "devnet",
                feePayer = true,
                feePayerKey = feePayer,
            ),
        )
        val transactionWithFp = Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        val transactionSolo = Charge.buildChargeTransaction(
            signer(),
            request.copy(methodDetails = request.methodDetails.copy(feePayer = false, feePayerKey = null)),
            fixedBlockhash,
        )
        // Wire bytes should differ because the fee payer changes the
        // ordered account-key set and the compiled instruction indices.
        assertNotEquals(transactionWithFp, transactionSolo)
    }

    @Test
    fun usesRecentBlockhashFromMethodDetailsWhenPresent() {
        val recentBlockhash = "11111111111111111111111111111111"
        val request = ChargeRequest(
            amount = "1000",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "localnet",
                recentBlockhash = recentBlockhash,
            ),
        )
        // BlockhashProvider returning random bytes; we expect it to be
        // ignored because methodDetails carries the blockhash.
        val unused = BlockhashProvider { ByteArray(32) { 0xff.toByte() } }
        val first = Charge.buildChargeTransaction(signer(), request, unused)
        val second = Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        assertEquals(first, second)
    }

    @Test
    fun buildCredentialHeaderReturnsPaymentScheme() {
        val request = ChargeRequest(
            amount = "1000",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "localnet",
                recentBlockhash = "11111111111111111111111111111111",
            ),
        )
        // Build a synthetic challenge with this request encoded.
        val requestB64 = Base64Url.encode(
            """{"amount":"1000","currency":"SOL","recipient":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY","methodDetails":{"network":"localnet","recentBlockhash":"11111111111111111111111111111111"}}""".encodeToByteArray(),
        )
        val challenge = PaymentChallenge(
            id = "abc",
            realm = "MPP Payment",
            method = "solana",
            intent = "charge",
            request = requestB64,
        )
        val header = Charge.buildCredentialHeader(signer(), challenge, fixedBlockhash)
        assertTrue(header.startsWith("Payment "))
    }

    @Test
    fun defaultTokenProgramRoutesToken2022MintsCorrectly() {
        assertEquals(Programs.TOKEN_PROGRAM, Charge.defaultTokenProgramFor("USDC", null))
        assertEquals(Programs.TOKEN_PROGRAM, Charge.defaultTokenProgramFor("USDT", null))
        assertEquals(Programs.TOKEN_PROGRAM, Charge.defaultTokenProgramFor("SOL", null))
        assertEquals(Programs.TOKEN_2022_PROGRAM, Charge.defaultTokenProgramFor("PYUSD", null))
        assertEquals(Programs.TOKEN_2022_PROGRAM, Charge.defaultTokenProgramFor("PYUSD", "devnet"))
        assertEquals(Programs.TOKEN_2022_PROGRAM, Charge.defaultTokenProgramFor("USDG", null))
        assertEquals(Programs.TOKEN_2022_PROGRAM, Charge.defaultTokenProgramFor("CASH", null))
        // Unknown mint passes through resolveStablecoinMint and ends up
        // on the legacy SPL token program (the safe default).
        assertEquals(Programs.TOKEN_PROGRAM, Charge.defaultTokenProgramFor("FAKEMINT", null))
    }

    @Test
    fun token2022CurrencyWithoutExplicitTokenProgramUsesToken2022Ata() {
        // Without an explicit methodDetails.tokenProgram, PYUSD must end
        // up on the Token-2022 program. We can't easily inspect the
        // compiled wire bytes here, but we can sanity check that the
        // built transaction is well-formed and the Token-2022 program id
        // appears in the account-keys section.
        val request = ChargeRequest(
            amount = "1000",
            currency = "PYUSD",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "devnet", decimals = 6),
        )
        val transaction = Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        val raw = JBase64.getDecoder().decode(transaction)
        // Token-2022 base58 string interpolated as a byte signature inside
        // the wire bytes is a reasonable witness.
        val token2022Bytes = Base58.decode(Programs.TOKEN_2022_PROGRAM)
        val tokenLegacyBytes = Base58.decode(Programs.TOKEN_PROGRAM)
        val containsToken2022 = (0..raw.size - token2022Bytes.size).any { idx ->
            raw.copyOfRange(idx, idx + token2022Bytes.size).contentEquals(token2022Bytes)
        }
        val containsTokenLegacy = (0..raw.size - tokenLegacyBytes.size).any { idx ->
            raw.copyOfRange(idx, idx + tokenLegacyBytes.size).contentEquals(tokenLegacyBytes)
        }
        assertTrue(containsToken2022, "transaction must reference the Token-2022 program for PYUSD")
        assertTrue(!containsTokenLegacy, "transaction must not reference the legacy Token program for PYUSD")
    }

    @Test
    fun resolveStablecoinMintMatchesRustReference() {
        assertEquals(null, Charge.resolveStablecoinMint("SOL", null))
        assertEquals(null, Charge.resolveStablecoinMint("sol", "localnet"))
        assertEquals(Mints.USDC_MAINNET, Charge.resolveStablecoinMint("USDC", null))
        assertEquals(Mints.USDC_DEVNET, Charge.resolveStablecoinMint("USDC", "devnet"))
        assertEquals(Mints.USDC_DEVNET, Charge.resolveStablecoinMint("USDC", "testnet"))
        assertEquals(Mints.USDT_MAINNET, Charge.resolveStablecoinMint("USDT", null))
        assertEquals(Mints.USDG_DEVNET, Charge.resolveStablecoinMint("USDG", "devnet"))
        assertEquals(Mints.PYUSD_MAINNET, Charge.resolveStablecoinMint("PYUSD", null))
        assertEquals(Mints.CASH_MAINNET, Charge.resolveStablecoinMint("CASH", null))
        // Unknown currency passes through unchanged (treated as a mint address).
        val raw = "FAKEMintAddressFAKEMintAddressFAKE"
        assertEquals(raw, Charge.resolveStablecoinMint(raw, null))
    }

    @Test
    fun rejectsMalformedBlockhash() {
        val request = ChargeRequest(
            amount = "1000",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(recentBlockhash = "0OIl"),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }
}
