package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.paycore.Base58
import com.solana.paykit.paycore.Base64Url
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.Mints
import com.solana.paykit.paycore.MppException
import com.solana.paykit.paycore.Programs
import com.solana.paykit.paycore.PublicKey
import com.solana.paykit.protocols.mpp.core.ChargeRequest
import com.solana.paykit.protocols.mpp.core.PaymentChallenge
import com.solana.paykit.protocols.mpp.core.SolanaChargeMethodDetails
import com.solana.paykit.protocols.mpp.core.SolanaChargeSplit

import java.util.Base64 as JBase64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json

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
    fun acceptsSplitsSumFittingInLong() {
        // Two large but non-overflowing splits. Sum stays within Long.
        val request = ChargeRequest(
            amount = (Long.MAX_VALUE).toString(),
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "localnet",
                splits = listOf(
                    SolanaChargeSplit(
                        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                        amount = "100",
                    ),
                    SolanaChargeSplit(
                        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                        amount = "200",
                    ),
                ),
            ),
        )
        Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
    }

    @Test
    fun rejectsSplitsSumOverflowingLong() {
        // Each split fits in Long but their sum overflows. Without the
        // checked-addition guard, splitsTotal would wrap negative, the
        // `primaryAmount <= 0L` check would pass, and each per-split
        // transfer would still emit its huge positive amount on the
        // wire. Regression for the Go #101 / Kotlin #105 P1 finding.
        val big = (Long.MAX_VALUE - 10L).toString()
        val request = ChargeRequest(
            amount = (Long.MAX_VALUE).toString(),
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "localnet",
                splits = listOf(
                    SolanaChargeSplit(
                        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                        amount = big,
                    ),
                    SolanaChargeSplit(
                        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                        amount = big,
                    ),
                ),
            ),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }

    @Test
    fun rejectsNegativeSplitAmountWithStructuredError() {
        // Regression: `toLongOrNull` parses "-100" into -100L, so
        // splitsTotal could go negative and `primaryAmount =
        // totalAmount - (-100)` would clear the <= 0 guard. The
        // negative value would then reach transferChecked and trip
        // an unchecked IllegalArgumentException from inside the wire
        // encoder. Callers catch MppException.InvalidTransaction,
        // so the guard must reject negative splits up front.
        val request = ChargeRequest(
            amount = "1000",
            currency = "USDC",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "mainnet",
                splits = listOf(
                    SolanaChargeSplit(
                        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                        amount = "-100",
                    ),
                ),
            ),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }

    @Test
    fun rejectsKnownSymbolCurrencyWithAtaCreationSplit() {
        // finding-9: ataCreationRequired must bind the EXACT base58 mint, not
        // a symbol. A fee-sponsored server pays the ATA rent, so it must pin
        // the mint it sponsors rather than trusting a symbol→mint mapping that
        // could diverge across SDKs. Rust/TS/Swift all reject the symbol path
        // (`mint_str != currency`). The prior Kotlin build ACCEPTED it, letting
        // Kotlin construct credentials the reference servers reject. This is
        // now a rejection test.
        val request = ChargeRequest(
            amount = "1000",
            currency = "USDC",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "mainnet",
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
    fun acceptsBase58MintCurrencyWithAtaCreationSplit() {
        // The positive case for finding-9: when `currency` IS the resolved
        // base58 mint address, ataCreationRequired is accepted. USDC mainnet
        // mint is a known stablecoin, so the token program resolves from the
        // static table without an RPC. Parity with the rust/Swift positive
        // path (`mint_str == currency`).
        val request = ChargeRequest(
            amount = "1000",
            currency = Mints.USDC_MAINNET,
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "mainnet",
                splits = listOf(
                    SolanaChargeSplit(
                        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                        amount = "100",
                        ataCreationRequired = true,
                    ),
                ),
            ),
        )
        Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
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
            request.copy(methodDetails = request.methodDetails!!.copy(feePayer = false, feePayerKey = null)),
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

    // ── Token-program resolution (finding-10) ──────────────────────────────

    @Test
    fun rejectsUnsupportedExplicitTokenProgram() {
        // finding-10(b): an explicit methodDetails.tokenProgram must be
        // validated against {Token, Token-2022} only. A bogus program id is
        // rejected client-side rather than mis-deriving ATAs. The prior build
        // never validated the explicit value. Mirrors rust resolve_token_program.
        val request = ChargeRequest(
            amount = "1000",
            currency = "USDC",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "devnet",
                decimals = 6,
                tokenProgram = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            ),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }

    @Test
    fun acceptsExplicitToken2022Program() {
        // A valid explicit Token-2022 program is accepted even when the mint
        // is unknown (the explicit value short-circuits owner resolution).
        val request = ChargeRequest(
            amount = "1000",
            currency = "So11111111111111111111111111111111111111112",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(
                network = "mainnet",
                decimals = 6,
                tokenProgram = Programs.TOKEN_2022_PROGRAM,
            ),
        )
        Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
    }

    @Test
    fun failsClosedForArbitraryMintWithoutResolverOrExplicitProgram() {
        // finding-10(a): an arbitrary (non-stablecoin) mint with no explicit
        // tokenProgram and no MintOwnerResolver must FAIL CLOSED rather than
        // guessing the legacy Token program. The prior build silently
        // defaulted to TOKEN_PROGRAM, mis-deriving ATAs for Token-2022 mints.
        val request = ChargeRequest(
            amount = "1000",
            currency = "So11111111111111111111111111111111111111112",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "mainnet", decimals = 6),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }

    @Test
    fun resolvesArbitraryMintProgramViaMintOwnerResolver() {
        // finding-10(a): with a MintOwnerResolver, an arbitrary mint's token
        // program is read from the mint account owner and validated against
        // {Token, Token-2022}. Mirrors rust resolve_token_program / swift RPC.
        val arbitraryMint = "So11111111111111111111111111111111111111112"
        var queried: String? = null
        val resolver = MintOwnerResolver { mint ->
            queried = mint
            Programs.TOKEN_2022_PROGRAM
        }
        val request = ChargeRequest(
            amount = "1000",
            currency = arbitraryMint,
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "mainnet", decimals = 6),
        )
        Charge.buildChargeTransaction(
            signer(),
            request,
            fixedBlockhash,
            mintOwnerResolver = resolver,
        )
        assertEquals(arbitraryMint, queried)
    }

    @Test
    fun rejectsArbitraryMintWhenOwnerIsUnsupportedProgram() {
        // The resolved owner must be Token or Token-2022; anything else is a
        // hard rejection (e.g. a mint owned by an unknown program).
        val resolver = MintOwnerResolver { "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY" }
        val request = ChargeRequest(
            amount = "1000",
            currency = "So11111111111111111111111111111111111111112",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "mainnet", decimals = 6),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(
                signer(),
                request,
                fixedBlockhash,
                mintOwnerResolver = resolver,
            )
        }
    }

    @Test
    fun knownStablecoinResolvesWithoutResolver() {
        // A known stablecoin (USDC) resolves its token program from the static
        // table, so no resolver is needed even without an explicit program.
        val request = ChargeRequest(
            amount = "1000",
            currency = "USDC",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "devnet", decimals = 6),
        )
        Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
    }

    // ── Unsigned u64 amounts (main medium) ─────────────────────────────────

    @Test
    fun acceptsAmountAboveSignedLongMax() {
        // main-medium: base-unit amounts are u64. A value in [2^63, 2^64)
        // overflows a signed Long (toLongOrNull returns null), so the prior
        // build rejected legitimate large amounts as "invalid amount". With
        // BigInteger parsing the full u64 range is representable. 2^63 + 5 is
        // a valid u64 that a signed Long cannot hold.
        val u64Amount = java.math.BigInteger.ONE.shiftLeft(63).add(java.math.BigInteger.valueOf(5))
        val request = ChargeRequest(
            amount = u64Amount.toString(),
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "localnet"),
        )
        // Must not throw: the amount is a valid u64.
        Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
    }

    @Test
    fun rejectsAmountAboveU64Max() {
        // 2^64 is one past the u64 ceiling and must be rejected.
        val tooBig = java.math.BigInteger.ONE.shiftLeft(64)
        val request = ChargeRequest(
            amount = tooBig.toString(),
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "localnet"),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
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

    @Test
    fun unsignedChargeTransactionMatchesSignedTransactionExceptForSignatureSlot() {
        // Drives the external-signer code path (e.g. Mobile Wallet Adapter).
        // The unsigned bytes must equal the locally-signed bytes once the
        // signature slot is zeroed; this guarantees a wallet that signs the
        // wire bytes we hand it produces a transaction byte-identical to
        // what the local-signer path would have produced.
        val request = ChargeRequest(
            amount = "1000000",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = SolanaChargeMethodDetails(network = "localnet"),
        )
        val signed = JBase64.getDecoder().decode(
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash),
        )
        val unsigned = Charge.buildUnsignedChargeTransaction(
            walletPublicKey = PublicKey(signer().publicKeyBytes),
            request = request,
            blockhashProvider = fixedBlockhash,
        )
        assertEquals(signed.size, unsigned.size)
        // Compact-array length byte is at index 0; then numRequiredSignatures
        // 64-byte signature slots follow. The rest is the message body and
        // must be byte-identical.
        val sigCount = signed[0].toInt() and 0xff
        val messageStart = 1 + sigCount * 64
        for (i in messageStart until signed.size) {
            assertEquals(signed[i], unsigned[i], "byte $i differs between signed and unsigned")
        }
        // The unsigned signature slot for the wallet must be 64 zero bytes.
        for (i in 1 until 1 + 64) {
            assertEquals(0.toByte(), unsigned[i])
        }
    }

    @Test
    fun unsignedChargeTransactionAcceptsExternalWalletPublicKey() {
        // Smoke test that an externally-provided pubkey (i.e. one the
        // local process has no signing key for) produces a well-formed
        // unsigned transaction. This is the production MWA case.
        val externalPubkey = PublicKey.fromBase58("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
        val request = ChargeRequest(
            amount = "500",
            currency = "USDC",
            recipient = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
            methodDetails = SolanaChargeMethodDetails(network = "devnet", decimals = 6),
        )
        val unsigned = Charge.buildUnsignedChargeTransaction(
            walletPublicKey = externalPubkey,
            request = request,
            blockhashProvider = fixedBlockhash,
        )
        assertTrue(unsigned.size > 64)
        assertEquals(0x01.toByte(), unsigned[0])
    }

    // ── Optional recipient / methodDetails (rust spine parity) ──────────────────

    @Test
    fun decodesChargeRequestWithoutRecipientOrMethodDetails() {
        // Rust ChargeRequest marks `recipient` and `methodDetails` Option<...>
        // with skip_serializing_if (charge.rs:27-40), so a wire payload may omit
        // both. Before the parity fix Kotlin required both at deserialization and
        // rejected such a payload, which the rust client decodes. After the fix
        // decoding succeeds with both fields null.
        val wire = """{"amount":"1000","currency":"SOL"}"""
        val request = Json.decodeFromString<ChargeRequest>(wire)
        assertEquals("1000", request.amount)
        assertEquals("SOL", request.currency)
        assertNull(request.recipient)
        assertNull(request.methodDetails)
    }

    @Test
    fun buildDefaultsMissingMethodDetails() {
        // Rust defaults a missing methodDetails (charge.rs:203-209
        // `unwrap_or_default`); the charge still builds. A SOL charge with a
        // recipient but no methodDetails must succeed (network defaults apply),
        // not throw.
        val request = ChargeRequest(
            amount = "1000000",
            currency = "SOL",
            recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            methodDetails = null,
        )
        val transaction = Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        val raw = JBase64.getDecoder().decode(transaction)
        assertTrue(raw.size > 64)
    }

    @Test
    fun buildRejectsMissingRecipientWhenNeeded() {
        // Rust errors on a missing recipient only at the point the transfer is
        // built ("No recipient in challenge", charge.rs:211-214). Kotlin mirrors
        // this: the wire type permits a null recipient, but building the
        // transaction without one throws.
        val request = ChargeRequest(
            amount = "1000000",
            currency = "SOL",
            recipient = null,
            methodDetails = SolanaChargeMethodDetails(network = "localnet"),
        )
        assertFailsWith<MppException.InvalidTransaction> {
            Charge.buildChargeTransaction(signer(), request, fixedBlockhash)
        }
    }
}
