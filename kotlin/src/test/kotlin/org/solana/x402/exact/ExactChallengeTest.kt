package org.solana.x402.exact

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ExactChallengeTest {
    @Test
    fun `SolanaNetwork mainnet CAIP-2 matches Rust spine SOLANA_MAINNET constant`() {
        // Regression: previous tip shipped the 44-char full base58 genesis hash,
        // which broke interop with every spine-compliant mainnet challenge. The
        // Rust spine constant lives at
        // rust/crates/x402/src/protocol/schemes/exact/types.rs (SOLANA_MAINNET).
        assertEquals(
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            SolanaNetwork.Mainnet.caip2,
        )
        assertEquals(32, SolanaNetwork.Mainnet.caip2.removePrefix("solana:").length)
        assertEquals(
            SolanaNetwork.Mainnet,
            SolanaNetwork.fromIdentifierOrNull("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
        )
    }

    @Test
    fun `selects Solana exact requirement from PAYMENT-REQUIRED header`() {
        val envelope = """
            {
              "accepts": [
                {
                  "scheme": "exact",
                  "network": "eip155:8453",
                  "asset": "0x0000000000000000000000000000000000000000",
                  "amount": "1000"
                },
                {
                  "scheme": "exact",
                  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                  "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                  "amount": "1000",
                  "payTo": "5T388jBjovy7d8mQ3emHxMDTbUF8b7nWvAnSiP3EAdFL",
                  "extra": { "feePayer": "HoCy8p5xxDDYTYWEbQZasEjVNM5rxvidx8AfyqA4ywBa" }
                }
              ],
              "resource": {
                "url": "http://127.0.0.1:3000/protected",
                "description": "fixture"
              }
            }
        """.trimIndent()
        val header = Base64.getEncoder().encodeToString(envelope.toByteArray(Charsets.UTF_8))

        val selected = ExactChallenge.selectSvmChallenge(
            headers = mapOf("PAYMENT-REQUIRED" to header),
            body = null,
        )

        assertNotNull(selected)
        assertEquals("exact", selected.requirement.scheme)
        assertEquals(ExactChallenge.DEFAULT_NETWORK, selected.requirement.network)
        assertEquals("1000", selected.requirement.amount)
        assertEquals("http://127.0.0.1:3000/protected", selected.resource?.url)
    }

    @Test
    fun `prefers requested stablecoin by symbol or mint`() {
        val body = """
            {
              "accepts": [
                {
                  "scheme": "exact",
                  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                  "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                  "amount": "1000"
                },
                {
                  "scheme": "exact",
                  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                  "asset": "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
                  "amount": "1000"
                }
              ]
            }
        """.trimIndent()

        val selected = ExactChallenge.selectSvmChallenge(
            headers = emptyMap(),
            body = body,
            preferredCurrencies = listOf("PYUSD", "USDC"),
        )

        assertNotNull(selected)
        assertEquals("CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM", selected.requirement.asset)
    }

    @Test
    fun `rejects network mismatch before payment construction`() {
        val body = """
            {
              "accepts": [
                {
                  "scheme": "exact",
                  "network": "solana:not-a-real-cluster",
                  "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                  "amount": "1000"
                }
              ]
            }
        """.trimIndent()

        val selected = ExactChallenge.selectSvmChallenge(headers = emptyMap(), body = body)

        assertNull(selected)
    }

    @Test
    fun `stablecoinMint resolves USDC per network without mainnet leak`() {
        val mainnetUsdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        val devnetUsdc = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

        // Typed (sealed-class) resolver — the source of truth.
        assertEquals(mainnetUsdc, ExactChallenge.stablecoinMint("USDC", SolanaNetwork.Mainnet))
        assertEquals(devnetUsdc, ExactChallenge.stablecoinMint("USDC", SolanaNetwork.Devnet))
        assertEquals(devnetUsdc, ExactChallenge.stablecoinMint("USDC", SolanaNetwork.Localnet))
        assertNotEquals(mainnetUsdc, ExactChallenge.stablecoinMint("USDC", SolanaNetwork.Devnet))
        assertNotEquals(mainnetUsdc, ExactChallenge.stablecoinMint("USDC", SolanaNetwork.Localnet))

        // String shim — all canonical aliases route correctly.
        assertEquals(devnetUsdc, ExactChallenge.stablecoinMint("USDC", "devnet"))
        assertEquals(devnetUsdc, ExactChallenge.stablecoinMint("USDC", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"))
        assertEquals(devnetUsdc, ExactChallenge.stablecoinMint("USDC", "localnet"))
        assertEquals(mainnetUsdc, ExactChallenge.stablecoinMint("USDC", "mainnet-beta"))
        // Aligned to Rust spine SOLANA_MAINNET constant (32-char canonical prefix).
        assertEquals(mainnetUsdc, ExactChallenge.stablecoinMint("USDC", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"))
    }

    @Test
    fun `stablecoinMint fails closed on unknown network for known symbol`() {
        // Money-loss bug regression: passing an unrecognised network must NOT
        // silently produce a mainnet mint address for a known stablecoin symbol.
        val error = assertFailsWith<IllegalArgumentException> {
            ExactChallenge.stablecoinMint("USDC", "solana:not-a-real-cluster")
        }
        assertEquals(
            true,
            error.message?.contains("unknown network", ignoreCase = true) == true,
            "expected fail-closed error, got: ${error.message}",
        )
    }

    @Test
    fun `stablecoinMint passes through unknown asset on unknown network`() {
        // A caller may hand us a raw mint address as the "currency" — that's
        // not a known symbol, so we should echo it back rather than throw.
        val mint = "SomeArbitraryMintAddress1111111111111111111"
        assertEquals(mint, ExactChallenge.stablecoinMint(mint, "solana:not-a-real-cluster"))
    }

    @Test
    fun `currencyMatches_returns_false_when_network_is_unrecognized`() {
        // currencyMatches is private; exercise it via selectSvmChallenge with a
        // single candidate whose network is unrecognised. The preference loop
        // must treat the unresolvable pair as "not a match" instead of letting
        // the underlying IllegalArgumentException escape and break selection.
        val body = """
            {
              "accepts": [
                {
                  "scheme": "exact",
                  "network": "solana:not-a-real-cluster",
                  "asset": "SomeArbitraryMintAddress1111111111111111111",
                  "amount": "1000"
                }
              ]
            }
        """.trimIndent()

        val selected = ExactChallenge.selectSvmChallenge(
            headers = emptyMap(),
            body = body,
            network = "solana:not-a-real-cluster",
            preferredCurrencies = listOf("USDC"),
        )

        // The candidate matched scheme + network filters but does not satisfy
        // the USDC preference under an unresolvable network — no throw, no match.
        assertNull(selected)
    }

    @Test
    fun `selectSvmChallenge_returns_null_for_unrecognized_network_with_stablecoin_preference`() {
        // Regression: previously an unrecognised network + a stablecoin symbol
        // preference threw IllegalArgumentException out of selectSvmChallenge,
        // breaking the entire challenge-selection loop. Must return null instead.
        val body = """
            {
              "accepts": [
                {
                  "scheme": "exact",
                  "network": "solana:not-a-real-cluster",
                  "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                  "amount": "1000"
                }
              ]
            }
        """.trimIndent()

        // No throw — just a null selection.
        val selected = ExactChallenge.selectSvmChallenge(
            headers = emptyMap(),
            body = body,
            network = "solana:not-a-real-cluster",
            preferredCurrencies = listOf("PYUSD"),
        )

        assertNull(selected)
    }

    @Test
    fun `stablecoinMint resolves PYUSD and USDG per network`() {
        assertEquals(
            "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
            ExactChallenge.stablecoinMint("PYUSD", SolanaNetwork.Mainnet),
        )
        assertEquals(
            "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
            ExactChallenge.stablecoinMint("PYUSD", SolanaNetwork.Devnet),
        )
        assertEquals(
            "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH",
            ExactChallenge.stablecoinMint("USDG", SolanaNetwork.Mainnet),
        )
        assertEquals(
            "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
            ExactChallenge.stablecoinMint("USDG", SolanaNetwork.Devnet),
        )
    }

    @Test
    fun `accepts canonical maxAmountRequired field when amount is absent`() {
        // Regression: prior tip read only `amount`, which silently dropped every
        // spine-shaped challenge that uses the canonical `maxAmountRequired`
        // wire field (TS fixture, Rust spine output, Go/Python/PHP ports).
        // Rust spine fallback lives at
        // rust/crates/x402/src/protocol/schemes/exact/types.rs.
        val body = """
            {
              "accepts": [
                {
                  "scheme": "exact",
                  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                  "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                  "maxAmountRequired": "1500",
                  "payTo": "5T388jBjovy7d8mQ3emHxMDTbUF8b7nWvAnSiP3EAdFL",
                  "extra": { "feePayer": "HoCy8p5xxDDYTYWEbQZasEjVNM5rxvidx8AfyqA4ywBa" }
                }
              ]
            }
        """.trimIndent()

        val selected = ExactChallenge.selectSvmChallenge(
            headers = emptyMap(),
            body = body,
        )

        assertNotNull(selected)
        assertEquals("exact", selected.requirement.scheme)
        assertEquals("1500", selected.requirement.amount)
    }

    @Test
    fun `prefers amount over maxAmountRequired when both are present`() {
        // When a challenge carries both fields, `amount` wins to preserve
        // back-compat with adapters that emit both for transitional reasons.
        val body = """
            {
              "accepts": [
                {
                  "scheme": "exact",
                  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                  "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                  "amount": "1000",
                  "maxAmountRequired": "9999"
                }
              ]
            }
        """.trimIndent()

        val selected = ExactChallenge.selectSvmChallenge(
            headers = emptyMap(),
            body = body,
        )

        assertNotNull(selected)
        assertEquals("1000", selected.requirement.amount)
    }

    @Test
    fun `skips native SOL offers and prefers SPL candidate`() {
        // Rust spine `rust/crates/x402/src/client/exact/payment.rs` supports
        // native SOL via System Program transfer. This Kotlin client is
        // SPL-only; selection must skip `asset: "SOL"` offers rather than
        // crash later at Base58.decode("SOL") inside the builder.
        val body = """
            {
              "accepts": [
                {
                  "scheme": "exact",
                  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                  "asset": "SOL",
                  "amount": "1000",
                  "payTo": "5T388jBjovy7d8mQ3emHxMDTbUF8b7nWvAnSiP3EAdFL"
                },
                {
                  "scheme": "exact",
                  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                  "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                  "amount": "2000",
                  "payTo": "5T388jBjovy7d8mQ3emHxMDTbUF8b7nWvAnSiP3EAdFL",
                  "extra": { "feePayer": "HoCy8p5xxDDYTYWEbQZasEjVNM5rxvidx8AfyqA4ywBa" }
                }
              ]
            }
        """.trimIndent()

        val selected = ExactChallenge.selectSvmChallenge(
            headers = emptyMap(),
            body = body,
        )

        assertNotNull(selected)
        assertEquals(
            "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            selected.requirement.asset,
        )
    }

    @Test
    fun `returns null when only native SOL offer is available`() {
        val body = """
            {
              "accepts": [
                {
                  "scheme": "exact",
                  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                  "asset": "SOL",
                  "amount": "1000",
                  "payTo": "5T388jBjovy7d8mQ3emHxMDTbUF8b7nWvAnSiP3EAdFL"
                }
              ]
            }
        """.trimIndent()

        val selected = ExactChallenge.selectSvmChallenge(
            headers = emptyMap(),
            body = body,
        )

        assertNull(selected)
    }
}

