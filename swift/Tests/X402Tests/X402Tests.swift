import Foundation
import Testing
@testable import X402
#if canImport(CryptoKit)
import CryptoKit
#endif

private struct FixedSigner: SolanaSigner {
    let address: SolanaPublicKey
    let signature: Data

    func sign(message: Data) async throws -> Data {
        signature
    }
}

private struct FixedBlockhashProvider: RecentBlockhashProvider {
    let blockhash: String
    func getLatestBlockhash() async throws -> String { blockhash }
}

private struct FixedATAResolver: AssociatedTokenAddressResolver {
    let source: SolanaPublicKey
    let destination: SolanaPublicKey

    func associatedTokenAddress(owner: SolanaPublicKey, mint: SolanaPublicKey, tokenProgram: SolanaPublicKey) throws -> SolanaPublicKey {
        owner.base58 == "11111111111111111111111111111112" ? source : destination
    }
}

@Test func ed25519CurveCheckAcceptsBasepointAndRejectsNonCanonicalY() throws {
    let basepoint = try Data(hex: "5866666666666666666666666666666666666666666666666666666666666666")
    #expect(Ed25519CompressedPoint.isOnCurve(basepoint))

    // y = p = 2^255 - 19, the smallest non-canonical y-coordinate encoding.
    // Little-endian: 0xed, 30×0xff, 0x7f (sign bit clear). Exactly 32 bytes.
    let fieldModulus = try Data(hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    #expect(fieldModulus.count == 32)
    #expect(!Ed25519CompressedPoint.isOnCurve(fieldModulus))

    // y = p + 1, also >= p and therefore non-canonical.
    let fieldModulusPlusOne = try Data(hex: "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    #expect(fieldModulusPlusOne.count == 32)
    #expect(!Ed25519CompressedPoint.isOnCurve(fieldModulusPlusOne))
}

@Test func challengeRejectsInvalidDecimalsAndDefaultsWhenAbsent() throws {
    // Out-of-range decimals must throw, not crash via UInt8(value) trap.
    let bad = PaymentRequirement(
        scheme: "exact",
        network: X402.solanaDevnet,
        amount: "1000",
        asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        payTo: "11111111111111111111111111111115",
        maxTimeoutSeconds: nil,
        extra: ["decimals": .number(999)]
    )
    #expect(throws: X402Error.self) {
        _ = try bad.decimals()
    }

    let fractional = PaymentRequirement(
        scheme: "exact",
        network: X402.solanaDevnet,
        amount: "1000",
        asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        payTo: "11111111111111111111111111111115",
        maxTimeoutSeconds: nil,
        extra: ["decimals": .number(6.5)]
    )
    #expect(throws: X402Error.self) {
        _ = try fractional.decimals()
    }

    let negative = PaymentRequirement(
        scheme: "exact",
        network: X402.solanaDevnet,
        amount: "1000",
        asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        payTo: "11111111111111111111111111111115",
        maxTimeoutSeconds: nil,
        extra: ["decimals": .number(-1)]
    )
    #expect(throws: X402Error.self) {
        _ = try negative.decimals()
    }

    let absent = PaymentRequirement(
        scheme: "exact",
        network: X402.solanaDevnet,
        amount: "1000",
        asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        payTo: "11111111111111111111111111111115",
        maxTimeoutSeconds: nil,
        extra: nil
    )
    #expect(try absent.decimals() == 6)
}

@Test func defaultATAResolverDerivesCanonicalAssociatedTokenAccounts() throws {
    let resolver = DefaultAssociatedTokenAddressResolver()
    let mint = try SolanaPublicKey("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
    let tokenProgram = try SolanaPublicKey(X402.tokenProgram)

    let source = try resolver.associatedTokenAddress(
        owner: try SolanaPublicKey("11111111111111111111111111111112"),
        mint: mint,
        tokenProgram: tokenProgram
    )
    let destination = try resolver.associatedTokenAddress(
        owner: try SolanaPublicKey("11111111111111111111111111111115"),
        mint: mint,
        tokenProgram: tokenProgram
    )

    #expect(source.base58 == "4tRapEGgJZKuGoeeMRrpHsxAEuvo5YnDCzTXykqDhrK9")
    #expect(destination.base58 == "CFGbKktYnf4cVvvkVYXPCFfHKq6TE7zc9XdBKxqS5P4q")
}

@Test func parsesSolanaExactChallengeFromBody() throws {
    let json = """
    {"x402Version":2,"accepts":[
      {"scheme":"exact","network":"eip155:8453","amount":"1000","asset":"0x0","payTo":"0x0"},
      {"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","amount":"1000","asset":"4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6}}
    ]}
    """
    let parsed = try parseX402Challenge(headers: [:], body: Data(json.utf8), selection: ChallengeSelection(network: "devnet"))
    let requirement = try #require(parsed)
    #expect(requirement.network == X402.solanaDevnet)
    #expect(requirement.asset == "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
    #expect(requirement.feePayer == "11111111111111111111111111111111")
}

@Test func buildsBase64PaymentHeaderWithInjectedSignerAndBlockhash() async throws {
    let signer = FixedSigner(
        address: try SolanaPublicKey("11111111111111111111111111111112"),
        signature: Data(repeating: 7, count: 64)
    )
    let builder = ExactTransactionBuilder(
        signer: signer,
        blockhashProvider: FixedBlockhashProvider(blockhash: "11111111111111111111111111111111"),
        ataResolver: FixedATAResolver(
            source: try SolanaPublicKey("11111111111111111111111111111113"),
            destination: try SolanaPublicKey("11111111111111111111111111111114")
        )
    )
    let requirement = PaymentRequirement(
        scheme: "exact",
        network: X402.solanaDevnet,
        amount: "1000",
        asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        payTo: "11111111111111111111111111111115",
        maxTimeoutSeconds: 300,
        extra: [
            "feePayer": .string("11111111111111111111111111111111"),
            "decimals": .number(6),
            "memo": .string("x402-swift-test"),
        ]
    )
    let header = try await builder.buildPaymentHeader(for: requirement)
    let decoded = try #require(Data(base64Encoded: header))
    let object = try #require(JSONSerialization.jsonObject(with: decoded) as? [String: Any])
    #expect(object["x402Version"] as? Int == 2)
    let payload = try #require(object["payload"] as? [String: Any])
    let tx = try #require(payload["transaction"] as? String)
    #expect(Data(base64Encoded: tx) != nil)
}

@Test func buildsPaymentHeaderWithDefaultATAResolver() async throws {
    let signer = FixedSigner(
        address: try SolanaPublicKey("11111111111111111111111111111112"),
        signature: Data(repeating: 9, count: 64)
    )
    let builder = ExactTransactionBuilder(
        signer: signer,
        blockhashProvider: FixedBlockhashProvider(blockhash: "11111111111111111111111111111111")
    )
    let requirement = PaymentRequirement(
        scheme: "exact",
        network: X402.solanaDevnet,
        amount: "1000",
        asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        payTo: "11111111111111111111111111111115",
        maxTimeoutSeconds: 300,
        extra: [
            "feePayer": .string("11111111111111111111111111111111"),
            "decimals": .number(6),
            "memo": .string("x402-swift-default-ata-test"),
        ]
    )

    let header = try await builder.buildPaymentHeader(for: requirement)
    let decoded = try #require(Data(base64Encoded: header))
    let object = try #require(JSONSerialization.jsonObject(with: decoded) as? [String: Any])
    let payload = try #require(object["payload"] as? [String: Any])
    let tx = try #require(payload["transaction"] as? String)
    #expect(Data(base64Encoded: tx) != nil)
}

#if canImport(CryptoKit)
@Test func memorySignerRejectsMismatchedEmbeddedPublicKey() throws {
    let privateKey = Curve25519.Signing.PrivateKey()
    let seed = [UInt8](privateKey.rawRepresentation)
    let derivedPublic = [UInt8](privateKey.publicKey.rawRepresentation)
    // Valid 64-byte construction first: must succeed.
    let valid = try MemorySolanaSigner(secretKey: seed + derivedPublic)
    #expect(valid.address.bytes.count == 32)

    // Now tamper the embedded public-key suffix: signer construction MUST reject.
    var tampered = derivedPublic
    tampered[0] ^= 0x01
    #expect(throws: X402Error.self) {
        _ = try MemorySolanaSigner(secretKey: seed + tampered)
    }
}
#endif

@Test func challengeRejectsUnsupportedTokenProgram() throws {
    // A malicious server tries to pin extra.tokenProgram to an arbitrary executable
    // program. The challenge parser must reject the whole envelope so the client
    // never even reaches the transaction builder.
    let json = """
    {"x402Version":2,"accepts":[
      {"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","amount":"1000","asset":"4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6,"tokenProgram":"EvilProgram11111111111111111111111111111111"}}
    ]}
    """
    #expect(throws: X402Error.unsupportedTokenProgram("EvilProgram11111111111111111111111111111111")) {
        _ = try parseX402Challenge(headers: [:], body: Data(json.utf8), selection: ChallengeSelection(network: "devnet"))
    }
}

@Test func acceptsSplTokenProgram() throws {
    let json = """
    {"x402Version":2,"accepts":[
      {"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","amount":"1000","asset":"4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6,"tokenProgram":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}}
    ]}
    """
    let parsed = try parseX402Challenge(headers: [:], body: Data(json.utf8), selection: ChallengeSelection(network: "devnet"))
    let requirement = try #require(parsed)
    #expect(try requirement.validatedTokenProgram() == X402.tokenProgram)
}

@Test func acceptsToken2022Program() throws {
    let json = """
    {"x402Version":2,"accepts":[
      {"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","amount":"1000","asset":"4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6,"tokenProgram":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}}
    ]}
    """
    let parsed = try parseX402Challenge(headers: [:], body: Data(json.utf8), selection: ChallengeSelection(network: "devnet"))
    let requirement = try #require(parsed)
    #expect(try requirement.validatedTokenProgram() == X402.token2022Program)
}

@Test func transactionBuilderRejectsUnsupportedTokenProgram() async throws {
    // Independent layer: even when a caller bypasses parseX402Challenge and
    // hand-constructs a PaymentRequirement, the builder MUST refuse to sign
    // for any tokenProgram outside the canonical SPL allowlist.
    let signer = FixedSigner(
        address: try SolanaPublicKey("11111111111111111111111111111112"),
        signature: Data(repeating: 7, count: 64)
    )
    let builder = ExactTransactionBuilder(
        signer: signer,
        blockhashProvider: FixedBlockhashProvider(blockhash: "11111111111111111111111111111111"),
        ataResolver: FixedATAResolver(
            source: try SolanaPublicKey("11111111111111111111111111111113"),
            destination: try SolanaPublicKey("11111111111111111111111111111114")
        )
    )
    let requirement = PaymentRequirement(
        scheme: "exact",
        network: X402.solanaDevnet,
        amount: "1000",
        asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        payTo: "11111111111111111111111111111115",
        maxTimeoutSeconds: 300,
        extra: [
            "feePayer": .string("11111111111111111111111111111111"),
            "decimals": .number(6),
            "tokenProgram": .string("EvilProgram11111111111111111111111111111111"),
        ]
    )
    await #expect(throws: X402Error.unsupportedTokenProgram("EvilProgram11111111111111111111111111111111")) {
        _ = try await builder.buildTransaction(for: requirement)
    }
}

private let multiCurrencyEnvelopeDevnet = """
{"x402Version":2,"accepts":[
  {"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","amount":"1000","asset":"4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6}},
  {"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","amount":"2000","asset":"CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6,"tokenProgram":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}}
]}
"""

private let multiCurrencyEnvelopeMainnet = """
{"x402Version":2,"accepts":[
  {"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"1000","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6}},
  {"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"2000","asset":"2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6,"tokenProgram":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}},
  {"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"3000","asset":"2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6,"tokenProgram":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}}
]}
"""

@Test func selectChallengePicksPyusdWhenPreferred() throws {
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(multiCurrencyEnvelopeDevnet.utf8),
        selection: ChallengeSelection(network: "devnet", currencies: ["PYUSD", "USDC"])
    )
    let requirement = try #require(parsed)
    #expect(requirement.asset == "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM")
}

@Test func selectChallengePicksUsdcWhenPreferred() throws {
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(multiCurrencyEnvelopeDevnet.utf8),
        selection: ChallengeSelection(network: "devnet", currencies: ["USDC", "PYUSD"])
    )
    let requirement = try #require(parsed)
    #expect(requirement.asset == "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
}

@Test func selectChallengeMatchesPyusdMintByDevnet() throws {
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(multiCurrencyEnvelopeDevnet.utf8),
        selection: ChallengeSelection(network: "devnet", currencies: ["PYUSD"])
    )
    let requirement = try #require(parsed)
    #expect(requirement.network == X402.solanaDevnet)
    #expect(requirement.asset == "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM")
}

@Test func selectChallengeMatchesPyusdMintByMainnet() throws {
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(multiCurrencyEnvelopeMainnet.utf8),
        selection: ChallengeSelection(network: "mainnet", currencies: ["PYUSD"])
    )
    let requirement = try #require(parsed)
    #expect(requirement.network == X402.solanaMainnet)
    #expect(requirement.asset == "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo")
}

@Test func selectChallengeMatchesUsdgMintByMainnet() throws {
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(multiCurrencyEnvelopeMainnet.utf8),
        selection: ChallengeSelection(network: "mainnet", currencies: ["USDG"])
    )
    let requirement = try #require(parsed)
    #expect(requirement.network == X402.solanaMainnet)
    #expect(requirement.asset == "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH")
}

private let mainnetOnlyPyusdEnvelope = """
{"x402Version":2,"accepts":[
  {"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"1000","asset":"2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6}}
]}
"""

private let bothNetworksPyusdEnvelope = """
{"x402Version":2,"accepts":[
  {"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"1000","asset":"2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6}},
  {"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","amount":"2000","asset":"CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6}}
]}
"""

@Test func selectRequirementRejectsMainnetOfferWhenDevnetRequested() throws {
    // SECURITY: the server only advertises a mainnet PYUSD offer, but the client
    // explicitly pinned `network = devnet`. The selector MUST fail closed rather
    // than silently widening to the mainnet offer (which would cause the client
    // to sign and broadcast a real-funds transaction on the wrong network).
    #expect(throws: X402Error.unsupportedNetwork(X402.solanaDevnet)) {
        _ = try parseX402Challenge(
            headers: [:],
            body: Data(mainnetOnlyPyusdEnvelope.utf8),
            selection: ChallengeSelection(network: "devnet")
        )
    }
}

@Test func selectRequirementUsesMainnetOnDefaultSelection() throws {
    // No network specified — the default mainnet preference is itself a soft
    // default, so widening is acceptable and behavior is preserved.
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(mainnetOnlyPyusdEnvelope.utf8),
        selection: ChallengeSelection()
    )
    let requirement = try #require(parsed)
    #expect(requirement.network == X402.solanaMainnet)
    #expect(requirement.asset == "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo")
}

@Test func selectRequirementMatchesDevnetWhenServerOffersBoth() throws {
    // Server advertises both networks; client pins devnet — must pick devnet.
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(bothNetworksPyusdEnvelope.utf8),
        selection: ChallengeSelection(network: "devnet")
    )
    let requirement = try #require(parsed)
    #expect(requirement.network == X402.solanaDevnet)
    #expect(requirement.asset == "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM")
}

@Test func challengeAcceptsCanonicalMaxAmountRequiredField() throws {
    // Regression: prior tip read only `amount`, which silently dropped every
    // spine-shaped challenge that uses the canonical `maxAmountRequired`
    // wire field (TS fixture, Rust spine output, Go/Kotlin/PHP ports).
    // Rust spine fallback lives at
    // rust/crates/x402/src/protocol/schemes/exact/types.rs.
    let json = """
    {"x402Version":2,"accepts":[
      {"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","maxAmountRequired":"1500","asset":"4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6}}
    ]}
    """
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(json.utf8),
        selection: ChallengeSelection(network: "devnet")
    )
    let requirement = try #require(parsed)
    #expect(requirement.amount == "1500")
    #expect(requirement.scheme == "exact")
}

@Test func challengePrefersAmountOverMaxAmountRequiredWhenBothPresent() throws {
    // When a challenge carries both fields, `amount` wins to preserve
    // back-compat with adapters that emit both for transitional reasons.
    let json = """
    {"x402Version":2,"accepts":[
      {"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","amount":"1000","maxAmountRequired":"9999","asset":"4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU","payTo":"11111111111111111111111111111111","extra":{"feePayer":"11111111111111111111111111111111","decimals":6}}
    ]}
    """
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(json.utf8),
        selection: ChallengeSelection(network: "devnet")
    )
    let requirement = try #require(parsed)
    #expect(requirement.amount == "1000")
}

@Test func currencyMatchesRejectsUnknownSymbol() throws {
    // Preferences contain only an unknown symbol — selector must return nil
    // rather than silently falling through to a different stablecoin.
    let parsed = try parseX402Challenge(
        headers: [:],
        body: Data(multiCurrencyEnvelopeDevnet.utf8),
        selection: ChallengeSelection(network: "devnet", currencies: ["BOGUS"])
    )
    #expect(parsed == nil)
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else {
            throw X402Error.invalidBase58(hex)
        }

        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw X402Error.invalidBase58(hex)
            }
            bytes.append(byte)
            index = next
        }
        self = Data(bytes)
    }
}
