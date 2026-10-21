import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - Legacy x402 exact (v1) wire support
//
// Swift implements the x402 CLIENT side, so it covers the conformance
// `build-transaction` mode: parse a legacy 402 challenge, build the legacy
// `X-PAYMENT` envelope, and keep the canonical `PAYMENT-SIGNATURE` as the
// default producer. The shared conformance vectors
// (`harness/vectors/x402-v1-*.json`) are judged by `pkc run --sdk swift`
// against harness/expectations/swift.toml, not by a second copy here.
//
// Mirrors rust `build_payment_header_v1` (client/exact/payment.rs:153-170),
// `v1_network_for_requirements` (payment.rs:393-404), and the default
// producer `build_payment_header` (payment.rs:132-150).

private struct LegacyFixtures {
    static func makeSigner() throws -> MemorySigner {
        try MemorySigner(secretKey: Data(repeating: 0x01, count: 32))
    }

    static func makeRpc() -> RpcClient {
        MintFixtureURLProtocol.rpc()
    }

    static let knownBlockhash = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
}

// MARK: - Legacy producer unit tests

@Suite("x402 legacy producer")
struct X402LegacyProducerTests {
    static func devnetOffer() -> X402AcceptsEntry {
        let extra: [String: JSONValue] = [
            "feePayer": .string(x402TestFeePayer),
            "recentBlockhash": .string(LegacyFixtures.knownBlockhash),
            "decimals": .int(6),
        ]
        return X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "1000",
            maxAmountRequired: nil,
            asset: Mints.usdcDevnet,
            payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            recipient: nil,
            extra: extra,
            maxTimeoutSeconds: 60
        )
    }

    private func decode(_ header: String) throws -> [String: Any] {
        let data = Data(base64Encoded: header)!
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    @Test
    func legacyEnvelopeHasTopLevelSchemeNetworkAndNoAccepted() async throws {
        let header = try await buildX402LegacyPaymentHeader(
            signer: try LegacyFixtures.makeSigner(),
            rpc: LegacyFixtures.makeRpc(),
            offer: Self.devnetOffer()
        )
        let env = try decode(header)
        #expect(env["x402Version"] as? Int == 1)
        #expect(env["scheme"] as? String == "exact")
        #expect(env["network"] as? String == "solana-devnet")  // plain slug, not CAIP-2
        #expect(env["accepted"] == nil)  // legacy binds only scheme + network
        let payload = env["payload"] as? [String: Any]
        #expect((payload?["transaction"] as? String)?.isEmpty == false)
    }

    @Test
    func legacyHeaderIsStandardBase64NotUrlSafe() async throws {
        // A standard-base64 string round-trips through Data(base64Encoded:);
        // url-safe ('-'/'_') would not. Use a SOL offer (no ATA dependency).
        let extra: [String: JSONValue] = [
            "feePayer": .string(x402TestFeePayer),"recentBlockhash": .string(LegacyFixtures.knownBlockhash)]
        let offer = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.mainnet,
            amount: "1000", maxAmountRequired: nil,
            asset: "SOL", payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            recipient: nil, extra: extra
        )
        let header = try await buildX402LegacyPaymentHeader(
            signer: try LegacyFixtures.makeSigner(), rpc: LegacyFixtures.makeRpc(), offer: offer
        )
        #expect(Data(base64Encoded: header) != nil)
        #expect(!header.contains("-"))
        #expect(!header.contains("_"))
    }

    @Test
    func legacyNetworkSlugMaps() async throws {
        // mainnet CAIP-2 -> "solana"
        let mainnet = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.mainnet,
            amount: "1000", maxAmountRequired: nil,
            asset: "SOL", payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            recipient: nil,
            extra: ["feePayer": .string(x402TestFeePayer), "recentBlockhash": .string(LegacyFixtures.knownBlockhash)]
        )
        let mainnetHeader = try await buildX402LegacyPaymentHeader(
            signer: try LegacyFixtures.makeSigner(), rpc: LegacyFixtures.makeRpc(), offer: mainnet
        )
        #expect(try decode(mainnetHeader)["network"] as? String == "solana")

        // testnet collapses to "solana" on the producer side (rust parity).
        let testnet = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.testnet,
            amount: "1000", maxAmountRequired: nil,
            asset: "SOL", payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            recipient: nil,
            extra: ["feePayer": .string(x402TestFeePayer), "recentBlockhash": .string(LegacyFixtures.knownBlockhash)]
        )
        let testnetHeader = try await buildX402LegacyPaymentHeader(
            signer: try LegacyFixtures.makeSigner(), rpc: LegacyFixtures.makeRpc(), offer: testnet
        )
        #expect(try decode(testnetHeader)["network"] as? String == "solana")
    }

    @Test
    func challengeDispatcherKeepsCanonicalAsDefault() async throws {
        let offer = Self.devnetOffer()
        // nil declared version -> canonical PAYMENT-SIGNATURE, x402Version 2.
        let canonical = try await buildX402PaymentForChallenge(
            signer: try LegacyFixtures.makeSigner(), rpc: LegacyFixtures.makeRpc(),
            offer: offer, declaredVersion: nil
        )
        #expect(canonical.headerName == X402PaymentHeader)
        #expect(try decode(canonical.value)["x402Version"] as? Int == 2)
        #expect(try decode(canonical.value)["accepted"] != nil)
        #expect(try decode(canonical.value)["scheme"] == nil)

        // declared version 2 -> still canonical.
        let v2 = try await buildX402PaymentForChallenge(
            signer: try LegacyFixtures.makeSigner(), rpc: LegacyFixtures.makeRpc(),
            offer: offer, declaredVersion: 2
        )
        #expect(v2.headerName == X402PaymentHeader)

        // declared version 1 -> legacy X-PAYMENT.
        let legacy = try await buildX402PaymentForChallenge(
            signer: try LegacyFixtures.makeSigner(), rpc: LegacyFixtures.makeRpc(),
            offer: offer, declaredVersion: 1
        )
        #expect(legacy.headerName == X402LegacyPaymentHeader)
        #expect(try decode(legacy.value)["x402Version"] as? Int == 1)
    }
}

// MARK: - Legacy challenge parse (dual-read) unit tests

@Suite("x402 legacy challenge parse")
struct X402LegacyChallengeParseTests {
    @Test
    func parsesLegacyBodyWithPlainNetworkAndMaxAmountRequired() throws {
        // Legacy 402 body: plain network slug + maxAmountRequired + x402Version 1.
        let body = """
        {
            "x402Version": 1,
            "error": "X-PAYMENT header is required",
            "accepts": [{
                "scheme": "exact",
                "extra": {"feePayer": "\(x402TestFeePayer)"},
                "network": "solana-devnet",
                "maxAmountRequired": "1000",
                "asset": "\(Mints.usdcDevnet)",
                "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                "maxTimeoutSeconds": 60
            }]
        }
        """
        let parsed = parseX402ChallengeWithVersion(headers: [], body: body)
        #expect(parsed != nil)
        #expect(parsed?.declaredVersion == 1)
        #expect(parsed?.offer.network == "solana-devnet")
        #expect(parsed?.offer.effectiveAmount == "1000")
        #expect(parsed?.offer.effectiveAsset == Mints.usdcDevnet)
    }

    @Test
    func legacyBodyWithPlainNetworkSelectsOnPreferredCluster() throws {
        // The plain `solana-devnet` slug must normalize to the devnet CAIP-2
        // when matched against a devnet preference.
        let body = """
        {
            "x402Version": 1,
            "accepts": [{
                "scheme": "exact",
                "extra": {"feePayer": "\(x402TestFeePayer)"},
                "network": "solana-devnet",
                "maxAmountRequired": "1000",
                "asset": "\(Mints.usdcDevnet)",
                "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
            }]
        }
        """
        let selection = X402ChallengeSelection(network: "devnet", currencies: ["USDC"])
        let parsed = parseX402ChallengeWithVersion(headers: [], body: body, selection: selection)
        #expect(parsed?.offer.asset == Mints.usdcDevnet)
    }

    @Test
    func readsCanonicalHeaderBeforeLegacyHeaderBeforeBody() throws {
        let net = SolanaNetwork.devnet
        // Canonical PAYMENT-REQUIRED header (v2) wins over everything.
        let canonicalEnv = "{\"x402Version\":2,\"accepts\":[{\"scheme\":\"exact\",\"network\":\"\(net)\",\"amount\":\"100\",\"asset\":\"SOL\",\"payTo\":\"from-canonical\",\"extra\":{\"feePayer\":\"\(x402TestFeePayer)\"}}]}"
        let legacyEnv = "{\"x402Version\":1,\"accepts\":[{\"scheme\":\"exact\",\"network\":\"solana-devnet\",\"maxAmountRequired\":\"200\",\"asset\":\"SOL\",\"payTo\":\"from-legacy-header\",\"extra\":{\"feePayer\":\"\(x402TestFeePayer)\"}}]}"
        let body = "{\"x402Version\":1,\"accepts\":[{\"scheme\":\"exact\",\"network\":\"solana-devnet\",\"maxAmountRequired\":\"300\",\"asset\":\"SOL\",\"payTo\":\"from-body\",\"extra\":{\"feePayer\":\"\(x402TestFeePayer)\"}}]}"

        let headers = [
            (name: "PAYMENT-REQUIRED", value: Data(canonicalEnv.utf8).base64EncodedString()),
            (name: "X-PAYMENT-REQUIRED", value: Data(legacyEnv.utf8).base64EncodedString()),
        ]
        let viaCanonical = parseX402ChallengeWithVersion(headers: headers, body: body)
        #expect(viaCanonical?.offer.effectivePayTo == "from-canonical")
        #expect(viaCanonical?.declaredVersion == 2)

        // Without the canonical header, the legacy X-PAYMENT-REQUIRED header
        // wins over the body.
        let legacyHeaders = [
            (name: "X-PAYMENT-REQUIRED", value: Data(legacyEnv.utf8).base64EncodedString()),
        ]
        let viaLegacyHeader = parseX402ChallengeWithVersion(headers: legacyHeaders, body: body)
        #expect(viaLegacyHeader?.offer.effectivePayTo == "from-legacy-header")
        #expect(viaLegacyHeader?.declaredVersion == 1)

        // With no headers, the body is the fallback.
        let viaBody = parseX402ChallengeWithVersion(headers: [], body: body)
        #expect(viaBody?.offer.effectivePayTo == "from-body")
        #expect(viaBody?.declaredVersion == 1)
    }

    @Test
    func roundTripsLegacyChallengeIntoLegacyPayment() async throws {
        // End-to-end client flow: parse a legacy body, then emit the version
        // it declared. The reply must be the legacy X-PAYMENT envelope.
        let body = """
        {
            "x402Version": 1,
            "accepts": [{
                "scheme": "exact",
                "network": "solana-devnet",
                "maxAmountRequired": "1000",
                "asset": "\(Mints.usdcDevnet)",
                "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                "extra": { "feePayer": "\(x402TestFeePayer)", "recentBlockhash": "\(LegacyFixtures.knownBlockhash)", "decimals": 6 }
            }]
        }
        """
        let parsed = parseX402ChallengeWithVersion(headers: [], body: body)
        #expect(parsed?.declaredVersion == 1)

        let payment = try await buildX402PaymentForChallenge(
            signer: try LegacyFixtures.makeSigner(),
            rpc: LegacyFixtures.makeRpc(),
            offer: parsed!.offer,
            declaredVersion: parsed!.declaredVersion
        )
        #expect(payment.headerName == X402LegacyPaymentHeader)
        let env = try JSONSerialization.jsonObject(
            with: Data(base64Encoded: payment.value)!
        ) as! [String: Any]
        #expect(env["x402Version"] as? Int == 1)
        #expect(env["network"] as? String == "solana-devnet")
        #expect(env["accepted"] == nil)
    }
}

// MARK: - Legacy network slug mapping unit tests

@Suite("SolanaNetwork legacy slugs")
struct SolanaNetworkLegacySlugTests {
    @Test
    func legacySlugMapping() {
        #expect(SolanaNetwork.legacySlug(for: SolanaNetwork.mainnet) == "solana")
        #expect(SolanaNetwork.legacySlug(for: SolanaNetwork.devnet) == "solana-devnet")
        #expect(SolanaNetwork.legacySlug(for: SolanaNetwork.testnet) == "solana")  // collapses
        #expect(SolanaNetwork.legacySlug(for: "devnet") == "solana-devnet")
        #expect(SolanaNetwork.legacySlug(for: "solana-devnet") == "solana-devnet")
        #expect(SolanaNetwork.legacySlug(for: "mainnet") == "solana")
        #expect(SolanaNetwork.legacySlug(for: "solana") == "solana")
    }

    @Test
    func isSolanaNetworkRecognizesCaip2AndPlainSlugs() {
        #expect(SolanaNetwork.isSolanaNetwork(SolanaNetwork.mainnet))
        #expect(SolanaNetwork.isSolanaNetwork(SolanaNetwork.devnet))
        #expect(SolanaNetwork.isSolanaNetwork(SolanaNetwork.testnet))
        #expect(SolanaNetwork.isSolanaNetwork("solana"))
        #expect(SolanaNetwork.isSolanaNetwork("solana-devnet"))
        #expect(SolanaNetwork.isSolanaNetwork("solana-testnet"))
        #expect(SolanaNetwork.isSolanaNetwork("mainnet-beta"))
        #expect(!SolanaNetwork.isSolanaNetwork("ethereum:1"))
        #expect(!SolanaNetwork.isSolanaNetwork("base"))
    }
}
