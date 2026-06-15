import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - x402 challenge parsing tests

@Suite("x402 challenge parsing")
struct X402ChallengeParsingTests {
    // MARK: - Header parsing

    @Test
    func parsesPaymentRequiredHeader() throws {
        let net = SolanaNetwork.devnet
        let envelope = """
        {
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": "\(net)",
                "amount": "1000",
                "asset": "\(Mints.usdcDevnet)",
                "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                "extra": {
                    "recentBlockhash": "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
                    "decimals": 6
                }
            }]
        }
        """
        let encoded = Data(envelope.utf8).base64EncodedString()
        let headers = [(name: "PAYMENT-REQUIRED", value: encoded)]
        let offer = parseX402Challenge(headers: headers, body: nil)
        #expect(offer != nil)
        #expect(offer?.effectiveAmount == "1000")
        #expect(offer?.asset == Mints.usdcDevnet)
    }

    @Test
    func parsesBodyFallback() throws {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [{
                "scheme": "exact",
                "network": "\(net)",
                "maxAmountRequired": "5000",
                "asset": "SOL",
                "payTo": "abc123"
            }]
        }
        """
        let offer = parseX402Challenge(headers: [], body: body)
        #expect(offer != nil)
        #expect(offer?.effectiveAmount == "5000")
        #expect(offer?.asset == "SOL")
    }

    @Test
    func parsesTopLevelCurrencyShape() throws {
        // Some x402 servers carry the mint as top-level `currency` with token
        // metadata at the top level instead of nested under `asset` + `extra`.
        // The client must resolve them via the `effective*` accessors so it
        // can pay either wire shape.
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [{
                "scheme": "exact",
                "network": "\(net)",
                "amount": "1000",
                "currency": "\(Mints.usdcDevnet)",
                "payTo": "abc123",
                "decimals": 6,
                "tokenProgram": "\(Mints.tokenProgram)",
                "recentBlockhash": "11111111111111111111111111111111"
            }]
        }
        """
        let offer = parseX402Challenge(headers: [], body: body)
        #expect(offer != nil)
        #expect(offer?.asset == nil)
        #expect(offer?.effectiveAsset == Mints.usdcDevnet)
        #expect(offer?.effectiveDecimals == 6)
        #expect(offer?.effectiveTokenProgram == Mints.tokenProgram)
        #expect(offer?.effectiveRecentBlockhash == "11111111111111111111111111111111")
    }

    // MARK: - Conflicting-shape precedence (must match Rust types.rs lines 340-349)

    /// When both `currency` (top-level) and `asset` are present, top-level
    /// `currency` wins. Rust: `string_field(object, "currency").or_else(|| ...)`.
    @Test
    func topLevelCurrencyWinsOverAssetWhenBothPresent() throws {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [{
                "scheme": "exact",
                "network": "\(net)",
                "amount": "1000",
                "currency": "\(Mints.usdcDevnet)",
                "asset": "\(Mints.pyusdDevnet)",
                "payTo": "abc123"
            }]
        }
        """
        let offer = parseX402Challenge(headers: [], body: body)
        // Top-level `currency` must win.
        #expect(offer?.effectiveAsset == Mints.usdcDevnet)
        // The underlying `asset` field is still accessible directly.
        #expect(offer?.asset == Mints.pyusdDevnet)
    }

    /// When both top-level `tokenProgram` and `extra.tokenProgram` are
    /// present, top-level wins. Rust: `string_field(object, "tokenProgram")
    /// .or_else(|| extra.and_then(...))`.
    @Test
    func topLevelTokenProgramWinsOverExtraTokenProgram() throws {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [{
                "scheme": "exact",
                "network": "\(net)",
                "amount": "1000",
                "asset": "\(Mints.usdcDevnet)",
                "payTo": "abc123",
                "tokenProgram": "\(Mints.token2022Program)",
                "extra": {
                    "tokenProgram": "\(Mints.tokenProgram)",
                    "recentBlockhash": "11111111111111111111111111111111"
                }
            }]
        }
        """
        let offer = parseX402Challenge(headers: [], body: body)
        // Top-level wins.
        #expect(offer?.effectiveTokenProgram == Mints.token2022Program)
    }

    /// When both top-level `decimals` and `extra.decimals` are present,
    /// top-level wins.
    @Test
    func topLevelDecimalsWinOverExtraDecimals() throws {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [{
                "scheme": "exact",
                "network": "\(net)",
                "amount": "1000",
                "asset": "\(Mints.usdcDevnet)",
                "payTo": "abc123",
                "decimals": 9,
                "extra": {
                    "decimals": 6,
                    "recentBlockhash": "11111111111111111111111111111111"
                }
            }]
        }
        """
        let offer = parseX402Challenge(headers: [], body: body)
        // Top-level 9 wins over extra 6.
        #expect(offer?.effectiveDecimals == 9)
    }

    /// When both top-level `recentBlockhash` and `extra.recentBlockhash` are
    /// present, top-level wins.
    @Test
    func topLevelRecentBlockhashWinsOverExtraBlockhash() throws {
        let net = SolanaNetwork.devnet
        let topHash = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
        let extraHash = "11111111111111111111111111111111"
        let body = """
        {
            "accepts": [{
                "scheme": "exact",
                "network": "\(net)",
                "amount": "1000",
                "asset": "\(Mints.usdcDevnet)",
                "payTo": "abc123",
                "recentBlockhash": "\(topHash)",
                "extra": {
                    "recentBlockhash": "\(extraHash)"
                }
            }]
        }
        """
        let offer = parseX402Challenge(headers: [], body: body)
        // Top-level wins.
        #expect(offer?.effectiveRecentBlockhash == topHash)
    }

    /// When only `asset` is present (no `currency`), `effectiveAsset` returns
    /// `asset` (unchanged behavior for the common case).
    @Test
    func assetUsedWhenNoCurrencyPresent() throws {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [{
                "scheme": "exact",
                "network": "\(net)",
                "amount": "1000",
                "asset": "\(Mints.usdcDevnet)",
                "payTo": "abc123"
            }]
        }
        """
        let offer = parseX402Challenge(headers: [], body: body)
        #expect(offer?.effectiveAsset == Mints.usdcDevnet)
        #expect(offer?.currency == nil)
    }

    @Test
    func prefersHeaderOverBody() throws {
        let net = SolanaNetwork.devnet
        let headerEnvelope = "{\"accepts\": [{\"scheme\": \"exact\",\"network\": \"\(net)\",\"amount\": \"100\",\"asset\": \"SOL\",\"payTo\": \"from-header\"}]}"
        let encoded = Data(headerEnvelope.utf8).base64EncodedString()
        let headers = [(name: "payment-required", value: encoded)]
        let body = "{\"accepts\": [{\"scheme\": \"exact\",\"network\": \"\(net)\",\"amount\": \"999\",\"asset\": \"SOL\",\"payTo\": \"from-body\"}]}"
        let offer = parseX402Challenge(headers: headers, body: body)
        #expect(offer?.effectivePayTo == "from-header")
        #expect(offer?.effectiveAmount == "100")
    }

    @Test
    func returnsNilWhenNoSolanaOffer() {
        let body = "{\"accepts\": [{\"network\": \"ethereum:1\", \"amount\": \"100\"}]}"
        #expect(parseX402Challenge(headers: [], body: body) == nil)
    }

    @Test
    func returnsNilWhenNoOffers() {
        #expect(parseX402Challenge(headers: [], body: nil) == nil)
        #expect(parseX402Challenge(headers: [], body: "garbage json") == nil)
    }

    // MARK: - Selection

    @Test
    func picksFirstCurrencyInPreferenceOrder() {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [
                {"scheme":"exact","network":"\(net)","amount":"1000000","asset":"\(Mints.usdcDevnet)","payTo":"x"},
                {"scheme":"exact","network":"\(net)","amount":"1000000","asset":"\(Mints.pyusdDevnet)","payTo":"x"}
            ]
        }
        """
        let selection = X402ChallengeSelection(network: "devnet", currencies: ["PYUSD", "USDC"])
        let offer = parseX402Challenge(headers: [], body: body, selection: selection)
        #expect(offer?.asset == Mints.pyusdDevnet)
    }

    @Test
    func fallsBackToSecondChoiceWhenFirstUnavailable() {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [
                {"scheme":"exact","network":"\(net)","amount":"1000000","asset":"\(Mints.usdcDevnet)","payTo":"x"}
            ]
        }
        """
        let selection = X402ChallengeSelection(network: "devnet", currencies: ["USDT", "USDC"])
        let offer = parseX402Challenge(headers: [], body: body, selection: selection)
        #expect(offer?.asset == Mints.usdcDevnet)
    }

    @Test
    func returnsNilWhenNoCurrencyMatches() {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [
                {"scheme":"exact","network":"\(net)","amount":"1000","asset":"SOL","payTo":"x"}
            ]
        }
        """
        let selection = X402ChallengeSelection(network: "devnet", currencies: ["USDC"])
        let offer = parseX402Challenge(headers: [], body: body, selection: selection)
        #expect(offer == nil)
    }

    @Test
    func noCurrencyPreferencePicksCheapest() {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [
                {"scheme":"exact","network":"\(net)","amount":"1000000","asset":"\(Mints.usdcDevnet)","payTo":"x"},
                {"scheme":"exact","network":"\(net)","amount":"5000","asset":"SOL","payTo":"x"}
            ]
        }
        """
        let selection = X402ChallengeSelection(network: "devnet", currencies: nil)
        let offer = parseX402Challenge(headers: [], body: body, selection: selection)
        #expect(offer?.asset == "SOL")
    }

    @Test
    func acceptsMintAddressAsCurrencyKey() {
        let net = SolanaNetwork.devnet
        let body = """
        {
            "accepts": [
                {"scheme":"exact","network":"\(net)","amount":"1000000","asset":"\(Mints.usdcDevnet)","payTo":"x"}
            ]
        }
        """
        let selection = X402ChallengeSelection(network: "devnet", currencies: [Mints.usdcDevnet])
        let offer = parseX402Challenge(headers: [], body: body, selection: selection)
        #expect(offer?.asset == Mints.usdcDevnet)
    }
}

// MARK: - x402 payment building tests

@Suite("x402 payment building")
struct X402PaymentBuildingTests {
    static func makeSigner() throws -> MemorySigner {
        try MemorySigner(secretKey: Data(repeating: 0x01, count: 32))
    }

    static func makeRpc() -> RpcClient {
        RpcClient(endpoint: URL(string: "http://localhost:8899")!)
    }

    static let knownBlockhash = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"

    static func solOffer() -> X402AcceptsEntry {
        let extra: [String: JSONValue] = ["recentBlockhash": .string(knownBlockhash)]
        return X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "1000",
            maxAmountRequired: nil,
            asset: "SOL",
            payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            recipient: nil,
            extra: extra
        )
    }

    static func splOffer() -> X402AcceptsEntry {
        let extra: [String: JSONValue] = [
            "recentBlockhash": .string(knownBlockhash),
            "tokenProgram": .string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            "decimals": .int(6),
            "memo": .string("order_42"),
        ]
        return X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "1000000",
            maxAmountRequired: nil,
            asset: Mints.usdcDevnet,
            payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            recipient: nil,
            extra: extra
        )
    }

    @Test
    func buildsSolPaymentHeader() async throws {
        let signer = try Self.makeSigner()
        let rpc = Self.makeRpc()
        let offer = Self.solOffer()
        let header = try await buildX402PaymentHeader(signer: signer, rpc: rpc, offer: offer)
        guard let envelopeData = Data(base64Encoded: header) else {
            Issue.record("header is not valid base64")
            return
        }
        let envelope = try JSONDecoder().decode(X402PaymentSignatureEnvelope.self, from: envelopeData)
        #expect(envelope.x402Version == X402Version)
        #expect(envelope.accepted?.asset == "SOL")
        #expect(!envelope.payload.transaction.isEmpty)
        guard let txData = Data(base64Encoded: envelope.payload.transaction) else {
            Issue.record("payload.transaction is not valid base64")
            return
        }
        // v0 transaction: first byte is 0x01 (1 sig slot), then 64-byte sig,
        // then 0x80 (v0 message prefix).
        #expect(txData.count > 65)
        #expect(txData[0] == 0x01)
        #expect(txData[1 + 64] == 0x80)
    }

    @Test
    func buildsSplPaymentHeader() async throws {
        let signer = try Self.makeSigner()
        let rpc = Self.makeRpc()
        let offer = Self.splOffer()
        let header = try await buildX402PaymentHeader(signer: signer, rpc: rpc, offer: offer)
        guard let envelopeData = Data(base64Encoded: header) else {
            Issue.record("header is not valid base64")
            return
        }
        let envelope = try JSONDecoder().decode(X402PaymentSignatureEnvelope.self, from: envelopeData)
        #expect(envelope.x402Version == X402Version)
        #expect(envelope.accepted?.asset == Mints.usdcDevnet)
    }

    @Test
    func echoesOfferedAcceptedVerbatimIncludingUnmodeledFields() async throws {
        // The rust verifier matches the echoed `accepted` against its offered
        // options, so fields the typed entry does not model (maxTimeoutSeconds)
        // must survive the round trip. Decode a challenge, build the header,
        // and assert the echoed `accepted` carries maxTimeoutSeconds verbatim.
        let body = """
        {
          "x402Version": 2,
          "accepts": [{
            "scheme": "exact",
            "network": "\(SolanaNetwork.devnet)",
            "amount": "1000",
            "asset": "\(Mints.usdcDevnet)",
            "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "maxTimeoutSeconds": 60,
            "extra": {
              "recentBlockhash": "\(Self.knownBlockhash)",
              "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
              "decimals": 6
            }
          }]
        }
        """
        let offer = parseX402Challenge(headers: [], body: body)
        #expect(offer != nil)
        let header = try await buildX402PaymentHeader(
            signer: try Self.makeSigner(), rpc: Self.makeRpc(), offer: offer!
        )
        let envData = Data(base64Encoded: header)!
        let obj = try JSONSerialization.jsonObject(with: envData) as! [String: Any]
        let accepted = obj["accepted"] as! [String: Any]
        // Unmodeled field preserved verbatim.
        #expect(accepted["maxTimeoutSeconds"] as? Int == 60)
        // Modeled fields still present.
        #expect(accepted["scheme"] as? String == "exact")
        #expect(accepted["asset"] as? String == Mints.usdcDevnet)
        let extra = accepted["extra"] as! [String: Any]
        #expect(extra["decimals"] as? Int == 6)
    }

    // MARK: - Typed-fallback canonical object (P2 fix)

    /// Regression: when `X402AcceptsEntry` is built in code (raw == nil), the
    /// typed-fallback path in `X402PaymentSignatureEnvelope.encode(to:)` must
    /// include `maxTimeoutSeconds` (defaulting to 300) so the rust v2 verifier
    /// can structurally compare the echoed `accepted` against its offered options.
    @Test
    func inCodeEntryTypedFallbackIncludesMaxTimeoutSeconds() async throws {
        let offer = Self.solOffer()   // raw == nil (built in code, not decoded)
        #expect(offer.raw == nil)

        let header = try await buildX402PaymentHeader(
            signer: try Self.makeSigner(), rpc: Self.makeRpc(), offer: offer
        )
        let envData = Data(base64Encoded: header)!
        let obj = try JSONSerialization.jsonObject(with: envData) as! [String: Any]
        let accepted = obj["accepted"] as! [String: Any]

        // maxTimeoutSeconds must be present (rust v2 verifier structural field).
        #expect(accepted["maxTimeoutSeconds"] != nil)
        // Default value is 300 when not set by the caller.
        #expect(accepted["maxTimeoutSeconds"] as? Int == 300)
    }

    /// A caller that sets an explicit `maxTimeoutSeconds` on the entry must
    /// have that value preserved in the typed fallback (not overridden by 300).
    @Test
    func inCodeEntryTypedFallbackPreservesExplicitMaxTimeoutSeconds() async throws {
        let extra: [String: JSONValue] = [
            "recentBlockhash": .string(Self.knownBlockhash),
        ]
        let offer = X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "2000",
            maxAmountRequired: nil,
            asset: "SOL",
            payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            recipient: nil,
            extra: extra,
            maxTimeoutSeconds: 60
        )
        #expect(offer.raw == nil)

        let header = try await buildX402PaymentHeader(
            signer: try Self.makeSigner(), rpc: Self.makeRpc(), offer: offer
        )
        let envData = Data(base64Encoded: header)!
        let obj = try JSONSerialization.jsonObject(with: envData) as! [String: Any]
        let accepted = obj["accepted"] as! [String: Any]

        #expect(accepted["maxTimeoutSeconds"] as? Int == 60)
    }

    @Test
    func throwsOnMissingAmount() async {
        let signer = try! Self.makeSigner()
        let rpc = Self.makeRpc()
        let offer = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: nil, maxAmountRequired: nil,
            asset: "SOL", payTo: "recipient", recipient: nil, extra: nil
        )
        do {
            _ = try await buildX402PaymentHeader(signer: signer, rpc: rpc, offer: offer)
            Issue.record("expected error")
        } catch { }
    }

    @Test
    func throwsOnMissingPayTo() async {
        let signer = try! Self.makeSigner()
        let rpc = Self.makeRpc()
        let offer = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: "1000", maxAmountRequired: nil,
            asset: "SOL", payTo: nil, recipient: nil, extra: nil
        )
        do {
            _ = try await buildX402PaymentHeader(signer: signer, rpc: rpc, offer: offer)
            Issue.record("expected error")
        } catch { }
    }

    @Test
    func throwsOnMissingAsset() async {
        let signer = try! Self.makeSigner()
        let rpc = Self.makeRpc()
        let offer = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: "1000", maxAmountRequired: nil,
            asset: nil, payTo: "recipient", recipient: nil, extra: nil
        )
        do {
            _ = try await buildX402PaymentHeader(signer: signer, rpc: rpc, offer: offer)
            Issue.record("expected error")
        } catch { }
    }
}

// MARK: - Mints / Network registry tests

@Suite("Mints and Network registry")
struct MintsNetworkTests {
    @Test
    func resolvesSolToNil() {
        #expect(Mints.resolveMint(currency: "SOL", cluster: nil) == nil)
        #expect(Mints.resolveMint(currency: "sol", cluster: nil) == nil)
    }

    @Test
    func resolvesUsdcByNetwork() {
        #expect(Mints.resolveMint(currency: "USDC", cluster: nil) == Mints.usdcMainnet)
        #expect(Mints.resolveMint(currency: "USDC", cluster: "devnet") == Mints.usdcDevnet)
    }

    @Test
    func resolvesTestnetToDevnetValues() {
        // Regression: "testnet" must not fall through to mainnet mints.
        #expect(Mints.resolveMint(currency: "USDC", cluster: "testnet") == Mints.usdcTestnet)
        #expect(Mints.resolveMint(currency: "USDC", cluster: "testnet") == Mints.usdcDevnet)
        #expect(Mints.resolveMint(currency: "USDG", cluster: "testnet") == Mints.usdgDevnet)
        #expect(Mints.resolveMint(currency: "PYUSD", cluster: "testnet") == Mints.pyusdDevnet)
        // USDT and CASH are mainnet-only regardless of cluster.
        #expect(Mints.resolveMint(currency: "USDT", cluster: "testnet") == Mints.usdtMainnet)
    }

    @Test
    func testnetCaip2AndClusterLabelRoundTrip() {
        #expect(SolanaNetwork.caip2(for: "testnet") == SolanaNetwork.testnet)
        #expect(SolanaNetwork.caip2(for: "solana-testnet") == SolanaNetwork.testnet)
        #expect(SolanaNetwork.caip2(for: SolanaNetwork.testnet) == SolanaNetwork.testnet)
        #expect(SolanaNetwork.clusterLabel(for: SolanaNetwork.testnet) == "testnet")
    }

    @Test
    func defaultTokenProgramIsCurrencyAware() {
        // Legacy SPL Token mints.
        #expect(Mints.defaultTokenProgram(currency: "USDC", cluster: "devnet") == Mints.tokenProgram)
        #expect(Mints.defaultTokenProgram(currency: "USDT", cluster: nil) == Mints.tokenProgram)
        // Token-2022 mints.
        #expect(Mints.defaultTokenProgram(currency: "USDG", cluster: "devnet") == Mints.token2022Program)
        #expect(Mints.defaultTokenProgram(currency: "PYUSD", cluster: nil) == Mints.token2022Program)
        #expect(Mints.defaultTokenProgram(currency: "CASH", cluster: nil) == Mints.token2022Program)
        // Resolved-by-mint-address agrees with symbol.
        #expect(Mints.defaultTokenProgram(currency: Mints.usdgMainnet, cluster: nil) == Mints.token2022Program)
    }

    // MARK: - resolveChargeMint regression (P2 regression fix)

    /// Regression: `resolveChargeMint` with network=="testnet" must return the
    /// *_TESTNET constants (which equal the devnet mints), not the mainnet mints.
    /// Previously the function only checked `isDevnet = "devnet"`, so testnet
    /// fell through to mainnet — producing a wrong mint for MPP charges.
    ///
    /// Rule:  devnet -> devnet mint
    ///        testnet -> testnet mint (== devnet mint)
    ///        localnet / nil / else -> mainnet mint
    @Test
    func resolveChargeMintTestnetMapsToTestnetConstants() {
        // testnet must NOT resolve to mainnet mints.
        #expect(Mints.resolveChargeMint(currency: "USDC", network: "testnet") != Mints.usdcMainnet)
        #expect(Mints.resolveChargeMint(currency: "USDG", network: "testnet") != Mints.usdgMainnet)
        #expect(Mints.resolveChargeMint(currency: "PYUSD", network: "testnet") != Mints.pyusdMainnet)

        // testnet must resolve to the *_TESTNET constants.
        #expect(Mints.resolveChargeMint(currency: "USDC", network: "testnet") == Mints.usdcTestnet)
        #expect(Mints.resolveChargeMint(currency: "USDG", network: "testnet") == Mints.usdgTestnet)
        #expect(Mints.resolveChargeMint(currency: "PYUSD", network: "testnet") == Mints.pyusdTestnet)

        // devnet still maps to devnet mints.
        #expect(Mints.resolveChargeMint(currency: "USDC", network: "devnet") == Mints.usdcDevnet)
        #expect(Mints.resolveChargeMint(currency: "USDG", network: "devnet") == Mints.usdgDevnet)
        #expect(Mints.resolveChargeMint(currency: "PYUSD", network: "devnet") == Mints.pyusdDevnet)

        // localnet must NOT use devnet mints (Surfpool localnet mirrors mainnet).
        #expect(Mints.resolveChargeMint(currency: "USDC", network: "localnet") == Mints.usdcMainnet)
        #expect(Mints.resolveChargeMint(currency: "USDG", network: "localnet") == Mints.usdgMainnet)
        #expect(Mints.resolveChargeMint(currency: "PYUSD", network: "localnet") == Mints.pyusdMainnet)

        // nil / mainnet / mainnet-beta also fall back to mainnet.
        #expect(Mints.resolveChargeMint(currency: "USDC", network: nil) == Mints.usdcMainnet)
        #expect(Mints.resolveChargeMint(currency: "USDC", network: "mainnet") == Mints.usdcMainnet)
    }

    @Test
    func passthroughForUnknownSymbol() {
        let addr = Mints.usdcMainnet
        #expect(Mints.resolveMint(currency: addr, cluster: nil) == addr)
    }

    @Test
    func caip2Mapping() {
        #expect(SolanaNetwork.caip2(for: nil) == SolanaNetwork.mainnet)
        #expect(SolanaNetwork.caip2(for: "mainnet") == SolanaNetwork.mainnet)
        #expect(SolanaNetwork.caip2(for: "devnet") == SolanaNetwork.devnet)
        #expect(SolanaNetwork.caip2(for: "localnet") == SolanaNetwork.devnet)
        #expect(SolanaNetwork.caip2(for: SolanaNetwork.devnet) == SolanaNetwork.devnet)
    }
}
