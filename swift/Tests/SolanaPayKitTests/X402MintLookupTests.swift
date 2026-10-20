import Foundation
import Testing
@testable import SolanaPayKit

/// Facilitator fee payer for x402 exact test offers. scheme_exact_svm.md
/// requires `extra.feePayer`, so every payable test offer carries one.
let x402TestFeePayer = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ"

// MARK: - Fixture mint RPC
//
// Stateless JSON-RPC stub: answers `getAccountInfo` from an immutable mint
// table (82-byte SPL mint layout, decimals @44, is_initialized @45) and
// `getLatestBlockhash` with a fixed hash. No shared mutable responder, so it
// cannot race with other suites.

final class MintFixtureURLProtocol: URLProtocol, @unchecked Sendable {
    struct Mint {
        let owner: String
        let decimals: UInt8
    }

    static let wsolMint = "So11111111111111111111111111111111111111112"
    static let systemOwnedMint = "Stake11111111111111111111111111111111111111"
    static let missingMint = "Vote111111111111111111111111111111111111111"
    static let unknownToken2022Mint = "Config1111111111111111111111111111111111111"

    static let mints: [String: Mint] = [
        Mints.usdcDevnet: Mint(owner: Mints.tokenProgram, decimals: 6),
        Mints.usdcMainnet: Mint(owner: Mints.tokenProgram, decimals: 6),
        Mints.pyusdMainnet: Mint(owner: Mints.token2022Program, decimals: 6),
        Mints.pyusdDevnet: Mint(owner: Mints.token2022Program, decimals: 6),
        Mints.usdgMainnet: Mint(owner: Mints.token2022Program, decimals: 6),
        Mints.usdgDevnet: Mint(owner: Mints.token2022Program, decimals: 6),
        Mints.usdtMainnet: Mint(owner: Mints.tokenProgram, decimals: 6),
        Mints.cashMainnet: Mint(owner: Mints.token2022Program, decimals: 6),
        wsolMint: Mint(owner: Mints.tokenProgram, decimals: 9),
        unknownToken2022Mint: Mint(owner: Mints.token2022Program, decimals: 6),
        systemOwnedMint: Mint(owner: "11111111111111111111111111111111", decimals: 6),
    ]

    static func rpc() -> RpcClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MintFixtureURLProtocol.self]
        return RpcClient(
            endpoint: URL(string: "https://mint-fixture.test/rpc")!,
            urlSession: URLSession(configuration: config)
        )
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let body = Self.readBody(request)
        let call = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
        let method = call["method"] as? String ?? ""
        let params = call["params"] as? [Any] ?? []
        let result: Any
        switch method {
        case "getLatestBlockhash":
            result = [
                "context": ["slot": 1],
                "value": ["blockhash": "11111111111111111111111111111111", "lastValidBlockHeight": 1000],
            ]
        case "getAccountInfo":
            let address = params.first as? String ?? ""
            if let mint = Self.mints[address] {
                var data = [UInt8](repeating: 0, count: 82)
                data[44] = mint.decimals
                data[45] = 1
                result = [
                    "context": ["slot": 1],
                    "value": [
                        "owner": mint.owner,
                        "lamports": 1_461_600,
                        "data": [Data(data).base64EncodedString(), "base64"],
                        "executable": false,
                        "rentEpoch": 0,
                    ] as [String: Any],
                ]
            } else {
                result = ["context": ["slot": 1], "value": NSNull()]
            }
        default:
            result = NSNull()
        }
        let payload: [String: Any] = ["jsonrpc": "2.0", "id": 1, "result": result]
        let response = HTTPURLResponse(
            url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: (try? JSONSerialization.data(withJSONObject: payload)) ?? Data())
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func readBody(_ request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}

// MARK: - x402 exact: decimals and token program from the mint (RULINGS S1)

@Suite("x402 exact reads token program and decimals from the mint account")
struct X402MintLookupTests {
    private static let payTo = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
    private static let feePayer = x402TestFeePayer

    private static func offer(asset: String, extra: [String: JSONValue] = [:]) -> X402AcceptsEntry {
        var merged = extra
        merged["feePayer"] = .string(feePayer)
        return X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.mainnet,
            amount: "1000",
            maxAmountRequired: nil,
            asset: asset,
            payTo: payTo,
            recipient: nil,
            extra: merged
        )
    }

    private static func transferChecked(_ header: String) throws -> (program: Pubkey, data: [UInt8]) {
        let envData = try #require(Data(base64Encoded: header))
        let env = try JSONDecoder().decode(X402PaymentSignatureEnvelope.self, from: envData)
        let tx = try TxDecoder.decode(base64: env.payload.transaction)
        let ix = try #require(tx.instructions.first { $0.data.first == 12 && $0.data.count == 10 })
        return (tx.accountKeys[ix.programIdIndex], Array(ix.data))
    }

    private static func signer() throws -> MemorySigner {
        try MemorySigner(secretKey: Data(repeating: 0x07, count: 32))
    }

    /// Regression: an offer without `decimals` used to sign TransferChecked
    /// with a hard-coded 6. A 9-decimal mint must be signed with 9.
    @Test
    func decimalsComeFromMintWhenOfferOmitsThem() async throws {
        let header = try await buildX402PaymentHeader(
            signer: try Self.signer(),
            rpc: MintFixtureURLProtocol.rpc(),
            offer: Self.offer(asset: MintFixtureURLProtocol.wsolMint)
        )
        let (program, data) = try Self.transferChecked(header)
        #expect(data.last == 9)
        #expect(program == .tokenProgram)
    }

    /// The token program comes from the mint owner on the same lookup, so a
    /// Token-2022 mint derives Token-2022 ATAs without a table.
    @Test
    func tokenProgramComesFromMintOwner() async throws {
        let header = try await buildX402PaymentHeader(
            signer: try Self.signer(),
            rpc: MintFixtureURLProtocol.rpc(),
            offer: Self.offer(asset: Mints.pyusdMainnet)
        )
        let (program, data) = try Self.transferChecked(header)
        #expect(program == .token2022Program)
        #expect(data.last == 6)
    }

    /// Positive control: a decimals hint that agrees with the mint is fine.
    @Test
    func matchingDecimalsHintIsAccepted() async throws {
        let header = try await buildX402PaymentHeader(
            signer: try Self.signer(),
            rpc: MintFixtureURLProtocol.rpc(),
            offer: Self.offer(asset: MintFixtureURLProtocol.wsolMint, extra: ["decimals": .int(9)])
        )
        let (_, data) = try Self.transferChecked(header)
        #expect(data.last == 9)
    }

    /// Regression: a decimals hint used to be signed as-is. One that
    /// disagrees with the mint is refused.
    @Test
    func decimalsHintDisagreeingWithMintIsRefused() async throws {
        await #expect(throws: PayKitError.self) {
            _ = try await buildX402PaymentHeader(
                signer: try Self.signer(),
                rpc: MintFixtureURLProtocol.rpc(),
                offer: Self.offer(asset: MintFixtureURLProtocol.wsolMint, extra: ["decimals": .int(6)])
            )
        }
    }

    /// Regression: with a decimals hint present the token program used to
    /// come from the stablecoin table, which defaults an unknown mint to the
    /// legacy Token program. It now comes from the mint owner.
    @Test
    func tokenProgramComesFromMintOwnerEvenWithDecimalsHint() async throws {
        let header = try await buildX402PaymentHeader(
            signer: try Self.signer(),
            rpc: MintFixtureURLProtocol.rpc(),
            offer: Self.offer(asset: MintFixtureURLProtocol.unknownToken2022Mint, extra: ["decimals": .int(6)])
        )
        let (program, _) = try Self.transferChecked(header)
        #expect(program == .token2022Program)
    }

    @Test
    func rejectsMissingMintAccount() async throws {
        await #expect(throws: PayKitError.self) {
            _ = try await buildX402PaymentHeader(
                signer: try Self.signer(),
                rpc: MintFixtureURLProtocol.rpc(),
                offer: Self.offer(asset: MintFixtureURLProtocol.missingMint)
            )
        }
    }

    @Test
    func rejectsMintWithUnexpectedOwner() async throws {
        await #expect(throws: PayKitError.self) {
            _ = try await buildX402PaymentHeader(
                signer: try Self.signer(),
                rpc: MintFixtureURLProtocol.rpc(),
                offer: Self.offer(asset: MintFixtureURLProtocol.systemOwnedMint)
            )
        }
    }

    @Test
    func rejectsTokenProgramThatDoesNotOwnMint() async throws {
        await #expect(throws: PayKitError.self) {
            _ = try await buildX402PaymentHeader(
                signer: try Self.signer(),
                rpc: MintFixtureURLProtocol.rpc(),
                offer: Self.offer(
                    asset: Mints.pyusdMainnet,
                    extra: ["tokenProgram": .string(Mints.tokenProgram)]
                )
            )
        }
    }
}
