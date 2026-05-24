import Foundation
import Testing
@testable import SolanaMpp

@Suite("Charge wire-signing pull path", .serialized)
struct ChargeWireTests {
    /// End-to-end pull-mode credential for an SPL charge with one
    /// split (matches the harness charge-split-ata shape). The test
    /// asserts the verifier can recover the signed transaction from
    /// the Authorization header, decode the base64 payload, and
    /// confirm the signer's signature is in slot 0 and verifies.
    @Test
    func splPullCredentialIsWellFormedAndSigned() async throws {
        let seed = Data(repeating: 7, count: 32)
        let signer = try MemorySigner(secretKey: seed)

        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        let recipient = "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir"
        let splitRecipient = "11111111111111111111111111111112"
        // 32-byte blockhash encoded as base58 of 32 alternating bytes.
        let blockhash = Base58.encode(Data(repeating: 0x11, count: 32))

        let requestJson = """
        {
          "amount": "1000",
          "currency": "\(mint)",
          "recipient": "\(recipient)",
          "externalId": "order-42",
          "methodDetails": {
            "network": "localnet",
            "decimals": 6,
            "feePayer": false,
            "recentBlockhash": "\(blockhash)",
            "splits": [
              {"recipient": "\(splitRecipient)", "amount": "100", "ataCreationRequired": true, "memo": "ref"}
            ],
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-1",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )

        let header = try await Charge.buildPullCredential(challenge: challenge, signer: signer)
        #expect(header.hasPrefix("Payment "))

        // Recover the signed transaction and verify the signature.
        let credEncoded = String(header.dropFirst("Payment ".count))
        let credData = try Base64URL.decode(credEncoded)
        let credential = try JSONDecoder().decode(PaymentCredential.self, from: credData)
        guard case let .transaction(txBase64) = credential.payload else {
            Issue.record("expected transaction payload")
            return
        }
        let txBytes = Data(base64Encoded: txBase64)!
        // Parse signature count + signatures + message length empirically.
        var offset = 0
        let sigCount = try ShortVec.decodeLength(txBytes, at: &offset)
        #expect(sigCount == 1)
        let sigStart = offset
        let sig = txBytes.subdata(in: sigStart..<(sigStart + 64))
        offset += 64
        let messageBytes = txBytes.subdata(in: offset..<txBytes.count)

        #expect(try Ed25519.verify(signature: sig, message: messageBytes, publicKey: signer.publicKey))
    }

    @Test
    func solPullCredentialUsesSystemTransfer() async throws {
        let seed = Data(repeating: 5, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let blockhash = Base58.encode(Data(repeating: 0x22, count: 32))
        let requestJson = """
        {
          "amount": "1000000000",
          "currency": "SOL",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "recentBlockhash": "\(blockhash)"
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-2",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )
        let header = try await Charge.buildPullCredential(challenge: challenge, signer: signer)
        #expect(header.hasPrefix("Payment "))
    }

    @Test
    func rejectsSplitsExceedingAmount() async throws {
        let seed = Data(repeating: 9, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let blockhash = Base58.encode(Data(repeating: 0x33, count: 32))
        let requestJson = """
        {
          "amount": "100",
          "currency": "SOL",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "recentBlockhash": "\(blockhash)",
            "splits": [{"recipient": "11111111111111111111111111111112", "amount": "100"}]
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-3",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )
        await #expect(throws: MppError.self) {
            _ = try await Charge.buildPullCredential(challenge: challenge, signer: signer)
        }
    }

    @Test
    func rejectsSymbolCurrencyWithAtaCreationSplit() async throws {
        // Spine parity for codex PR #104 P2 finding: Rust
        // (`rust/src/server/charge.rs` `validate_charge_options`) and TS
        // verifiers require the request currency to be the resolved mint
        // address itself when `ataCreationRequired` is set; a symbol
        // like "USDC" is rejected. Swift must reject client-side so it
        // never signs a credential the verifier will refuse.
        let seed = Data(repeating: 11, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let blockhash = Base58.encode(Data(repeating: 0x55, count: 32))
        let requestJson = """
        {
          "amount": "1000",
          "currency": "USDC",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "decimals": 6,
            "feePayer": false,
            "recentBlockhash": "\(blockhash)",
            "splits": [
              {"recipient": "11111111111111111111111111111112", "amount": "100", "ataCreationRequired": true}
            ],
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-symbol",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )
        await #expect(throws: MppError.self) {
            _ = try await Charge.buildPullCredential(challenge: challenge, signer: signer)
        }
    }

    @Test
    func rejectsAtaCreationWithBogusNonMintCurrency() async throws {
        // Sibling regression: a bogus currency string that is neither a
        // known symbol nor a valid base58 mint address must still be
        // rejected when ataCreationRequired is set.
        let seed = Data(repeating: 12, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let blockhash = Base58.encode(Data(repeating: 0x66, count: 32))
        let requestJson = """
        {
          "amount": "1000",
          "currency": "not-a-mint",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "decimals": 6,
            "feePayer": false,
            "recentBlockhash": "\(blockhash)",
            "splits": [
              {"recipient": "11111111111111111111111111111112", "amount": "100", "ataCreationRequired": true}
            ],
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-bogus",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )
        await #expect(throws: MppError.self) {
            _ = try await Charge.buildPullCredential(challenge: challenge, signer: signer)
        }
    }

    /// Regression for codex PR #104 P2 finding: when the server omits
    /// `methodDetails.tokenProgram`, the client must resolve the program
    /// id from the mint account's owner via RPC (matching the Rust
    /// client's `resolve_token_program`). The previous hard-coded
    /// allow-list silently treated Token-2022 mints not in the set as
    /// legacy SPL, deriving wrong ATAs and producing a transaction that
    /// would fail on-chain.
    @Test
    func resolvesTokenProgramFromMintOwnerWhenOmitted_LegacySpl() async throws {
        RpcStubURLProtocol.reset()
        RpcStubURLProtocol.responder = { _ in
            let body = #"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","lamports":0,"data":["",""],"executable":false,"rentEpoch":0}}}"#
            return StubResponse(statusCode: 200, headers: ["Content-Type": "application/json"], body: Data(body.utf8))
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RpcStubURLProtocol.self]
        let session = URLSession(configuration: config)
        let rpc = RpcClient(endpoint: URL(string: "https://stub.test/rpc")!, urlSession: session)

        let seed = Data(repeating: 21, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let blockhash = Base58.encode(Data(repeating: 0x77, count: 32))
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        let requestJson = """
        {
          "amount": "1000",
          "currency": "\(mint)",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "decimals": 6,
            "feePayer": false,
            "recentBlockhash": "\(blockhash)"
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-legacy",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )
        let header = try await Charge.buildPullCredential(challenge: challenge, signer: signer, rpc: rpc)
        #expect(header.hasPrefix("Payment "))
    }

    @Test
    func resolvesTokenProgramFromMintOwnerWhenOmitted_Token2022() async throws {
        RpcStubURLProtocol.reset()
        RpcStubURLProtocol.responder = { _ in
            // Token-2022 program id: TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
            let body = #"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"owner":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb","lamports":0,"data":["",""],"executable":false,"rentEpoch":0}}}"#
            return StubResponse(statusCode: 200, headers: ["Content-Type": "application/json"], body: Data(body.utf8))
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RpcStubURLProtocol.self]
        let session = URLSession(configuration: config)
        let rpc = RpcClient(endpoint: URL(string: "https://stub.test/rpc")!, urlSession: session)

        let seed = Data(repeating: 22, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let blockhash = Base58.encode(Data(repeating: 0x78, count: 32))
        // A plausible base58 mint not present in any hard-coded set.
        let mint = "9zoqdwEBKWEi9G5Ze8BSkdmppbGSebokm5o8HWXdZMVw"
        let requestJson = """
        {
          "amount": "1000",
          "currency": "\(mint)",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "decimals": 6,
            "feePayer": false,
            "recentBlockhash": "\(blockhash)"
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-t22",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )
        let header = try await Charge.buildPullCredential(challenge: challenge, signer: signer, rpc: rpc)
        #expect(header.hasPrefix("Payment "))
    }

    @Test
    func rejectsOmittedTokenProgramWithoutRpc() async throws {
        // Without an RpcClient and without explicit tokenProgram, the
        // client must refuse to silently guess a program id. The
        // previous hard-coded allow-list could mis-derive ATAs for any
        // Token-2022 mint outside the set.
        let seed = Data(repeating: 23, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let blockhash = Base58.encode(Data(repeating: 0x79, count: 32))
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        let requestJson = """
        {
          "amount": "1000",
          "currency": "\(mint)",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "decimals": 6,
            "recentBlockhash": "\(blockhash)"
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-no-rpc",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )
        await #expect(throws: MppError.self) {
            _ = try await Charge.buildPullCredential(challenge: challenge, signer: signer)
        }
    }

    @Test
    func rejectsMintOwnedByUnsupportedProgram() async throws {
        RpcStubURLProtocol.reset()
        RpcStubURLProtocol.responder = { _ in
            // System program is not a valid token program.
            let body = #"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"owner":"11111111111111111111111111111111","lamports":0,"data":["",""],"executable":false,"rentEpoch":0}}}"#
            return StubResponse(statusCode: 200, headers: ["Content-Type": "application/json"], body: Data(body.utf8))
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RpcStubURLProtocol.self]
        let session = URLSession(configuration: config)
        let rpc = RpcClient(endpoint: URL(string: "https://stub.test/rpc")!, urlSession: session)

        let seed = Data(repeating: 24, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let blockhash = Base58.encode(Data(repeating: 0x7A, count: 32))
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        let requestJson = """
        {
          "amount": "1000",
          "currency": "\(mint)",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "decimals": 6,
            "recentBlockhash": "\(blockhash)"
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-bad-owner",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )
        await #expect(throws: MppError.self) {
            _ = try await Charge.buildPullCredential(challenge: challenge, signer: signer, rpc: rpc)
        }
    }

    @Test
    func pickChallengeReturnsFirstSolanaCharge() throws {
        let request = Base64URL.encode(Data(#"{"amount":"1","currency":"SOL","recipient":"11111111111111111111111111111112","methodDetails":{}}"#.utf8))
        let headers = [
            "Payment id=\"x\", realm=\"r\", method=\"ethereum\", intent=\"charge\", request=\"\(request)\"",
            "Payment id=\"y\", realm=\"r\", method=\"solana\", intent=\"charge\", request=\"\(request)\"",
            "Payment id=\"z\", realm=\"r\", method=\"solana\", intent=\"session\", request=\"\(request)\"",
        ]
        let picked = try Charge.pickChallenge(wwwAuthenticateHeaders: headers)
        #expect(picked.id == "y")
    }

    @Test
    func pickChallengeSkipsSolanaChargeWithMalformedRequestPayload() throws {
        // Regression for codex PR #104 P2 finding: a header that frames
        // as `method=solana, intent=charge` but whose embedded request
        // payload is malformed must be skipped during selection so the
        // caller does not get a challenge that explodes later in
        // `buildChargeTransaction`.
        let validRequest = Base64URL.encode(Data(#"{"amount":"1","currency":"SOL","recipient":"11111111111111111111111111111112","methodDetails":{}}"#.utf8))
        let malformedRequest = Base64URL.encode(Data(#"{"not a charge request"}"#.utf8))
        let headers = [
            "Payment id=\"bad\", realm=\"r\", method=\"solana\", intent=\"charge\", request=\"\(malformedRequest)\"",
            "Payment id=\"good\", realm=\"r\", method=\"solana\", intent=\"charge\", request=\"\(validRequest)\"",
        ]
        let picked = try Charge.pickChallenge(wwwAuthenticateHeaders: headers)
        #expect(picked.id == "good")
    }

    @Test
    func rejectsMoreThanEightSplits() async throws {
        // Spine cap for codex PR #104 P2 finding: Rust and TS both
        // reject `splits.length > 8`. Swift must enforce client-side so
        // it never signs an out-of-spec credential.
        let seed = Data(repeating: 13, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let blockhash = Base58.encode(Data(repeating: 0x77, count: 32))
        let splitsArray = (0..<9)
            .map { _ in #"{"recipient":"11111111111111111111111111111112","amount":"1"}"# }
            .joined(separator: ",")
        let requestJson = """
        {
          "amount": "1000",
          "currency": "SOL",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "feePayer": false,
            "recentBlockhash": "\(blockhash)",
            "splits": [\(splitsArray)]
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challenge = try PaymentChallenge(
            id: "ch-too-many-splits",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: requestB64
        )
        await #expect(throws: MppError.self) {
            _ = try await Charge.buildPullCredential(challenge: challenge, signer: signer)
        }
    }
}

// MARK: - Dedicated URLProtocol stub for RPC tests
//
// Lives in its own subclass so it does not share global responder state
// with `StubURLProtocol` (used by HTTPClientTests). URLSession installs
// every protocol class globally for any matching session, so a single
// shared stub would cause cross-suite test races.

final class RpcStubURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var responder: ((URLRequest) -> StubResponse)?
    nonisolated(unsafe) static var requestCount = 0

    static func reset() {
        responder = nil
        requestCount = 0
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requestCount += 1
        guard let responder = Self.responder else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "rpc-stub", code: 0))
            return
        }
        let stub = responder(request)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: stub.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: stub.headers
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: stub.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
