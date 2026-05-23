import Foundation
import Testing
@testable import SolanaMpp

@Suite("Charge wire-signing pull path")
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
}
