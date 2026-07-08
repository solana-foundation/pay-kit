import Foundation
import Testing
@testable import SolanaPayKit

@Suite("Charge credential")
struct ChargeCredentialTests {
    @Test
    func parsesChargeChallengeWithSplits() throws {
        let challenge = try MppHeaders.parseWWWAuthenticate(Self.challengeHeader())
        let request = try challenge.chargeRequest

        #expect(challenge.id == "challenge-1")
        #expect(challenge.method == "solana")
        #expect(challenge.intent == "charge")
        #expect(request.amount == "1000")
        #expect(request.currency == "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
        #expect(request.methodDetails.network == "localnet")
        #expect(request.methodDetails.splits?.first?.amount == "250")
        #expect(request.methodDetails.splits?.first?.ataCreationRequired == true)
    }

    @Test
    func parsesAuthParamsWithWhitespaceBeforeQuotedValues() throws {
        let request = try Self.encodedRequest()
        let challenge = try MppHeaders.parseWWWAuthenticate(
            """
            Payment id= "challenge-1", realm= \t"MPP Payment", method= "solana", intent= "charge", request= "\(request)"
            """
        )

        #expect(challenge.id == "challenge-1")
        #expect(challenge.realm == "MPP Payment")
        #expect(challenge.request == request)
    }

    @Test
    func rejectsUnterminatedQuotedAuthParam() throws {
        let request = try Self.encodedRequest()

        #expect(throws: MppError.invalidHeader) {
            _ = try MppHeaders.parseWWWAuthenticate(
                """
                Payment id="challenge-1", realm="MPP Payment", method="solana", intent="charge", request="\(request)
                """
            )
        }
    }

    @Test
    func rejectsDanglingEscapeInQuotedAuthParam() throws {
        #expect(throws: MppError.invalidHeader) {
            _ = try MppHeaders.parseWWWAuthenticate(
                """
                Payment id="challenge-1\\
                """
            )
        }
    }

    @Test
    func preservesChargeRequestDecodeDetails() throws {
        let invalidRequest = Base64URL.encode(Data(#"{"amount":"1000"}"#.utf8))
        let challenge = try PaymentChallenge(
            id: "challenge-4",
            realm: "MPP Payment",
            method: "solana",
            intent: "charge",
            request: invalidRequest
        )

        do {
            _ = try challenge.chargeRequest
            Issue.record("expected invalid JSON error")
        } catch let MppError.invalidJSON(detail) {
            #expect(detail.contains("currency"))
        }
    }

    @Test
    func serializesPullModeAuthorizationCredential() async throws {
        let challenge = try MppHeaders.parseWWWAuthenticate(Self.challengeHeader())
        let builder = ChargeCredentialBuilder(
            transactionProvider: StaticChargeTransactionProvider(transaction: "base64-transaction")
        )

        let header = try await builder.authorizationHeader(for: challenge)
        #expect(header.hasPrefix("Payment "))

        let encoded = String(header.dropFirst("Payment ".count))
        let credentialData = try Base64URL.decode(encoded)
        let credential = try JSONDecoder().decode(PaymentCredential.self, from: credentialData)

        #expect(credential.challenge.id == challenge.id)
        #expect(credential.challenge.request == challenge.request)
        #expect(credential.payload == .transaction("base64-transaction"))
    }

    @Test
    func transactionProviderCanUseSolanaSigner() async throws {
        let challenge = try MppHeaders.parseWWWAuthenticate(Self.challengeHeader())
        let signer = MemorySigner(
            publicKey: Data("dev-public-key".utf8),
            address: "feePayer1111111111111111111111111111111"
        ) { message in
            #expect(String(decoding: message, as: UTF8.self) == "charge:1000:recipient11111111111111111111111111111111")
            return Data("signed-transaction-bytes".utf8)
        }
        let builder = ChargeCredentialBuilder(
            transactionProvider: SignerBackedTransactionProvider(signer: signer)
        )

        let header = try await builder.authorizationHeader(for: challenge)
        let encoded = String(header.dropFirst("Payment ".count))
        let credentialData = try Base64URL.decode(encoded)
        let credential = try JSONDecoder().decode(PaymentCredential.self, from: credentialData)
        let request = try challenge.chargeRequest

        #expect(signer.address == request.methodDetails.feePayerKey)
        #expect(credential.payload == .transaction("c2lnbmVkLXRyYW5zYWN0aW9uLWJ5dGVz"))
    }

    @Test
    func rejectsUnsupportedIntent() async throws {
        let request = try Self.encodedRequest()
        let challenge = try PaymentChallenge(
            id: "challenge-2",
            realm: "MPP Payment",
            method: "solana",
            intent: "session",
            request: request
        )
        let builder = ChargeCredentialBuilder(
            transactionProvider: StaticChargeTransactionProvider(transaction: "tx")
        )

        await #expect(throws: MppError.unsupportedChallenge(method: "solana", intent: "session")) {
            _ = try await builder.authorizationHeader(for: challenge)
        }
    }

    @Test
    func rejectsMalformedRequestBase64() throws {
        #expect(throws: MppError.invalidBase64URL) {
            _ = try PaymentChallenge(
                id: "challenge-3",
                realm: "MPP Payment",
                method: "solana",
                intent: "charge",
                request: "@@@"
            )
        }
    }

    @Test
    func rejectsOversizedRequestParam() throws {
        // Audit #9: the `request` parameter must be capped at 16 KiB before
        // any base64url-decode + JSON-parse work runs. A value past the cap
        // is rejected as an invalid header.
        let oversized = String(repeating: "A", count: MppHeaders.maxTokenLength + 1)
        let header = """
        Payment id="c", realm="r", method="solana", intent="charge", request="\(oversized)"
        """
        #expect(throws: MppError.invalidHeader) {
            _ = try MppHeaders.parseWWWAuthenticate(header)
        }
    }

    @Test
    func acceptsRequestParamAtCap() throws {
        // A valid challenge whose encoded request is within the cap parses.
        let request = try Self.encodedRequest()
        #expect(request.utf8.count <= MppHeaders.maxTokenLength)
        let header = """
        Payment id="c", realm="r", method="solana", intent="charge", request="\(request)"
        """
        let challenge = try MppHeaders.parseWWWAuthenticate(header)
        #expect(challenge.method == "solana")
    }

    private static func challengeHeader() throws -> String {
        let request = try encodedRequest()
        return """
        Payment id="challenge-1", realm="MPP Payment", method="solana", intent="charge", request="\(request)", expires="2099-05-20T00:00:00Z"
        """
    }

    private static func encodedRequest() throws -> String {
        let json = """
        {
          "amount": "1000",
          "currency": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
          "recipient": "recipient11111111111111111111111111111111",
          "externalId": "order-123",
          "methodDetails": {
            "network": "localnet",
            "decimals": 6,
            "feePayer": true,
            "feePayerKey": "feePayer1111111111111111111111111111111",
            "recentBlockhash": "blockhash11111111111111111111111111111111",
            "splits": [
              {
                "recipient": "platform111111111111111111111111111111",
                "amount": "250",
                "ataCreationRequired": true,
                "memo": "harness split"
              }
            ],
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
          }
        }
        """
        return Base64URL.encode(Data(json.utf8))
    }
}

private struct SignerBackedTransactionProvider: ChargeTransactionProviding {
    let signer: any SolanaSigner

    func buildTransaction(for request: ChargeRequest) async throws -> String {
        let message = Data("charge:\(request.amount):\(request.recipient)".utf8)
        let signedTransaction = try await signer.sign(message: message)
        return signedTransaction.base64EncodedString()
    }
}
