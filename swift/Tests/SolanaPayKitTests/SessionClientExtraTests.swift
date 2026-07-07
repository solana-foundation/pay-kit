import Foundation
import Testing
@testable import SolanaPayKit

/// Coverage for the session challenge dispatch, credential framing, and opener
/// option/error paths beyond the happy-path opener test.
@Suite("Session client dispatch + credential", .serialized)
struct SessionClientExtraTests {
    private let operatorAddress = Base58.encode(Data(repeating: 0x05, count: 32))
    private let recipient = Base58.encode(Data(repeating: 0x06, count: 32))
    private let blockhash = Base58.encode(Data(repeating: 0x11, count: 32))

    private func request(recipient: String? = nil) -> SessionRequest {
        SessionRequest(
            cap: "1000000", currency: "USDC", decimals: 6, network: "localnet",
            operator: operatorAddress, recipient: recipient ?? self.recipient,
            modes: [.pull], pullVoucherStrategy: .clientVoucher, recentSlot: 4321
        )
    }

    private func signers() throws -> (MemorySigner, MemorySigner) {
        (try MemorySigner(secretKey: Data(repeating: 1, count: 32)),
         try MemorySigner(secretKey: Data(repeating: 2, count: 32)))
    }

    @Test
    func challengeSessionRequestDecodesAndDispatches() throws {
        let req = request()
        let encoded = Base64URL.encode(try JSONEncoder().encode(req))
        let challenge = try PaymentChallenge(id: "1", realm: "r", method: "solana", intent: "session", request: encoded)

        let decoded = try challenge.sessionRequest
        #expect(decoded == req)
        try challenge.requireSolanaSession() // does not throw

        let chargeChallenge = try PaymentChallenge(id: "1", realm: "r", method: "solana", intent: "charge", request: encoded)
        #expect(throws: PayKitError.self) { try chargeChallenge.requireSolanaSession() }
    }

    @Test
    func sessionRequestRoundTripsThroughTheWire() throws {
        let req = SessionRequest(
            cap: "5", currency: "USDC", decimals: 6, network: "devnet", operator: operatorAddress,
            recipient: recipient, splits: [SessionSplit(recipient: recipient, bps: 10)],
            programId: PaymentChannels.programId.base58, externalId: "ext-1", minVoucherDelta: "2",
            modes: [.pull, .push], pullVoucherStrategy: .clientVoucher, recentBlockhash: blockhash,
            recentSlot: 4321
        )
        let encoded = try JSONEncoder().encode(req)
        // recentSlot serializes as a decimal string, like salt on OpenPayload.
        let object = try #require(try JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(object["recentSlot"] as? String == "4321")
        let decoded = try JSONDecoder().decode(SessionRequest.self, from: encoded)
        #expect(decoded == req)
    }

    @Test
    func serializeSessionCredentialFramesPaymentHeader() async throws {
        let (payer, sessionSigner) = try signers()
        let opener = try await PaymentChannelSession.open(
            request: request(), payerSigner: payer, sessionSigner: sessionSigner, recentBlockhash: blockhash
        )
        let voucherAction = try await opener.session.voucherAction(100)
        let echo = try PaymentChallenge(
            id: "1", realm: "r", method: "solana", intent: "session",
            request: Base64URL.encode(try JSONEncoder().encode(request()))
        ).echo()

        let header = try serializeSessionCredential(challenge: echo, action: voucherAction)
        #expect(header.hasPrefix("Payment "))
        let payload = String(header.dropFirst("Payment ".count))
        let object = try #require(try JSONSerialization.jsonObject(with: try Base64URL.decode(payload)) as? [String: Any])
        #expect(object["challenge"] != nil)
        let inner = try #require(object["payload"] as? [String: Any])
        #expect(inner["action"] as? String == "voucher")
    }

    @Test
    func openerHonorsExplicitOptions() async throws {
        let (payer, sessionSigner) = try signers()
        let options = PaymentChannelSessionOpenOptions(
            open: PaymentChannelOpenOptions(
                deposit: 55,
                gracePeriod: 12,
                programId: PaymentChannels.programId,
                recipients: [PaymentChannels.Distribution(recipient: try Pubkey(base58: recipient), bps: 25)],
                salt: 7,
                tokenProgram: .tokenProgram
            )
        )
        let opener = try await PaymentChannelSession.open(
            request: request(), payerSigner: payer, sessionSigner: sessionSigner,
            recentBlockhash: blockhash, options: options
        )
        #expect(opener.open.deposit == 55)
        #expect(opener.open.gracePeriod == 12)
        #expect(opener.open.salt == 7)
        #expect(opener.open.recipients.count == 1)
        #expect(opener.open.recipients[0].bps == 25)
    }

    @Test
    func openerRejectsBadRecipientAndBadBlockhash() async throws {
        let (payer, sessionSigner) = try signers()
        await #expect(throws: PayKitError.self) {
            _ = try await PaymentChannelSession.open(
                request: request(recipient: "not base58 !!!"), payerSigner: payer, sessionSigner: sessionSigner,
                recentBlockhash: blockhash
            )
        }
        await #expect(throws: (any Error).self) {
            _ = try await PaymentChannelSession.open(
                request: request(), payerSigner: payer, sessionSigner: sessionSigner, recentBlockhash: "short"
            )
        }
    }
}
