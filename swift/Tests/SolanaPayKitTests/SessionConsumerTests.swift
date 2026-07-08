import Foundation
import Testing
@testable import SolanaPayKit

/// SessionConsumer commit flow, validation order, and replay reconcile-and-clamp,
/// mirroring Go `session_consumer.go` tests and the #162 lost-response fix.
@Suite("SessionConsumer", .serialized)
struct SessionConsumerTests {
    /// Records each commit and echoes a committed receipt pinned to the
    /// voucher's cumulative. Re-committing a deliveryId already seen returns a
    /// replayed receipt at the first settled cumulative (server dedupe).
    final class RecordingTransport: CommitTransport, @unchecked Sendable {
        private(set) var commits: [CommitPayload] = []
        var fail = false
        private var settled: [String: String] = [:]

        func commit(directive: MeteringDirective, payload: CommitPayload) async throws -> CommitReceipt {
            if fail { throw PayKitError.invalidTransaction("commit failed") }
            if let prior = settled[directive.deliveryId] {
                return CommitReceipt(
                    deliveryId: directive.deliveryId, sessionId: directive.sessionId,
                    amount: directive.amount, cumulative: prior, status: .replayed
                )
            }
            let cumulative = payload.voucher.data.cumulative
            settled[directive.deliveryId] = cumulative
            commits.append(payload)
            return CommitReceipt(
                deliveryId: directive.deliveryId, sessionId: directive.sessionId,
                amount: directive.amount, cumulative: cumulative, status: .committed
            )
        }
    }

    /// Always reports a fixed settled cumulative as replayed, ignoring the voucher.
    struct ReplayTransport: CommitTransport {
        let settled: String
        func commit(directive: MeteringDirective, payload: CommitPayload) async throws -> CommitReceipt {
            CommitReceipt(
                deliveryId: directive.deliveryId, sessionId: directive.sessionId,
                amount: directive.amount, cumulative: settled, status: .replayed
            )
        }
    }

    private func makeSession(channel: UInt8 = 7) throws -> ActiveSession {
        let signer = try MemorySigner(secretKey: Data(repeating: 42, count: 32))
        return ActiveSession(channelId: try Pubkey(bytes: Data(repeating: channel, count: 32)), signer: signer)
    }

    private func directive(_ session: ActiveSession, amount: Int, deliveryId: String = "d1") -> MeteringDirective {
        MeteringDirective(
            deliveryId: deliveryId, sessionId: session.channelIdString(), amount: String(amount),
            currency: "USDC", sequence: 1, expiresAt: defaultSessionExpiresAt
        )
    }

    @Test
    func ackSendsCommitAndAdvancesWatermark() async throws {
        let session = try makeSession()
        let transport = RecordingTransport()
        let consumer = SessionConsumer(session: session, transport: transport)
        let envelope = MeteredEnvelope(payload: "work", metering: directive(session, amount: 250))

        let delivery = try consumer.accept(envelope)
        #expect(delivery.payload == "work")
        let receipt = try await delivery.ack()

        #expect(receipt.cumulative == "250")
        #expect(receipt.status == .committed)
        #expect(session.cumulative == 250)
        #expect(transport.commits.count == 1)
    }

    @Test
    func commitAliasAndIntoParts() async throws {
        let session = try makeSession()
        session.setExpiresAt(1234)
        let transport = RecordingTransport()
        let consumer = SessionConsumer(session: session, transport: transport)

        let first = try consumer.accept(MeteredEnvelope(payload: "first", metering: directive(session, amount: 50)))
        let receipt = try await first.commit()
        #expect(receipt.cumulative == "50")
        #expect(transport.commits[0].voucher.data.expiresAt == 1234)

        let second = try consumer.accept(MeteredEnvelope(payload: "second", metering: directive(session, amount: 75, deliveryId: "d2")))
        let (payload, metering) = second.intoParts()
        #expect(payload == "second")
        #expect(metering.amount == "75")
    }

    @Test
    func invalidDirectivesRejectedBeforeCommit() async throws {
        let session = try makeSession()
        let transport = RecordingTransport()
        let consumer = SessionConsumer(session: session, transport: transport)

        let wrong = MeteringDirective(
            deliveryId: "d1", sessionId: "other-session", amount: "1", currency: "USDC",
            sequence: 1, expiresAt: defaultSessionExpiresAt
        )
        await #expect(throws: PayKitError.self) { _ = try await consumer.commitDirective(wrong) }

        await #expect(throws: PayKitError.self) { _ = try await consumer.commitDirective(directive(session, amount: 0)) }

        let badAmount = MeteringDirective(
            deliveryId: "d1", sessionId: session.channelIdString(), amount: "bad", currency: "USDC",
            sequence: 1, expiresAt: defaultSessionExpiresAt
        )
        await #expect(throws: PayKitError.self) { _ = try await consumer.commitDirective(badAmount) }

        #expect(transport.commits.isEmpty)
        #expect(session.cumulative == 0)
    }

    @Test
    func failedCommitDoesNotAdvanceWatermark() async throws {
        let session = try makeSession()
        let transport = RecordingTransport()
        transport.fail = true
        let consumer = SessionConsumer(session: session, transport: transport)

        await #expect(throws: PayKitError.self) { _ = try await consumer.commitDirective(directive(session, amount: 250)) }
        #expect(session.cumulative == 0)

        transport.fail = false
        let receipt = try await consumer.commitDirective(directive(session, amount: 250))
        #expect(receipt.cumulative == "250")
        #expect(session.cumulative == 250)
    }

    @Test
    func duplicateDeliveryReplayDoesNotDoubleCount() async throws {
        let session = try makeSession()
        let transport = RecordingTransport()
        let consumer = SessionConsumer(session: session, transport: transport)
        let d = directive(session, amount: 100)

        let r1 = try await consumer.commitDirective(d)
        #expect(r1.status == .committed)
        #expect(session.cumulative == 100)

        let r2 = try await consumer.commitDirective(d)
        #expect(r2.status == .replayed)
        #expect(r2.cumulative == "100")
        #expect(session.cumulative == 100)
        #expect(transport.commits.count == 1)
    }

    @Test
    func replayedReceiptReconcilesToClampedSettled() async throws {
        // Server reports the delivery already settled at 100; the client clamps
        // to the just-prepared voucher (250) → min(100, 250) = 100.
        let session = try makeSession()
        let consumer = SessionConsumer(session: session, transport: ReplayTransport(settled: "100"))
        let receipt = try await consumer.commitDirective(directive(session, amount: 250))
        #expect(receipt.status == .replayed)
        #expect(session.cumulative == 100)
    }

    @Test
    func replayedReceiptNeverRegressesWatermark() async throws {
        let session = try makeSession()
        session.reconcileSettled(300)
        let consumer = SessionConsumer(session: session, transport: ReplayTransport(settled: "100"))
        _ = try await consumer.commitDirective(directive(session, amount: 50))
        #expect(session.cumulative == 300)
    }

    @Test
    func replayedReceiptClampsInflatedServerCumulative() async throws {
        // A buggy/malicious server reports a replay far above the prepared
        // voucher; the watermark clamps to the prepared value (250).
        let session = try makeSession()
        let consumer = SessionConsumer(session: session, transport: ReplayTransport(settled: "1000000"))
        _ = try await consumer.commitDirective(directive(session, amount: 250))
        #expect(session.cumulative == 250)
    }
}
