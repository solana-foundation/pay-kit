import Foundation
import Testing
@testable import SolanaPayKit

/// ActiveSession watermark, nonce, expiry, and action-builder behavior,
/// mirroring the Rust spine `client/session.rs` golden tests and the Go
/// `ReconcileSettled` lost-response clamp.
@Suite("ActiveSession", .serialized)
struct ActiveSessionTests {
    private func makeSession(seed: UInt8 = 42, channel: UInt8 = 7) throws -> ActiveSession {
        let signer = try MemorySigner(secretKey: Data(repeating: seed, count: 32))
        let channelId = try Pubkey(bytes: Data(repeating: channel, count: 32))
        return ActiveSession(channelId: channelId, signer: signer)
    }

    @Test
    func prepareDoesNotAdvanceButRecordDoes() async throws {
        let session = try makeSession()
        let prepared = try await session.prepareIncrement(75)
        #expect(prepared.data.cumulative == "75")
        #expect(prepared.data.nonce == 1)
        #expect(session.cumulative == 0)

        try session.recordVoucher(prepared)
        #expect(session.cumulative == 75)

        // Recording the same voucher again is non-increasing → rejected.
        #expect(throws: PayKitError.self) { try session.recordVoucher(prepared) }
    }

    @Test
    func signIncrementAdvancesWatermarkAndNonce() async throws {
        let session = try makeSession()
        let first = try await session.signIncrement(100)
        #expect(first.data.cumulative == "100")
        #expect(first.data.nonce == 1)
        #expect(session.cumulative == 100)

        let second = try await session.signIncrement(10)
        #expect(second.data.cumulative == "110")
        #expect(second.data.nonce == 2)
        #expect(session.cumulative == 110)
    }

    @Test
    func signVoucherRejectsNonIncreasingAndZero() async throws {
        let session = try makeSession()
        _ = try await session.signIncrement(100)
        await #expect(throws: PayKitError.self) { _ = try await session.signVoucher(100) }
        await #expect(throws: PayKitError.self) { _ = try await session.signVoucher(50) }

        let fresh = try makeSession(seed: 9, channel: 8)
        await #expect(throws: PayKitError.self) { _ = try await fresh.signVoucher(0) }
    }

    @Test
    func recordVoucherRejectsInvalidCumulativeAndDefaultsNonce() throws {
        let session = try makeSession()
        let bad = SignedVoucher(
            data: VoucherData(channelId: session.channelIdString(), cumulative: "not-a-number", expiresAt: defaultSessionExpiresAt),
            signature: "sig"
        )
        #expect(throws: PayKitError.self) { try session.recordVoucher(bad) }

        // Missing nonce defaults to current nonce + 1.
        let noNonce = SignedVoucher(
            data: VoucherData(channelId: session.channelIdString(), cumulative: "15", expiresAt: defaultSessionExpiresAt, nonce: nil),
            signature: "sig"
        )
        try session.recordVoucher(noNonce)
        #expect(session.cumulative == 15)
    }

    @Test
    func recordVoucherRejectsForeignChannel() throws {
        let session = try makeSession()
        let foreign = SignedVoucher(
            data: VoucherData(channelId: "11111111111111111111111111111112", cumulative: "10", expiresAt: defaultSessionExpiresAt),
            signature: "sig"
        )
        #expect(throws: PayKitError.self) { try session.recordVoucher(foreign) }
        #expect(session.cumulative == 0)
    }

    @Test
    func reconcileSettledAdvancesAndNeverRegresses() throws {
        let session = try makeSession()
        session.reconcileSettled(300)
        #expect(session.cumulative == 300)
        // A stale settled value never regresses the watermark.
        session.reconcileSettled(100)
        #expect(session.cumulative == 300)
    }

    @Test
    func expiresAtControlsVoucherExpiry() async throws {
        let session = try makeSession()
        session.setExpiresAt(1234)
        let v1 = try await session.prepareIncrement(10)
        #expect(v1.data.expiresAt == 1234)

        session.setExpiresAt(5678)
        let v2 = try await session.prepareIncrement(10)
        #expect(v2.data.expiresAt == 5678)
    }

    @Test
    func closeActionVoucherFollowsFinalIncrement() async throws {
        let session = try makeSession()
        if case let .close(payload) = try await session.closeAction(finalIncrement: nil) {
            #expect(payload.voucher == nil)
            #expect(payload.channelId == session.channelIdString())
        } else {
            Issue.record("expected close action")
        }

        _ = try await session.signIncrement(100)
        if case let .close(payload) = try await session.closeAction(finalIncrement: 50) {
            #expect(payload.voucher?.data.cumulative == "150")
        } else {
            Issue.record("expected close action")
        }

        // A zero final increment carries no voucher.
        if case let .close(payload) = try await session.closeAction(finalIncrement: 0) {
            #expect(payload.voucher == nil)
        } else {
            Issue.record("expected close action")
        }
    }

    @Test
    func openAndTopupActionFields() async throws {
        let session = try makeSession()
        if case let .open(payload) = session.openAction(deposit: 1_000_000, openTxSignature: "txsig123") {
            #expect(payload.mode == .push)
            #expect(payload.deposit == "1000000")
            #expect(payload.signature == "txsig123")
            #expect(payload.channelId == session.channelIdString())
            #expect(payload.authorizedSigner == session.authorizedSigner())
        } else {
            Issue.record("expected open action")
        }

        if case let .open(payload) = session.openPullAction(
            tokenAccount: "payer-ata-123",
            approvedAmount: 5_000_000,
            owner: "wallet123",
            approveTxSignature: "approvesig"
        ) {
            #expect(payload.mode == .pull)
            #expect(payload.approvedAmount == "5000000")
            #expect(payload.owner == "wallet123")
            #expect(payload.tokenAccount == "payer-ata-123")
            #expect(payload.channelId == nil)
        } else {
            Issue.record("expected open action")
        }

        if case let .topUp(payload) = session.topupAction(newDeposit: 5_000_000, topupTxSignature: "topuptx") {
            #expect(payload.newDeposit == "5000000")
            #expect(payload.signature == "topuptx")
            #expect(payload.channelId == session.channelIdString())
        } else {
            Issue.record("expected topUp action")
        }

        if case let .open(payload) = session.openPaymentChannelAction(
            mode: .pull, deposit: 9_000, payer: "Payer", payee: "Payee", mint: "Mint", salt: 42, gracePeriod: 60,
            openSlot: 5000, signature: "open-sig"
        ) {
            #expect(payload.mode == .pull)
            #expect(payload.deposit == "9000")
            #expect(payload.salt == 42)
            #expect(payload.gracePeriod == 60)
            // The builder's program-named openSlot crosses HTTP as recentSlot.
            #expect(payload.recentSlot == 5000)
            #expect(payload.signature == "open-sig")
        } else {
            Issue.record("expected open action")
        }
    }
}
