import Foundation

/// Transport that commits a signed voucher to the session server and returns a
/// receipt. Mirrors the Rust/Go `CommitTransport`.
public protocol CommitTransport: Sendable {
    func commit(directive: MeteringDirective, payload: CommitPayload) async throws -> CommitReceipt
}

/// Client side of metered delivery: signs a voucher per directive, commits it
/// through the transport, and advances the local watermark only on success.
/// Mirrors Go `SessionConsumer` (`go/protocols/mpp/client/session_consumer.go`).
public final class SessionConsumer {
    public let session: ActiveSession
    public let transport: CommitTransport

    public init(session: ActiveSession, transport: CommitTransport) {
        self.session = session
        self.transport = transport
    }

    /// Validate the directive against the active session and wrap it for ack.
    public func accept<Payload: Codable & Equatable & Sendable>(
        _ envelope: MeteredEnvelope<Payload>
    ) throws -> MeteredDelivery<Payload> {
        try validateDirective(envelope.metering)
        return MeteredDelivery(consumer: self, payload: envelope.payload, metering: envelope.metering)
    }

    /// Sign a voucher for the directive amount, commit it, and advance the
    /// watermark. Rejects a mismatched session, a non-integer amount, or a zero
    /// amount before committing. On a committed receipt the prepared voucher is
    /// recorded; on a replayed receipt the watermark reconciles to the settled
    /// cumulative, clamped to the just-prepared voucher (the server is untrusted)
    /// and never regressing.
    @discardableResult
    public func commitDirective(_ directive: MeteringDirective) async throws -> CommitReceipt {
        try validateDirective(directive)
        let amount = try directive.amountBaseUnits()
        guard amount != 0 else {
            throw MppError.invalidTransaction("metered delivery amount must be greater than zero")
        }

        let voucher = try await session.prepareIncrement(amount)
        let payload = CommitPayload(deliveryId: directive.deliveryId, voucher: voucher)
        let receipt = try await transport.commit(directive: directive, payload: payload)

        switch receipt.status {
        case .replayed:
            guard let settled = UInt64(receipt.cumulative) else {
                throw MppError.invalidTransaction("invalid replayed receipt cumulative: \(receipt.cumulative)")
            }
            guard let prepared = UInt64(voucher.data.cumulative) else {
                throw MppError.invalidTransaction("invalid prepared voucher cumulative: \(voucher.data.cumulative)")
            }
            session.reconcileSettled(min(settled, prepared))
        case .committed:
            try session.recordVoucher(voucher)
        }
        return receipt
    }

    private func validateDirective(_ directive: MeteringDirective) throws {
        let channelId = session.channelIdString()
        guard directive.sessionId == channelId else {
            throw MppError.invalidTransaction(
                "metered delivery session \(directive.sessionId) does not match active session \(channelId)"
            )
        }
    }
}

/// A validated metered delivery awaiting acknowledgement. `ack`/`commit` sign
/// and commit the voucher; `intoParts` releases the payload without committing.
public final class MeteredDelivery<Payload> {
    private let consumer: SessionConsumer
    public let payload: Payload
    public let metering: MeteringDirective

    init(consumer: SessionConsumer, payload: Payload, metering: MeteringDirective) {
        self.consumer = consumer
        self.payload = payload
        self.metering = metering
    }

    @discardableResult
    public func ack() async throws -> CommitReceipt {
        try await consumer.commitDirective(metering)
    }

    @discardableResult
    public func commit() async throws -> CommitReceipt {
        try await ack()
    }

    public func intoParts() -> (Payload, MeteringDirective) {
        (payload, metering)
    }
}
