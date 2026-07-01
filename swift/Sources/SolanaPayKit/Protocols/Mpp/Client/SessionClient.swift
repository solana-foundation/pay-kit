import Foundation

/// A live metered session bound to one payment channel.
///
/// Holds the cumulative watermark, request nonce, and voucher expiry, and signs
/// monotonically-increasing vouchers with the session signer. Mirrors the Go
/// reference `ActiveSession` (`go/protocols/mpp/client/session.go`) including the
/// `ReconcileSettled` lost-response clamp. Sessions are single-threaded; the
/// type is a reference type (mutating signs advance the watermark) and is not
/// `Sendable`.
public final class ActiveSession {
    public let channelId: Pubkey
    public private(set) var cumulative: UInt64
    private var nonce: UInt64
    private var expiresAt: Int64
    private let signer: SolanaSigner

    public init(channelId: Pubkey, signer: SolanaSigner, cumulative: UInt64 = 0, expiresAt: Int64 = defaultSessionExpiresAt) {
        self.channelId = channelId
        self.signer = signer
        self.cumulative = cumulative
        self.nonce = 0
        self.expiresAt = expiresAt
    }

    public func setExpiresAt(_ value: Int64) {
        expiresAt = value
    }

    /// base58 of the session signer's public key (the on-chain authorized signer).
    public func authorizedSigner() -> String {
        signer.address
    }

    public func channelIdString() -> String {
        channelId.base58
    }

    // MARK: - Voucher signing

    /// Sign a voucher at an absolute cumulative without advancing the watermark
    /// (retry-safe). Rejects a cumulative that does not strictly exceed the
    /// current watermark.
    public func prepareVoucher(_ cumulative: UInt64) async throws -> SignedVoucher {
        guard cumulative > self.cumulative else {
            throw PayKitError.invalidTransaction(
                "voucher cumulative \(cumulative) must exceed current watermark \(self.cumulative)"
            )
        }
        let data = VoucherData(
            channelId: channelIdString(),
            cumulative: String(cumulative),
            expiresAt: expiresAt,
            nonce: nonce + 1
        )
        let signature = try await signer.sign(message: try data.messageBytes())
        return SignedVoucher(data: data, signature: Base58.encode(signature))
    }

    /// Sign a voucher `amount` above the current watermark (no advance).
    public func prepareIncrement(_ amount: UInt64) async throws -> SignedVoucher {
        try await prepareVoucher(try addToWatermark(amount))
    }

    /// Advance the watermark to a recorded voucher: rejects a voucher bound to a
    /// different channel, a non-increasing cumulative, or an unparseable
    /// cumulative; advances the nonce to at least `nonce + 1` (or the voucher's
    /// nonce when higher). Mirrors Go `RecordVoucher`.
    public func recordVoucher(_ voucher: SignedVoucher) throws {
        guard voucher.data.channelId == channelIdString() else {
            throw PayKitError.invalidTransaction(
                "voucher channel \(voucher.data.channelId) does not match active session \(channelIdString())"
            )
        }
        guard let cumulative = UInt64(voucher.data.cumulative) else {
            throw PayKitError.invalidTransaction("invalid voucher cumulative")
        }
        guard cumulative > self.cumulative else {
            throw PayKitError.invalidTransaction(
                "voucher cumulative \(cumulative) must exceed current watermark \(self.cumulative)"
            )
        }
        self.cumulative = cumulative
        var candidate = self.nonce + 1
        if let nonce = voucher.data.nonce, nonce > candidate { candidate = nonce }
        self.nonce = candidate
    }

    /// Reconcile the watermark to a server-settled cumulative (e.g. a replayed
    /// commit receipt). Advances to `settled` only when it is ahead and never
    /// regresses; advancing also bumps the nonce by one. Mirrors Go
    /// `ReconcileSettled` (the #162 lost-response fix).
    public func reconcileSettled(_ settled: UInt64) {
        if settled > cumulative {
            cumulative = settled
            nonce += 1
        }
    }

    /// Sign an absolute voucher and advance the watermark.
    @discardableResult
    public func signVoucher(_ cumulative: UInt64) async throws -> SignedVoucher {
        let voucher = try await prepareVoucher(cumulative)
        try recordVoucher(voucher)
        return voucher
    }

    /// Sign an increment voucher and advance the watermark.
    @discardableResult
    public func signIncrement(_ amount: UInt64) async throws -> SignedVoucher {
        try await signVoucher(try addToWatermark(amount))
    }

    // MARK: - Action builders

    public func voucherAction(_ amount: UInt64) async throws -> SessionAction {
        .voucher(VoucherPayload(voucher: try await signIncrement(amount)))
    }

    /// Cooperative close. A `finalIncrement` greater than zero signs one last
    /// voucher before closing; `nil` or `0` closes without a voucher.
    public func closeAction(finalIncrement: UInt64?) async throws -> SessionAction {
        var voucher: SignedVoucher?
        if let amount = finalIncrement, amount > 0 {
            voucher = try await signIncrement(amount)
        }
        return .close(ClosePayload(channelId: channelIdString(), voucher: voucher))
    }

    public func openAction(deposit: UInt64, openTxSignature: String) -> SessionAction {
        .open(OpenPayload.push(
            channelId: channelIdString(),
            deposit: String(deposit),
            authorizedSigner: authorizedSigner(),
            signature: openTxSignature
        ))
    }

    public func openPaymentChannelAction(
        mode: SessionMode = .push,
        deposit: UInt64,
        payer: String,
        payee: String,
        mint: String,
        salt: UInt64,
        gracePeriod: UInt32,
        signature: String
    ) -> SessionAction {
        .open(OpenPayload.paymentChannel(
            mode: mode,
            channelId: channelIdString(),
            deposit: String(deposit),
            payer: payer,
            payee: payee,
            mint: mint,
            salt: salt,
            gracePeriod: gracePeriod,
            authorizedSigner: authorizedSigner(),
            signature: signature
        ))
    }

    public func openPullAction(
        tokenAccount: String,
        approvedAmount: UInt64,
        owner: String,
        approveTxSignature: String
    ) -> SessionAction {
        .open(OpenPayload.pull(
            tokenAccount: tokenAccount,
            approvedAmount: String(approvedAmount),
            owner: owner,
            authorizedSigner: authorizedSigner(),
            signature: approveTxSignature
        ))
    }

    public func topupAction(newDeposit: UInt64, topupTxSignature: String) -> SessionAction {
        .topUp(TopUpPayload(
            channelId: channelIdString(),
            newDeposit: String(newDeposit),
            signature: topupTxSignature
        ))
    }

    private func addToWatermark(_ amount: UInt64) throws -> UInt64 {
        let (sum, overflow) = cumulative.addingReportingOverflow(amount)
        guard !overflow else {
            throw PayKitError.invalidTransaction("voucher cumulative overflow adding \(amount) to \(cumulative)")
        }
        return sum
    }
}

// MARK: - Payment-channel session opener

/// Placeholder operator signature: the server fills its fee-payer slot before
/// broadcasting the open transaction.
public let pendingServerSignature = String(repeating: "1", count: 64)

/// Derived channel parameters for an open.
public struct PaymentChannelOpen: Sendable {
    public let channelId: Pubkey
    public let payer: Pubkey
    public let payee: Pubkey
    public let mint: Pubkey
    public let authorizedSigner: Pubkey
    public let salt: UInt64
    public let deposit: UInt64
    public let gracePeriod: UInt32
    public let recipients: [PaymentChannels.Distribution]
    public let tokenProgram: Pubkey
    public let programId: Pubkey

    func openPayload(mode: SessionMode, signature: String) -> OpenPayload {
        OpenPayload.paymentChannel(
            mode: mode,
            channelId: channelId.base58,
            deposit: String(deposit),
            payer: payer.base58,
            payee: payee.base58,
            mint: mint.base58,
            salt: salt,
            gracePeriod: gracePeriod,
            authorizedSigner: authorizedSigner.base58,
            signature: signature
        )
    }
}

/// Per-channel open overrides; unset fields fall back to challenge-derived defaults.
public struct PaymentChannelOpenOptions: Sendable {
    public var deposit: UInt64?
    public var gracePeriod: UInt32?
    public var programId: Pubkey?
    public var recipients: [PaymentChannels.Distribution]?
    public var salt: UInt64?
    public var tokenProgram: Pubkey?

    public init(
        deposit: UInt64? = nil,
        gracePeriod: UInt32? = nil,
        programId: Pubkey? = nil,
        recipients: [PaymentChannels.Distribution]? = nil,
        salt: UInt64? = nil,
        tokenProgram: Pubkey? = nil
    ) {
        self.deposit = deposit
        self.gracePeriod = gracePeriod
        self.programId = programId
        self.recipients = recipients
        self.salt = salt
        self.tokenProgram = tokenProgram
    }
}

public struct PaymentChannelSessionOpenOptions: Sendable {
    public var open: PaymentChannelOpenOptions
    public var signature: String?
    public var cumulative: UInt64?
    public var expiresAt: Int64?

    public init(
        open: PaymentChannelOpenOptions = .init(),
        signature: String? = nil,
        cumulative: UInt64? = nil,
        expiresAt: Int64? = nil
    ) {
        self.open = open
        self.signature = signature
        self.cumulative = cumulative
        self.expiresAt = expiresAt
    }
}

/// Result of opening a payment-channel session client-side.
public struct PaymentChannelSessionOpen {
    public let open: PaymentChannelOpen
    public let session: ActiveSession
    public let action: SessionAction
}

public enum PaymentChannelSession {
    /// Build a pull + clientVoucher payment-channel session open. The payer
    /// partial-signs the open transaction; the operator (fee payer) co-signs and
    /// broadcasts. `recentBlockhash` is base58. Mirrors
    /// `create_payment_channel_session_opener`.
    public static func open(
        request: SessionRequest,
        payerSigner: SolanaSigner,
        sessionSigner: SolanaSigner,
        recentBlockhash: String,
        options: PaymentChannelSessionOpenOptions = .init()
    ) async throws -> PaymentChannelSessionOpen {
        try ensureClientVoucherPull(request)
        let authorizedSigner = try Pubkey(bytes: sessionSigner.publicKey)
        let feePayer = try Pubkey(base58: request.operator)
        let payer = try Pubkey(bytes: payerSigner.publicKey)
        let open = try deriveOpen(request: request, payer: payer, authorizedSigner: authorizedSigner, options: options.open)

        let blockhash = try Base58.decode(recentBlockhash)
        guard blockhash.count == 32 else {
            throw PayKitError.invalidTransaction("recentBlockhash must decode to 32 bytes")
        }
        let tx = try await PaymentChannels.buildOpenTransaction(
            payer: payerSigner,
            payee: open.payee,
            mint: open.mint,
            authorizedSigner: open.authorizedSigner,
            salt: open.salt,
            deposit: open.deposit,
            gracePeriod: open.gracePeriod,
            recipients: open.recipients,
            tokenProgram: open.tokenProgram,
            programId: open.programId,
            feePayer: feePayer,
            recentBlockhash: blockhash
        )

        let session = ActiveSession(
            channelId: open.channelId,
            signer: sessionSigner,
            cumulative: options.cumulative ?? 0,
            expiresAt: options.expiresAt ?? defaultSessionExpiresAt
        )
        let signature = options.signature ?? pendingServerSignature
        let action = SessionAction.open(open.openPayload(mode: .pull, signature: signature).withTransaction(tx.transaction))
        return PaymentChannelSessionOpen(open: open, session: session, action: action)
    }

    static func ensureClientVoucherPull(_ request: SessionRequest) throws {
        guard request.modes.contains(.pull) else {
            throw PayKitError.invalidTransaction("session challenge does not advertise pull mode")
        }
        guard request.pullVoucherStrategy == .clientVoucher else {
            throw PayKitError.invalidTransaction("session challenge does not advertise pull + clientVoucher")
        }
    }

    static func deriveOpen(
        request: SessionRequest,
        payer: Pubkey,
        authorizedSigner: Pubkey,
        options: PaymentChannelOpenOptions
    ) throws -> PaymentChannelOpen {
        guard let mintString = Mints.resolveChargeMint(currency: request.currency, network: request.network) else {
            throw PayKitError.invalidTransaction("session payment channels require an SPL token")
        }
        let mint = try Pubkey(base58: mintString)
        let payee: Pubkey
        do { payee = try Pubkey(base58: request.recipient) } catch {
            throw PayKitError.invalidPubkey("invalid recipient \(request.recipient)")
        }
        let deposit: UInt64
        if let explicit = options.deposit {
            deposit = explicit
        } else if let parsed = UInt64(request.cap) {
            deposit = parsed
        } else {
            throw PayKitError.invalidTransaction("invalid session cap: \(request.cap)")
        }
        let gracePeriod = options.gracePeriod ?? PaymentChannels.defaultGracePeriodSeconds
        let programId: Pubkey
        if let explicit = options.programId {
            programId = explicit
        } else if let requested = request.programId {
            do { programId = try Pubkey(base58: requested) } catch {
                throw PayKitError.invalidPubkey("invalid programId \(requested)")
            }
        } else {
            programId = PaymentChannels.programId
        }
        let tokenProgram: Pubkey
        if let explicit = options.tokenProgram {
            tokenProgram = explicit
        } else {
            tokenProgram = try Pubkey(base58: Mints.defaultTokenProgram(currency: request.currency, cluster: request.network))
        }
        let recipients: [PaymentChannels.Distribution]
        if let explicit = options.recipients {
            recipients = explicit
        } else {
            recipients = try request.splits.map { split in
                let recipient: Pubkey
                do { recipient = try Pubkey(base58: split.recipient) } catch {
                    throw PayKitError.invalidPubkey("invalid split recipient \(split.recipient)")
                }
                return PaymentChannels.Distribution(recipient: recipient, bps: split.bps)
            }
        }
        let salt = options.salt ?? PaymentChannels.uniqueSalt()
        let channelId = try PaymentChannels.findChannelPda(
            payer: payer, payee: payee, mint: mint, authorizedSigner: authorizedSigner, salt: salt, programId: programId
        )
        return PaymentChannelOpen(
            channelId: channelId,
            payer: payer,
            payee: payee,
            mint: mint,
            authorizedSigner: authorizedSigner,
            salt: salt,
            deposit: deposit,
            gracePeriod: gracePeriod,
            recipients: recipients,
            tokenProgram: tokenProgram,
            programId: programId
        )
    }
}

// MARK: - Session credential framing + challenge dispatch

private struct SessionCredential: Encodable {
    let challenge: ChallengeEcho
    let payload: SessionAction
}

/// Build an `Authorization: Payment <base64url(credential)>` value for a session
/// action, echoing the challenge. Mirrors Go `SerializeSessionCredential`.
public func serializeSessionCredential(challenge: ChallengeEcho, action: SessionAction) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(SessionCredential(challenge: challenge, payload: action))
    return "\(MppHeaders.paymentScheme) \(Base64URL.encode(data))"
}

extension PaymentChallenge {
    /// Require a `solana`/`session` challenge before opening a session.
    public func requireSolanaSession() throws {
        guard method == "solana", intent == "session" else {
            throw PayKitError.unsupportedChallenge(method: method, intent: intent)
        }
    }

    /// Decode the base64url-encoded session request carried by the challenge.
    public var sessionRequest: SessionRequest {
        get throws {
            guard request.utf8.count <= MppHeaders.maxTokenLength else {
                throw PayKitError.invalidHeader
            }
            let data = try Base64URL.decode(request)
            do {
                return try JSONDecoder().decode(SessionRequest.self, from: data)
            } catch {
                throw PayKitError.invalidJSON(String(describing: error))
            }
        }
    }
}
