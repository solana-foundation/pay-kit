import Foundation

/// MPP payment-channel session wire types.
///
/// Mirrors the Rust spine (`rust/crates/mpp/src/protocol/intents/session.rs`)
/// and the Go reference (`go/protocols/mpp/protocol/intents/session.go`)
/// tag-for-tag and key-for-key. The JSON keys are camelCase and equal the Swift
/// property names except where noted (`salt` serializes as a decimal string and
/// reads string-or-number; `VoucherData.cumulativeAmount` also reads the legacy
/// `cumulative` alias; `SessionAction` is an internally-tagged union flattened
/// onto the `action` key).

/// Default voucher/session expiry: 2100-01-01T00:00:00Z, kept under JS
/// `Number.MAX_SAFE_INTEGER`. Matches `DEFAULT_SESSION_EXPIRES_AT`.
public let defaultSessionExpiresAt: Int64 = 4_102_444_800

public enum SessionMode: String, Codable, Equatable, Sendable {
    case push
    case pull
}

public enum SessionPullVoucherStrategy: String, Codable, Equatable, Sendable {
    case clientVoucher
    case operatedVoucher
}

public enum CommitStatus: String, Codable, Equatable, Sendable {
    case committed
    case replayed
}

public struct SessionSplit: Codable, Equatable, Sendable {
    public let recipient: String
    public let bps: UInt16

    public init(recipient: String, bps: UInt16) {
        self.recipient = recipient
        self.bps = bps
    }
}

public struct SessionRequest: Codable, Equatable, Sendable {
    public let cap: String
    public let currency: String
    public let decimals: Int?
    public let network: String?
    public let `operator`: String
    public let recipient: String
    public let splits: [SessionSplit]
    public let programId: String?
    public let description: String?
    public let externalId: String?
    public let minVoucherDelta: String?
    public let modes: [SessionMode]
    public let pullVoucherStrategy: SessionPullVoucherStrategy?
    public let recentBlockhash: String?

    public init(
        cap: String,
        currency: String,
        decimals: Int? = nil,
        network: String? = nil,
        operator: String,
        recipient: String,
        splits: [SessionSplit] = [],
        programId: String? = nil,
        description: String? = nil,
        externalId: String? = nil,
        minVoucherDelta: String? = nil,
        modes: [SessionMode] = [],
        pullVoucherStrategy: SessionPullVoucherStrategy? = nil,
        recentBlockhash: String? = nil
    ) {
        self.cap = cap
        self.currency = currency
        self.decimals = decimals
        self.network = network
        self.operator = `operator`
        self.recipient = recipient
        self.splits = splits
        self.programId = programId
        self.description = description
        self.externalId = externalId
        self.minVoucherDelta = minVoucherDelta
        self.modes = modes
        self.pullVoucherStrategy = pullVoucherStrategy
        self.recentBlockhash = recentBlockhash
    }

    enum CodingKeys: String, CodingKey {
        case cap, currency, decimals, network, `operator`, recipient, splits
        case programId, description, externalId, minVoucherDelta, modes
        case pullVoucherStrategy, recentBlockhash
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        cap = try c.decode(String.self, forKey: .cap)
        currency = try c.decode(String.self, forKey: .currency)
        decimals = try c.decodeIfPresent(Int.self, forKey: .decimals)
        network = try c.decodeIfPresent(String.self, forKey: .network)
        `operator` = try c.decode(String.self, forKey: .operator)
        recipient = try c.decode(String.self, forKey: .recipient)
        splits = try c.decodeIfPresent([SessionSplit].self, forKey: .splits) ?? []
        programId = try c.decodeIfPresent(String.self, forKey: .programId)
        description = try c.decodeIfPresent(String.self, forKey: .description)
        externalId = try c.decodeIfPresent(String.self, forKey: .externalId)
        minVoucherDelta = try c.decodeIfPresent(String.self, forKey: .minVoucherDelta)
        modes = try c.decodeIfPresent([SessionMode].self, forKey: .modes) ?? []
        pullVoucherStrategy = try c.decodeIfPresent(SessionPullVoucherStrategy.self, forKey: .pullVoucherStrategy)
        recentBlockhash = try c.decodeIfPresent(String.self, forKey: .recentBlockhash)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(cap, forKey: .cap)
        try c.encode(currency, forKey: .currency)
        try c.encodeIfPresent(decimals, forKey: .decimals)
        try c.encodeIfPresent(network, forKey: .network)
        try c.encode(`operator`, forKey: .operator)
        try c.encode(recipient, forKey: .recipient)
        if !splits.isEmpty { try c.encode(splits, forKey: .splits) }
        try c.encodeIfPresent(programId, forKey: .programId)
        try c.encodeIfPresent(description, forKey: .description)
        try c.encodeIfPresent(externalId, forKey: .externalId)
        try c.encodeIfPresent(minVoucherDelta, forKey: .minVoucherDelta)
        if !modes.isEmpty { try c.encode(modes, forKey: .modes) }
        try c.encodeIfPresent(pullVoucherStrategy, forKey: .pullVoucherStrategy)
        try c.encodeIfPresent(recentBlockhash, forKey: .recentBlockhash)
    }
}

/// Open-channel action payload. `salt` serializes as a decimal string and reads
/// string-or-number; every other field is omitted when nil except
/// `authorizedSigner` and `signature`, which are always present.
public struct OpenPayload: Codable, Equatable, Sendable {
    public var mode: SessionMode
    public var channelId: String?
    public var deposit: String?
    public var payer: String?
    public var payee: String?
    public var mint: String?
    public var salt: UInt64?
    public var gracePeriod: UInt32?
    public var transaction: String?
    public var tokenAccount: String?
    public var approvedAmount: String?
    public var owner: String?
    public var initMultiDelegateTx: String?
    public var updateDelegationTx: String?
    public var authorizedSigner: String
    public var signature: String

    public init(
        mode: SessionMode,
        channelId: String? = nil,
        deposit: String? = nil,
        payer: String? = nil,
        payee: String? = nil,
        mint: String? = nil,
        salt: UInt64? = nil,
        gracePeriod: UInt32? = nil,
        transaction: String? = nil,
        tokenAccount: String? = nil,
        approvedAmount: String? = nil,
        owner: String? = nil,
        initMultiDelegateTx: String? = nil,
        updateDelegationTx: String? = nil,
        authorizedSigner: String,
        signature: String
    ) {
        self.mode = mode
        self.channelId = channelId
        self.deposit = deposit
        self.payer = payer
        self.payee = payee
        self.mint = mint
        self.salt = salt
        self.gracePeriod = gracePeriod
        self.transaction = transaction
        self.tokenAccount = tokenAccount
        self.approvedAmount = approvedAmount
        self.owner = owner
        self.initMultiDelegateTx = initMultiDelegateTx
        self.updateDelegationTx = updateDelegationTx
        self.authorizedSigner = authorizedSigner
        self.signature = signature
    }

    /// Push payment-channel open with explicit deposit + channel parties.
    public static func paymentChannel(
        mode: SessionMode,
        channelId: String,
        deposit: String,
        payer: String,
        payee: String,
        mint: String,
        salt: UInt64,
        gracePeriod: UInt32,
        authorizedSigner: String,
        signature: String
    ) -> OpenPayload {
        OpenPayload(
            mode: mode,
            channelId: channelId,
            deposit: deposit,
            payer: payer,
            payee: payee,
            mint: mint,
            salt: salt,
            gracePeriod: gracePeriod,
            authorizedSigner: authorizedSigner,
            signature: signature
        )
    }

    /// Minimal push open referencing an already-funded channel.
    public static func push(
        channelId: String,
        deposit: String,
        authorizedSigner: String,
        signature: String
    ) -> OpenPayload {
        OpenPayload(mode: .push, channelId: channelId, deposit: deposit, authorizedSigner: authorizedSigner, signature: signature)
    }

    /// Pull (delegated-allowance) open.
    public static func pull(
        tokenAccount: String,
        approvedAmount: String,
        owner: String,
        authorizedSigner: String,
        signature: String
    ) -> OpenPayload {
        OpenPayload(
            mode: .pull,
            tokenAccount: tokenAccount,
            approvedAmount: approvedAmount,
            owner: owner,
            authorizedSigner: authorizedSigner,
            signature: signature
        )
    }

    /// Attach the server/operator-broadcast open transaction (base64).
    public func withTransaction(_ transaction: String) -> OpenPayload {
        var copy = self
        copy.transaction = transaction
        return copy
    }

    enum CodingKeys: String, CodingKey {
        case mode, channelId, deposit, payer, payee, mint, salt, gracePeriod
        case transaction, tokenAccount, approvedAmount, owner
        case initMultiDelegateTx, updateDelegationTx, authorizedSigner, signature
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode = try c.decode(SessionMode.self, forKey: .mode)
        channelId = try c.decodeIfPresent(String.self, forKey: .channelId)
        deposit = try c.decodeIfPresent(String.self, forKey: .deposit)
        payer = try c.decodeIfPresent(String.self, forKey: .payer)
        payee = try c.decodeIfPresent(String.self, forKey: .payee)
        mint = try c.decodeIfPresent(String.self, forKey: .mint)
        salt = try Self.decodeSalt(c)
        gracePeriod = try c.decodeIfPresent(UInt32.self, forKey: .gracePeriod)
        transaction = try c.decodeIfPresent(String.self, forKey: .transaction)
        tokenAccount = try c.decodeIfPresent(String.self, forKey: .tokenAccount)
        approvedAmount = try c.decodeIfPresent(String.self, forKey: .approvedAmount)
        owner = try c.decodeIfPresent(String.self, forKey: .owner)
        initMultiDelegateTx = try c.decodeIfPresent(String.self, forKey: .initMultiDelegateTx)
        updateDelegationTx = try c.decodeIfPresent(String.self, forKey: .updateDelegationTx)
        authorizedSigner = try c.decode(String.self, forKey: .authorizedSigner)
        signature = try c.decode(String.self, forKey: .signature)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(mode, forKey: .mode)
        try c.encodeIfPresent(channelId, forKey: .channelId)
        try c.encodeIfPresent(deposit, forKey: .deposit)
        try c.encodeIfPresent(payer, forKey: .payer)
        try c.encodeIfPresent(payee, forKey: .payee)
        try c.encodeIfPresent(mint, forKey: .mint)
        // salt always serializes as a decimal string.
        if let salt { try c.encode(String(salt), forKey: .salt) }
        try c.encodeIfPresent(gracePeriod, forKey: .gracePeriod)
        try c.encodeIfPresent(transaction, forKey: .transaction)
        try c.encodeIfPresent(tokenAccount, forKey: .tokenAccount)
        try c.encodeIfPresent(approvedAmount, forKey: .approvedAmount)
        try c.encodeIfPresent(owner, forKey: .owner)
        try c.encodeIfPresent(initMultiDelegateTx, forKey: .initMultiDelegateTx)
        try c.encodeIfPresent(updateDelegationTx, forKey: .updateDelegationTx)
        try c.encode(authorizedSigner, forKey: .authorizedSigner)
        try c.encode(signature, forKey: .signature)
    }

    /// Reads `salt` from either a JSON string ("42") or an integer (42); absent → nil.
    /// A non-integer number (e.g. a float or negative) or a key present with the wrong
    /// type is treated as nil because the first `UInt64` attempt swallows its error via
    /// `try?`; only a present-but-non-numeric string raises.
    private static func decodeSalt(_ c: KeyedDecodingContainer<CodingKeys>) throws -> UInt64? {
        if let value = try? c.decode(UInt64.self, forKey: .salt) {
            return value
        }
        if let s = try c.decodeIfPresent(String.self, forKey: .salt) {
            guard let value = UInt64(s) else {
                throw PayKitError.invalidTransaction("invalid salt string: \(s)")
            }
            return value
        }
        return nil
    }
}

/// The signed-voucher data covered by the Ed25519 signature (minus `nonce`).
public struct VoucherData: Codable, Equatable, Sendable {
    public let channelId: String
    public let cumulative: String
    public let expiresAt: Int64
    public let nonce: UInt64?

    public init(channelId: String, cumulative: String, expiresAt: Int64, nonce: UInt64? = nil) {
        self.channelId = channelId
        self.cumulative = cumulative
        self.expiresAt = expiresAt
        self.nonce = nonce
    }

    enum CodingKeys: String, CodingKey {
        case channelId
        case cumulativeAmount
        case cumulative
        case expiresAt
        case nonce
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        channelId = try c.decode(String.self, forKey: .channelId)
        // Write key is `cumulativeAmount`; accept the legacy `cumulative` alias.
        if let amount = try c.decodeIfPresent(String.self, forKey: .cumulativeAmount) {
            cumulative = amount
        } else {
            cumulative = try c.decode(String.self, forKey: .cumulative)
        }
        expiresAt = try c.decode(Int64.self, forKey: .expiresAt)
        nonce = try c.decodeIfPresent(UInt64.self, forKey: .nonce)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(channelId, forKey: .channelId)
        try c.encode(cumulative, forKey: .cumulativeAmount)
        try c.encode(expiresAt, forKey: .expiresAt)
        try c.encodeIfPresent(nonce, forKey: .nonce)
    }

    /// The 48-byte Ed25519 preimage for this voucher.
    public func messageBytes() throws -> Data {
        let channel = try Pubkey(base58: channelId)
        guard let amount = UInt64(cumulative) else {
            throw PayKitError.invalidTransaction("invalid voucher cumulative: \(cumulative)")
        }
        return PaymentChannels.voucherMessageBytes(channelId: channel, cumulative: amount, expiresAt: expiresAt)
    }
}

public struct SignedVoucher: Codable, Equatable, Sendable {
    public let data: VoucherData
    public let signature: String

    public init(data: VoucherData, signature: String) {
        self.data = data
        self.signature = signature
    }
}

public struct VoucherPayload: Codable, Equatable, Sendable {
    public let voucher: SignedVoucher
    public init(voucher: SignedVoucher) { self.voucher = voucher }
}

public struct CommitPayload: Codable, Equatable, Sendable {
    public let deliveryId: String
    public let voucher: SignedVoucher
    public init(deliveryId: String, voucher: SignedVoucher) {
        self.deliveryId = deliveryId
        self.voucher = voucher
    }
}

public struct TopUpPayload: Codable, Equatable, Sendable {
    public let channelId: String
    public let newDeposit: String
    public let signature: String
    public init(channelId: String, newDeposit: String, signature: String) {
        self.channelId = channelId
        self.newDeposit = newDeposit
        self.signature = signature
    }
}

public struct ClosePayload: Codable, Equatable, Sendable {
    public let channelId: String
    public let voucher: SignedVoucher?
    public init(channelId: String, voucher: SignedVoucher? = nil) {
        self.channelId = channelId
        self.voucher = voucher
    }
}

public struct MeteringDirective: Codable, Equatable, Sendable {
    public let deliveryId: String
    public let sessionId: String
    public let amount: String
    public let currency: String
    public let sequence: UInt64
    public let expiresAt: Int64
    public let commitUrl: String?
    public let proof: String?

    public init(
        deliveryId: String,
        sessionId: String,
        amount: String,
        currency: String,
        sequence: UInt64,
        expiresAt: Int64,
        commitUrl: String? = nil,
        proof: String? = nil
    ) {
        self.deliveryId = deliveryId
        self.sessionId = sessionId
        self.amount = amount
        self.currency = currency
        self.sequence = sequence
        self.expiresAt = expiresAt
        self.commitUrl = commitUrl
        self.proof = proof
    }

    /// Parse `amount` as base units. Mirrors `amount_base_units`.
    public func amountBaseUnits() throws -> UInt64 {
        guard let value = UInt64(amount) else {
            throw PayKitError.invalidTransaction("invalid metering amount: \(amount)")
        }
        return value
    }
}

public struct MeteringUsage: Codable, Equatable, Sendable {
    public let deliveryId: String
    public let amount: String
    public init(deliveryId: String, amount: String) {
        self.deliveryId = deliveryId
        self.amount = amount
    }

    public func amountBaseUnits() throws -> UInt64 {
        guard let value = UInt64(amount) else {
            throw PayKitError.invalidTransaction("invalid metering usage amount: \(amount)")
        }
        return value
    }
}

public struct MeteredEnvelope<Payload: Codable & Equatable & Sendable>: Codable, Equatable, Sendable {
    public let payload: Payload
    public let metering: MeteringDirective
    public init(payload: Payload, metering: MeteringDirective) {
        self.payload = payload
        self.metering = metering
    }
}

public struct CommitReceipt: Codable, Equatable, Sendable {
    public let deliveryId: String
    public let sessionId: String
    public let amount: String
    public let cumulative: String
    public let status: CommitStatus

    public init(deliveryId: String, sessionId: String, amount: String, cumulative: String, status: CommitStatus) {
        self.deliveryId = deliveryId
        self.sessionId = sessionId
        self.amount = amount
        self.cumulative = cumulative
        self.status = status
    }
}

/// Internally-tagged session action union. The discriminator lives on the
/// `action` key and the payload fields are flattened alongside it, e.g.
/// `{"action":"open","mode":"pull",...}`. The TopUp tag is camelCase `topUp`.
public enum SessionAction: Equatable, Sendable {
    case open(OpenPayload)
    case voucher(VoucherPayload)
    case commit(CommitPayload)
    case topUp(TopUpPayload)
    case close(ClosePayload)

    private enum ActionKey: String, CodingKey { case action }
}

extension SessionAction: Codable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: ActionKey.self)
        let action = try c.decode(String.self, forKey: .action)
        switch action {
        case "open": self = .open(try OpenPayload(from: decoder))
        case "voucher": self = .voucher(try VoucherPayload(from: decoder))
        case "commit": self = .commit(try CommitPayload(from: decoder))
        case "topUp": self = .topUp(try TopUpPayload(from: decoder))
        case "close": self = .close(try ClosePayload(from: decoder))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: ActionKey.action, in: c, debugDescription: "unknown session action \(action)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        // Encode the payload (writes its own keys) then inject the action tag
        // into the same keyed container.
        switch self {
        case let .open(p): try p.encode(to: encoder)
        case let .voucher(p): try p.encode(to: encoder)
        case let .commit(p): try p.encode(to: encoder)
        case let .topUp(p): try p.encode(to: encoder)
        case let .close(p): try p.encode(to: encoder)
        }
        var c = encoder.container(keyedBy: ActionKey.self)
        try c.encode(tag, forKey: .action)
    }

    private var tag: String {
        switch self {
        case .open: return "open"
        case .voucher: return "voucher"
        case .commit: return "commit"
        case .topUp: return "topUp"
        case .close: return "close"
        }
    }
}
