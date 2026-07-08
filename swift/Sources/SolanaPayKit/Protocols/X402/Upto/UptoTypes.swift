import Foundation

// MARK: - x402 wire types (upto scheme, payment-channel asset transfer method)

/// `upto` scheme identifier.
public let X402UptoScheme: String = "upto"

/// Payment-channel asset transfer method (normative SVM backend for `upto`).
public let X402UptoAssetTransferMethod: String = "payment-channel"

/// The `extra` object on an `upto` requirement.
///
/// Carries the operator binding and the server-prefetched blockhash + slot the
/// client needs to build the channel `open`. `facilitatorFee` is omitted from
/// the wire when `0`; every other absent field is `nil`.
public struct X402UptoExtra: Codable, Sendable, Equatable {
    /// Asset transfer method; must equal `"payment-channel"` for the SVM backend.
    public let assetTransferMethod: String
    /// Token program address (legacy SPL or Token-2022); defaults to legacy SPL.
    public let tokenProgram: String?
    /// Operator/facilitator key: channel payee, fee payer, rent payer, and
    /// voucher signer. Required.
    public let facilitatorAddress: String
    /// Facilitator cut in basis points (0..10000) of the settled amount; the
    /// beneficiary receives `10000 - facilitatorFee`. Omitted from JSON when `0`.
    public let facilitatorFee: Int
    /// Channel program id; defaults to the canonical deployment when absent.
    public let channelProgram: String?
    /// Server-prefetched recent blockhash for the open transaction.
    public let recentBlockhash: String?
    /// Last block height at which `recentBlockhash` is valid (decimal string).
    public let lastValidBlockHeight: String?
    /// Server-prefetched current slot for the open (decimal string; the same
    /// RPC call that prefetches `recentBlockhash` returns it). Becomes the
    /// program's `openSlot`: it seeds the channel PDA and rides in `openArgs`.
    public let recentSlot: String?
    /// Earliest activation time (Unix seconds).
    public let validAfter: Int?

    public init(
        assetTransferMethod: String,
        tokenProgram: String? = nil,
        facilitatorAddress: String,
        facilitatorFee: Int = 0,
        channelProgram: String? = nil,
        recentBlockhash: String? = nil,
        lastValidBlockHeight: String? = nil,
        recentSlot: String? = nil,
        validAfter: Int? = nil
    ) {
        self.assetTransferMethod = assetTransferMethod
        self.tokenProgram = tokenProgram
        self.facilitatorAddress = facilitatorAddress
        self.facilitatorFee = facilitatorFee
        self.channelProgram = channelProgram
        self.recentBlockhash = recentBlockhash
        self.lastValidBlockHeight = lastValidBlockHeight
        self.recentSlot = recentSlot
        self.validAfter = validAfter
    }

    private enum CodingKeys: String, CodingKey {
        case assetTransferMethod, tokenProgram, facilitatorAddress, facilitatorFee
        case channelProgram, recentBlockhash, lastValidBlockHeight, recentSlot, validAfter
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        assetTransferMethod = try container.decode(String.self, forKey: .assetTransferMethod)
        tokenProgram = try container.decodeIfPresent(String.self, forKey: .tokenProgram)
        facilitatorAddress = try container.decode(String.self, forKey: .facilitatorAddress)
        facilitatorFee = try container.decodeIfPresent(Int.self, forKey: .facilitatorFee) ?? 0
        channelProgram = try container.decodeIfPresent(String.self, forKey: .channelProgram)
        recentBlockhash = try container.decodeIfPresent(String.self, forKey: .recentBlockhash)
        lastValidBlockHeight = try container.decodeIfPresent(String.self, forKey: .lastValidBlockHeight)
        recentSlot = try container.decodeIfPresent(String.self, forKey: .recentSlot)
        validAfter = try container.decodeIfPresent(Int.self, forKey: .validAfter)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(assetTransferMethod, forKey: .assetTransferMethod)
        try container.encodeIfPresent(tokenProgram, forKey: .tokenProgram)
        try container.encode(facilitatorAddress, forKey: .facilitatorAddress)
        // A zero fee is omitted from the wire; only a non-zero cut is emitted.
        if facilitatorFee != 0 {
            try container.encode(facilitatorFee, forKey: .facilitatorFee)
        }
        try container.encodeIfPresent(channelProgram, forKey: .channelProgram)
        try container.encodeIfPresent(recentBlockhash, forKey: .recentBlockhash)
        try container.encodeIfPresent(lastValidBlockHeight, forKey: .lastValidBlockHeight)
        try container.encodeIfPresent(recentSlot, forKey: .recentSlot)
        try container.encodeIfPresent(validAfter, forKey: .validAfter)
    }
}

/// An `upto` payment requirement (one `accepts` entry in a 402 challenge).
///
/// Preserves the verbatim challenge object (`raw`) so the client can echo it
/// unchanged into the `Payment-Signature` envelope's `accepted` field; the
/// server reads `scheme`/`network` out of that echoed object.
public struct X402UptoRequirements: Codable, Sendable {
    /// Scheme identifier; defaults to `"upto"`.
    public let scheme: String
    /// CAIP-2 network identifier.
    public let network: String
    /// Maximum authorized amount (base units, decimal string).
    public let amount: String
    /// SPL mint address (or a known symbol).
    public let asset: String
    /// Base58 recipient (the beneficiary).
    public let payTo: String
    /// Completion window in seconds.
    public let maxTimeoutSeconds: Int
    /// Scheme-specific data.
    public let extra: X402UptoExtra
    /// Verbatim offered object as received on the wire, echoed back unchanged in
    /// the outbound envelope's `accepted` field. `nil` for in-code entries.
    public let raw: JSONValue?

    public init(
        scheme: String = X402UptoScheme,
        network: String,
        amount: String,
        asset: String,
        payTo: String,
        maxTimeoutSeconds: Int,
        extra: X402UptoExtra,
        raw: JSONValue? = nil
    ) {
        self.scheme = scheme
        self.network = network
        self.amount = amount
        self.asset = asset
        self.payTo = payTo
        self.maxTimeoutSeconds = maxTimeoutSeconds
        self.extra = extra
        self.raw = raw
    }

    private enum CodingKeys: String, CodingKey {
        case scheme, network, amount, asset, payTo, maxTimeoutSeconds, extra
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        scheme = try container.decodeIfPresent(String.self, forKey: .scheme) ?? X402UptoScheme
        network = try container.decode(String.self, forKey: .network)
        amount = try container.decode(String.self, forKey: .amount)
        asset = try container.decode(String.self, forKey: .asset)
        payTo = try container.decode(String.self, forKey: .payTo)
        maxTimeoutSeconds = try container.decode(Int.self, forKey: .maxTimeoutSeconds)
        extra = try container.decode(X402UptoExtra.self, forKey: .extra)
        raw = try JSONValue(from: decoder)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(scheme, forKey: .scheme)
        try container.encode(network, forKey: .network)
        try container.encode(amount, forKey: .amount)
        try container.encode(asset, forKey: .asset)
        try container.encode(payTo, forKey: .payTo)
        try container.encode(maxTimeoutSeconds, forKey: .maxTimeoutSeconds)
        try container.encode(extra, forKey: .extra)
    }

    /// Parse the authorized maximum as base units.
    public func maxAmount() throws -> UInt64 {
        guard let value = UInt64(amount) else {
            throw PayKitError.invalidTransaction("x402 client: invalid upto amount \(amount)")
        }
        return value
    }

    /// The canonical `accepted` value to echo: the verbatim wire object when one
    /// was captured, else the typed encoding.
    func acceptedValue() throws -> JSONValue {
        if let raw { return raw }
        return try JSONValue.encoding(self)
    }
}

/// The `PAYMENT-REQUIRED` envelope for an `upto` challenge.
public struct X402UptoRequiredEnvelope: Codable, Sendable {
    /// x402 protocol version declared by the server.
    public let x402Version: Int?
    /// Advertised payment requirements.
    public let accepts: [X402UptoRequirements]
    /// Optional human-readable error string.
    public let error: String?

    public init(x402Version: Int?, accepts: [X402UptoRequirements], error: String? = nil) {
        self.x402Version = x402Version
        self.accepts = accepts
        self.error = error
    }

    private enum CodingKeys: String, CodingKey {
        case x402Version, accepts, error
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        x402Version = try container.decodeIfPresent(Int.self, forKey: .x402Version)
        // Decode each entry independently: a mixed challenge (e.g. an `exact`
        // entry whose `extra` lacks the upto-required fields sitting beside an
        // `upto` entry) must still surface the upto offers rather than failing
        // the whole parse. Entries that do not decode as an upto requirement
        // are dropped here; the scheme filter in `parseUptoAccepts` then keeps
        // only `scheme == "upto"`.
        if let rawEntries = try container.decodeIfPresent([JSONValue].self, forKey: .accepts) {
            accepts = rawEntries.compactMap { try? $0.decode(X402UptoRequirements.self) }
        } else {
            accepts = []
        }
        error = try container.decodeIfPresent(String.self, forKey: .error)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(x402Version, forKey: .x402Version)
        try container.encode(accepts, forKey: .accepts)
        try container.encodeIfPresent(error, forKey: .error)
    }
}

/// The client authorization carried in `PAYMENT-SIGNATURE.payload`.
///
/// For the payment-channel method the channel `open` is the authorization: the
/// client's signature commits the deposit ceiling, payee, and mint. The
/// payload carries no `signature` and no `profile` field.
public struct X402UptoPayload: Codable, Sendable, Equatable {
    /// Payer wallet (base58).
    public let from: String
    /// Signed ceiling (base units, decimal string); equals verification `amount`.
    public let maxAmount: String
    /// Deadline (Unix seconds).
    public let expiresAt: Int
    /// Activation time (Unix seconds).
    public let validAfter: Int
    /// Unique per-authorization identifier (opaque string).
    public let nonce: String
    /// Channel PDA (base58).
    public let channelId: String
    /// On-chain escrow ceiling (base units); equals `maxAmount`.
    public let deposit: String
    /// Voucher signer — the operator/facilitator key (base58).
    public let authorizedSigner: String
    /// Base64 client-signed `open` transaction for the operator to co-sign and
    /// broadcast. Omitted from JSON when absent.
    public let openTransaction: String?

    public init(
        from: String,
        maxAmount: String,
        expiresAt: Int,
        validAfter: Int,
        nonce: String,
        channelId: String,
        deposit: String,
        authorizedSigner: String,
        openTransaction: String?
    ) {
        self.from = from
        self.maxAmount = maxAmount
        self.expiresAt = expiresAt
        self.validAfter = validAfter
        self.nonce = nonce
        self.channelId = channelId
        self.deposit = deposit
        self.authorizedSigner = authorizedSigner
        self.openTransaction = openTransaction
    }

    private enum CodingKeys: String, CodingKey {
        case from, maxAmount, expiresAt, validAfter, nonce, channelId
        case deposit, authorizedSigner, openTransaction
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        from = try container.decode(String.self, forKey: .from)
        maxAmount = try container.decode(String.self, forKey: .maxAmount)
        expiresAt = try container.decode(Int.self, forKey: .expiresAt)
        validAfter = try container.decode(Int.self, forKey: .validAfter)
        nonce = try container.decode(String.self, forKey: .nonce)
        channelId = try container.decode(String.self, forKey: .channelId)
        deposit = try container.decode(String.self, forKey: .deposit)
        authorizedSigner = try container.decode(String.self, forKey: .authorizedSigner)
        openTransaction = try container.decodeIfPresent(String.self, forKey: .openTransaction)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(from, forKey: .from)
        try container.encode(maxAmount, forKey: .maxAmount)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(validAfter, forKey: .validAfter)
        try container.encode(nonce, forKey: .nonce)
        try container.encode(channelId, forKey: .channelId)
        try container.encode(deposit, forKey: .deposit)
        try container.encode(authorizedSigner, forKey: .authorizedSigner)
        try container.encodeIfPresent(openTransaction, forKey: .openTransaction)
    }
}

/// The `PAYMENT-SIGNATURE` envelope for an `upto` payment.
///
/// Emits the canonical x402 v2 shape `{ x402Version, accepted, payload }`:
/// `scheme`/`network` live inside the echoed `accepted` object, not at the
/// envelope level.
public struct X402UptoSignatureEnvelope: Codable, Sendable {
    /// x402 protocol version.
    public let x402Version: Int
    /// The chosen requirements object, echoed verbatim.
    public let accepted: JSONValue
    /// The client authorization.
    public let payload: X402UptoPayload

    public init(x402Version: Int, accepted: JSONValue, payload: X402UptoPayload) {
        self.x402Version = x402Version
        self.accepted = accepted
        self.payload = payload
    }
}

/// The `PAYMENT-RESPONSE` settlement result for an `upto` payment.
public struct X402UptoSettlementResponse: Codable, Sendable {
    /// Whether settlement succeeded.
    public let success: Bool
    /// Failure reason when `success` is false.
    public let errorReason: String?
    /// Payer wallet (base58).
    public let payer: String?
    /// Settlement transaction signature.
    public let transaction: String
    /// CAIP-2 network identifier.
    public let network: String
    /// Actual base units charged (may be `"0"`).
    public let amount: String

    public init(
        success: Bool,
        errorReason: String? = nil,
        payer: String? = nil,
        transaction: String,
        network: String,
        amount: String
    ) {
        self.success = success
        self.errorReason = errorReason
        self.payer = payer
        self.transaction = transaction
        self.network = network
        self.amount = amount
    }

    private enum CodingKeys: String, CodingKey {
        case success, errorReason, payer, transaction, network, amount
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        success = try container.decode(Bool.self, forKey: .success)
        errorReason = try container.decodeIfPresent(String.self, forKey: .errorReason)
        payer = try container.decodeIfPresent(String.self, forKey: .payer)
        transaction = try container.decode(String.self, forKey: .transaction)
        network = try container.decode(String.self, forKey: .network)
        amount = try container.decode(String.self, forKey: .amount)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(success, forKey: .success)
        try container.encodeIfPresent(errorReason, forKey: .errorReason)
        try container.encodeIfPresent(payer, forKey: .payer)
        try container.encode(transaction, forKey: .transaction)
        try container.encode(network, forKey: .network)
        try container.encode(amount, forKey: .amount)
    }
}
