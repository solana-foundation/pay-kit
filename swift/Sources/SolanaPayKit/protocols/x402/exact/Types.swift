import Foundation

// MARK: - x402 wire types (exact scheme)

/// x402 protocol version constant emitted in the `Payment-Signature` envelope.
public let X402Version: Int = 2

/// Legacy x402 protocol version (v1). Mirrors the rust spine constant
/// `X402_VERSION_V1` (constants.rs:10). The default producer stays
/// `X402Version` (v2); this is emitted only when the server's challenge
/// declared the legacy version.
public let X402VersionLegacy: Int = 1

/// Legacy client payment header carrying the base64 legacy envelope.
/// Mirrors rust `X402_V1_PAYMENT_HEADER` (constants.rs:16).
public let X402LegacyPaymentHeader: String = "X-PAYMENT"

/// Legacy server challenge header. Mirrors rust
/// `X402_V1_PAYMENT_REQUIRED_HEADER` (constants.rs:19).
public let X402LegacyPaymentRequiredHeader: String = "X-PAYMENT-REQUIRED"

/// Canonical v2 payment header. Mirrors rust `X402_V2_PAYMENT_HEADER`
/// (constants.rs:25).
public let X402PaymentHeader: String = "PAYMENT-SIGNATURE"

/// One entry in the `accepts` array of a `PAYMENT-REQUIRED` challenge.
///
/// The x402 pay_kit server stamps `extra.recentBlockhash`,
/// `extra.feePayer`, `extra.tokenProgram`, `extra.decimals`, and
/// `extra.memo`. All fields are optional from the client's perspective;
/// the payment builder falls back gracefully when any are absent.
public struct X402AcceptsEntry: Codable, Sendable {
    /// Protocol name (`"x402"`). Optional in some server implementations.
    public let scheme: String?
    /// CAIP-2 network identifier (e.g. `"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"`).
    public let network: String
    /// Amount in base units (string to avoid JSON integer precision issues).
    public let amount: String?
    /// Alias used by some x402 servers for `amount`.
    public let maxAmountRequired: String?
    /// On-chain mint address (resolved SPL token) or `"SOL"` for native SOL.
    public let asset: String?
    /// Recipient wallet address.
    public let payTo: String?
    /// Recipient alias used by legacy x402-express servers.
    public let recipient: String?
    /// Extra per-server fields: `feePayer`, `recentBlockhash`, `tokenProgram`,
    /// `decimals`, `memo`, etc. Modeled as `JSONValue` to match the rust
    /// spine, where `extra` is an untyped `serde_json::Value`.
    public let extra: [String: JSONValue]?

    // Top-level currency fields. Some x402 servers carry the mint as
    // `currency` and the token metadata at the top level instead of nested
    // under `asset` + `extra`. These are read as fallbacks so the client can
    // pay a server emitting either shape.
    /// Mint/symbol when carried at the top level (otherwise `asset`).
    public let currency: String?
    /// Token decimals when carried at the top level (otherwise `extra.decimals`).
    public let decimals: Int?
    /// SPL token program at the top level (otherwise `extra.tokenProgram`).
    public let tokenProgram: String?
    /// Pinned blockhash at the top level (otherwise `extra.recentBlockhash`).
    public let recentBlockhash: String?
    /// Managed fee-payer pubkey at the top level. The rust normalization reads
    /// `feePayerKey` top-level-first, then the nested `extra.feePayer` alias.
    public let feePayerKey: String?
    /// Managed fee-payer toggle. Defaults to true when a key is present; an
    /// explicit `false` opts out (rust `bool_field("feePayer").or(key -> true)`).
    public let feePayer: Bool?

    /// Maximum payment window in seconds. Present when the server sends it at
    /// the top level (e.g. `"maxTimeoutSeconds": 60`). Used in the typed
    /// fallback canonical object so the rust verifier can structurally
    /// compare the echoed `accepted` against its offered options. Default is
    /// 300 when omitted (mirrors rust `to_accepted_value` default).
    public let maxTimeoutSeconds: Int?

    /// The verbatim offered object as received on the wire, preserved so the
    /// client can echo it back unchanged in the `Payment-Signature`
    /// envelope's `accepted` field. `nil` for entries built in code (e.g.
    /// tests) rather than decoded from a challenge. The rust verifier
    /// matches the echoed `accepted` against its offered options, so this
    /// must carry every field — including ones the typed properties above do
    /// not model (`maxTimeoutSeconds`, `resource`, server extras).
    public let raw: JSONValue?

    private enum CodingKeys: String, CodingKey {
        case scheme, network, amount, maxAmountRequired, asset, payTo, recipient, extra
        case currency, decimals, tokenProgram, recentBlockhash, maxTimeoutSeconds
        case feePayerKey, feePayer
    }

    public init(
        scheme: String?,
        network: String,
        amount: String?,
        maxAmountRequired: String?,
        asset: String?,
        payTo: String?,
        recipient: String?,
        extra: [String: JSONValue]?,
        currency: String? = nil,
        decimals: Int? = nil,
        tokenProgram: String? = nil,
        recentBlockhash: String? = nil,
        feePayerKey: String? = nil,
        feePayer: Bool? = nil,
        maxTimeoutSeconds: Int? = nil,
        raw: JSONValue? = nil
    ) {
        self.scheme = scheme
        self.network = network
        self.amount = amount
        self.maxAmountRequired = maxAmountRequired
        self.asset = asset
        self.payTo = payTo
        self.recipient = recipient
        self.extra = extra
        self.currency = currency
        self.decimals = decimals
        self.tokenProgram = tokenProgram
        self.recentBlockhash = recentBlockhash
        self.feePayerKey = feePayerKey
        self.feePayer = feePayer
        self.maxTimeoutSeconds = maxTimeoutSeconds
        self.raw = raw
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        scheme = try container.decodeIfPresent(String.self, forKey: .scheme)
        network = try container.decode(String.self, forKey: .network)
        amount = try container.decodeIfPresent(String.self, forKey: .amount)
        maxAmountRequired = try container.decodeIfPresent(String.self, forKey: .maxAmountRequired)
        asset = try container.decodeIfPresent(String.self, forKey: .asset)
        payTo = try container.decodeIfPresent(String.self, forKey: .payTo)
        recipient = try container.decodeIfPresent(String.self, forKey: .recipient)
        extra = try container.decodeIfPresent([String: JSONValue].self, forKey: .extra)
        currency = try container.decodeIfPresent(String.self, forKey: .currency)
        decimals = try container.decodeIfPresent(Int.self, forKey: .decimals)
        tokenProgram = try container.decodeIfPresent(String.self, forKey: .tokenProgram)
        recentBlockhash = try container.decodeIfPresent(String.self, forKey: .recentBlockhash)
        feePayerKey = try container.decodeIfPresent(String.self, forKey: .feePayerKey)
        feePayer = try container.decodeIfPresent(Bool.self, forKey: .feePayer)
        maxTimeoutSeconds = try container.decodeIfPresent(Int.self, forKey: .maxTimeoutSeconds)
        // Capture the verbatim object for faithful echo.
        raw = try JSONValue(from: decoder)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(scheme, forKey: .scheme)
        try container.encode(network, forKey: .network)
        try container.encodeIfPresent(amount, forKey: .amount)
        try container.encodeIfPresent(maxAmountRequired, forKey: .maxAmountRequired)
        try container.encodeIfPresent(asset, forKey: .asset)
        try container.encodeIfPresent(payTo, forKey: .payTo)
        try container.encodeIfPresent(recipient, forKey: .recipient)
        try container.encodeIfPresent(extra, forKey: .extra)
        try container.encodeIfPresent(currency, forKey: .currency)
        try container.encodeIfPresent(decimals, forKey: .decimals)
        try container.encodeIfPresent(tokenProgram, forKey: .tokenProgram)
        try container.encodeIfPresent(recentBlockhash, forKey: .recentBlockhash)
        try container.encodeIfPresent(feePayerKey, forKey: .feePayerKey)
        try container.encodeIfPresent(feePayer, forKey: .feePayer)
        // Emit maxTimeoutSeconds; fall back to 300 (rust `to_accepted_value` default)
        // so in-code entries produce a verifier-compatible canonical accepted object.
        try container.encode(maxTimeoutSeconds ?? 300, forKey: .maxTimeoutSeconds)
    }

    // MARK: - Computed helpers

    /// The effective payment amount (prefers `amount`, falls back to
    /// `maxAmountRequired`).
    public var effectiveAmount: String? { amount ?? maxAmountRequired }

    /// The effective recipient address (prefers `payTo`, falls back to
    /// `recipient`).
    public var effectivePayTo: String? { payTo ?? recipient }

    /// The effective mint: top-level `currency` wins, then `asset`.
    ///
    /// Matches the Rust deserializer precedence:
    /// `string_field(object, "currency").or_else(|| string_field(object, "asset"))`.
    public var effectiveAsset: String? { currency ?? asset }

    /// The effective token program: top-level `tokenProgram` wins, then
    /// `extra.tokenProgram`.
    ///
    /// Matches Rust: `string_field(object, "tokenProgram")
    ///   .or_else(|| extra_object.and_then(|e| string_field(e, "tokenProgram")))`.
    public var effectiveTokenProgram: String? { tokenProgram ?? extraString("tokenProgram") }

    /// The effective token decimals: top-level `decimals` wins, then
    /// `extra.decimals`.
    ///
    /// Matches Rust: `u8_field(object, "decimals")
    ///   .or_else(|| extra_object.and_then(|e| u8_field(e, "decimals")))`.
    public var effectiveDecimals: Int? { decimals ?? extraInt("decimals") }

    /// The effective pinned blockhash: top-level `recentBlockhash` wins,
    /// then `extra.recentBlockhash`.
    ///
    /// Matches Rust: `string_field(object, "recentBlockhash")
    ///   .or_else(|| extra_object.and_then(|e| string_field(e, "recentBlockhash")))`.
    public var effectiveRecentBlockhash: String? {
        recentBlockhash ?? extraString("recentBlockhash")
    }

    /// The effective managed fee-payer pubkey, or `nil` when the offer does
    /// not request one.
    ///
    /// Mirrors the rust normalization (`types.rs`): the key is the top-level
    /// `feePayerKey`, else the nested `extra.feePayer` alias; the `feePayer`
    /// toggle then gates it, defaulting to true when a key is present so only
    /// an explicit `false` opts out.
    public var effectiveFeePayerKey: String? {
        guard let key = feePayerKey ?? extraString("feePayer") else { return nil }
        return feePayer != false ? key : nil
    }

    /// Extract a `String` value from `extra`.
    public func extraString(_ key: String) -> String? {
        guard case let .string(s)? = extra?[key], !s.isEmpty else { return nil }
        return s
    }

    /// Extract an `Int` value from `extra`.
    public func extraInt(_ key: String) -> Int? {
        guard case let .int(i)? = extra?[key] else { return nil }
        return i
    }
}

// MARK: - JSON value

/// A losslessly round-trippable JSON value. Used to preserve the verbatim
/// offered `accepts` entry so the client can echo it back unchanged in the
/// `Payment-Signature` envelope's `accepted` field (the rust verifier
/// matches the echoed object against its offered options after normalizing
/// both through the same serializer, so fields the typed `X402AcceptsEntry`
/// does not model — `maxTimeoutSeconds`, `resource`, server-specific extras
/// — must survive the round trip).
public indirect enum JSONValue: Codable, Sendable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let b = try? container.decode(Bool.self) {
            self = .bool(b)
        } else if let i = try? container.decode(Int.self) {
            self = .int(i)
        } else if let d = try? container.decode(Double.self) {
            self = .double(d)
        } else if let s = try? container.decode(String.self) {
            self = .string(s)
        } else if let arr = try? container.decode([JSONValue].self) {
            self = .array(arr)
        } else if let obj = try? container.decode([String: JSONValue].self) {
            self = .object(obj)
        } else {
            self = .null
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let s): try container.encode(s)
        case .int(let i):    try container.encode(i)
        case .double(let d): try container.encode(d)
        case .bool(let b):   try container.encode(b)
        case .object(let o): try container.encode(o)
        case .array(let a):  try container.encode(a)
        case .null:          try container.encodeNil()
        }
    }
}

/// The outer `PAYMENT-REQUIRED` JSON envelope that wraps the `accepts` list.
public struct X402PaymentRequiredEnvelope: Codable, Sendable {
    public let x402Version: Int?
    public let accepts: [X402AcceptsEntry]
}

/// The `payload` field of a `Payment-Signature` envelope.
public struct X402PaymentPayload: Codable, Sendable {
    /// Standard-base64 encoded signed VersionedTransaction.
    public let transaction: String

    public init(transaction: String) {
        self.transaction = transaction
    }
}

/// The client payment header value (base64 of this JSON).
///
/// Mirrors the rust `PaymentSignatureEnvelope` (types.rs:587-608), a single
/// type covering both wire shapes:
/// - Canonical (v2): `{ x402Version: 2, accepted, payload }`, carried in the
///   `PAYMENT-SIGNATURE` header. `scheme`/`network` are `nil` and omitted.
/// - Legacy (v1): `{ x402Version: 1, scheme, network, payload }`, carried in
///   the `X-PAYMENT` header. `accepted` is `nil` and omitted; `scheme` and
///   `network` (a plain SVM slug) are top-level siblings of `payload`.
///
/// `scheme`/`network`/`accepted` are skipped when `nil`, matching the rust
/// `skip_serializing_if = "Option::is_none"` on each field.
public struct X402PaymentSignatureEnvelope: Codable, Sendable {
    public let x402Version: Int
    /// Top-level scheme (legacy v1 only; `nil` and omitted for v2).
    public let scheme: String?
    /// Top-level plain SVM network slug (legacy v1 only; `nil` for v2).
    public let network: String?
    public let accepted: X402AcceptsEntry?
    public let payload: X402PaymentPayload

    public init(
        x402Version: Int,
        scheme: String? = nil,
        network: String? = nil,
        accepted: X402AcceptsEntry?,
        payload: X402PaymentPayload
    ) {
        self.x402Version = x402Version
        self.scheme = scheme
        self.network = network
        self.accepted = accepted
        self.payload = payload
    }

    private enum CodingKeys: String, CodingKey {
        case x402Version, scheme, network, accepted, payload
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        x402Version = try container.decode(Int.self, forKey: .x402Version)
        scheme = try container.decodeIfPresent(String.self, forKey: .scheme)
        network = try container.decodeIfPresent(String.self, forKey: .network)
        accepted = try container.decodeIfPresent(X402AcceptsEntry.self, forKey: .accepted)
        payload = try container.decode(X402PaymentPayload.self, forKey: .payload)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(x402Version, forKey: .x402Version)
        // Legacy v1 siblings; omitted (and thus absent on v2) when nil.
        try container.encodeIfPresent(scheme, forKey: .scheme)
        try container.encodeIfPresent(network, forKey: .network)
        // Echo the offered requirement verbatim when we captured it on the
        // wire (preserves maxTimeoutSeconds / resource / server extras the
        // typed entry does not model); fall back to the typed encoding for
        // in-code entries. Mirrors the rust client's `to_accepted_value`,
        // which returns the original parsed object unchanged. The legacy v1
        // envelope omits `accepted` entirely (it binds only scheme+network).
        if let raw = accepted?.raw {
            try container.encode(raw, forKey: .accepted)
        } else {
            try container.encodeIfPresent(accepted, forKey: .accepted)
        }
        try container.encode(payload, forKey: .payload)
    }
}

/// Client-side preferences for picking one offer from an `accepts` list.
///
/// Mirrors the rust `ChallengeSelection` struct.
public struct X402ChallengeSelection: Sendable {
    /// CAIP-2 id or cluster slug for the preferred network. `nil` defaults
    /// to Solana mainnet.
    public let network: String?
    /// Priority-ordered currencies the client will pay in (symbols or mint
    /// addresses, interchangeable). The first server offer matching the
    /// highest-priority currency wins. `nil` falls back to cheapest by amount.
    public let currencies: [String]?

    public init(network: String? = nil, currencies: [String]? = nil) {
        self.network = network
        self.currencies = currencies
    }
}
