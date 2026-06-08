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

    /// Decode this JSON value into a `Decodable` type by round-tripping
    /// through `JSONEncoder`/`JSONDecoder`. Used to read the typed
    /// `payment-identifier` extension out of the verbatim extensions map.
    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        let data = try JSONEncoder().encode(self)
        return try JSONDecoder().decode(type, from: data)
    }

    /// Encode an `Encodable` value into a `JSONValue`, preserving its shape
    /// so it can be re-emitted verbatim alongside unknown extensions.
    public static func encoding<T: Encodable>(_ value: T) throws -> JSONValue {
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }
}

/// The outer `PAYMENT-REQUIRED` JSON envelope that wraps the `accepts` list.
///
/// `extensions` is an untyped passthrough object on the challenge (rust
/// `PaymentRequiredEnvelope.extensions: Option<serde_json::Value>`,
/// `types.rs:458`): a server may advertise any extension. The client echoes
/// it into the outbound credential via `X402PaymentExtensions.echoing`.
public struct X402PaymentRequiredEnvelope: Codable, Sendable {
    public let x402Version: Int?
    public let accepts: [X402AcceptsEntry]
    public let extensions: JSONValue?

    public init(x402Version: Int?, accepts: [X402AcceptsEntry], extensions: JSONValue? = nil) {
        self.x402Version = x402Version
        self.accepts = accepts
        self.extensions = extensions
    }

    private enum CodingKeys: String, CodingKey {
        case x402Version, accepts, extensions
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        x402Version = try container.decodeIfPresent(Int.self, forKey: .x402Version)
        accepts = try container.decode([X402AcceptsEntry].self, forKey: .accepts)
        extensions = try container.decodeIfPresent(JSONValue.self, forKey: .extensions)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(x402Version, forKey: .x402Version)
        try container.encode(accepts, forKey: .accepts)
        try container.encodeIfPresent(extensions, forKey: .extensions)
    }
}

// MARK: - x402 v2 extensions (rust PaymentExtensions et al.)

/// The kebab-case JSON key under which the `payment-identifier` extension
/// rides on the `extensions` object. Hard rule from the rust spine
/// (`#[serde(rename = "payment-identifier")]`, `types.rs:519`): the key is
/// `payment-identifier`, not `paymentIdentifier`.
public let X402PaymentIdentifierKey: String = "payment-identifier"

/// Spec pattern for a `payment-identifier.info.id` value
/// (`^[A-Za-z0-9_-]{16,128}$`, rust `types.rs:488`).
public let X402PaymentIdentifierIDPattern: String = "^[A-Za-z0-9_-]{16,128}$"

/// Client/server-side fields of the `payment-identifier` extension,
/// serialized camelCase. Mirrors rust `PaymentIdentifierInfo`
/// (`types.rs:483-493`). Both fields are omitted from the wire when `nil`
/// (rust `skip_serializing_if = "Option::is_none"`).
public struct X402PaymentIdentifierInfo: Codable, Sendable, Equatable {
    /// Server-side: whether clients MUST populate `id`. When `true` and
    /// `id` is missing, the server returns 400.
    public let required: Bool?
    /// Client-side idempotency key. Must match `^[A-Za-z0-9_-]{16,128}$`.
    public let id: String?

    public init(required: Bool? = nil, id: String? = nil) {
        self.required = required
        self.id = id
    }

    private enum CodingKeys: String, CodingKey {
        case required, id
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        required = try container.decodeIfPresent(Bool.self, forKey: .required)
        id = try container.decodeIfPresent(String.self, forKey: .id)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(required, forKey: .required)
        try container.encodeIfPresent(id, forKey: .id)
    }
}

/// The `payment-identifier` extension. Echoed by the client into the
/// outbound `PAYMENT-SIGNATURE` with `info.id` populated. Mirrors rust
/// `PaymentIdentifierExtension` (`types.rs:500-507`): `info` defaults to an
/// empty object, `schema` is echoed verbatim per x402 v2 §5.1.2 and omitted
/// when absent.
public struct X402PaymentIdentifierExtension: Codable, Sendable, Equatable {
    public let info: X402PaymentIdentifierInfo
    /// JSON Schema published by the server describing required client-side
    /// fields. Echoed verbatim; omitted when absent.
    public let schema: JSONValue?

    public init(info: X402PaymentIdentifierInfo = X402PaymentIdentifierInfo(), schema: JSONValue? = nil) {
        self.info = info
        self.schema = schema
    }

    private enum CodingKeys: String, CodingKey {
        case info, schema
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        info = try container.decodeIfPresent(X402PaymentIdentifierInfo.self, forKey: .info)
            ?? X402PaymentIdentifierInfo()
        schema = try container.decodeIfPresent(JSONValue.self, forKey: .schema)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(info, forKey: .info)
        try container.encodeIfPresent(schema, forKey: .schema)
    }
}

/// Typed view over the x402 v2 `extensions` object on
/// `X402PaymentSignatureEnvelope`. The known `payment-identifier` extension
/// is fielded out; every other extension this SDK does not type natively is
/// retained verbatim under its own key so the echo-and-append rule
/// (§5.1.2) never drops forward-compatible payloads.
///
/// Mirrors rust `PaymentExtensions { payment_identifier, #[serde(flatten)]
/// other }` (`types.rs:514-527`): on the wire `payment-identifier` and every
/// unknown extension are sibling keys of a single flat object. Modeled here
/// as one verbatim `[String: JSONValue]` map (`raw`) so round-trips are
/// byte-faithful and `payment-identifier` is parsed/edited through typed
/// accessors without losing the rest.
public struct X402PaymentExtensions: Codable, Sendable, Equatable {
    /// The verbatim extensions object as received/built. Keys are the
    /// extension ids (`payment-identifier`, plus any unknown ones).
    public private(set) var raw: [String: JSONValue]

    public init(raw: [String: JSONValue] = [:]) {
        self.raw = raw
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        raw = try container.decode([String: JSONValue].self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(raw)
    }

    /// The typed `payment-identifier` extension, decoded from `raw` on
    /// access (`nil` when the key is absent or malformed).
    public var paymentIdentifier: X402PaymentIdentifierExtension? {
        guard let value = raw[X402PaymentIdentifierKey] else { return nil }
        return try? value.decode(X402PaymentIdentifierExtension.self)
    }

    /// True when no keys are populated. Lets callers avoid emitting an empty
    /// `extensions: {}` object on outbound envelopes (rust
    /// `PaymentExtensions::is_empty`, `types.rs:533-535`).
    public var isEmpty: Bool { raw.isEmpty }

    /// `payment-identifier.info.required == true` (rust
    /// `requires_payment_identifier`, `types.rs:538-543`).
    public var requiresPaymentIdentifier: Bool {
        paymentIdentifier?.info.required == true
    }

    /// Set (or overwrite) the client-side `payment-identifier.info.id`,
    /// creating the extension entry if the server did not advertise one.
    /// Preserves the server's `info.required` and `schema` verbatim. Mirrors
    /// rust `with_payment_identifier_id` (`types.rs:548-553`): the entry is
    /// `get_or_insert_with(Default)` then `entry.info.id = Some(id)`.
    public func withPaymentIdentifierID(_ id: String) -> X402PaymentExtensions {
        var next = self
        let existing = next.paymentIdentifier ?? X402PaymentIdentifierExtension()
        let updatedInfo = X402PaymentIdentifierInfo(required: existing.info.required, id: id)
        let updated = X402PaymentIdentifierExtension(info: updatedInfo, schema: existing.schema)
        if let encoded = try? JSONValue.encoding(updated) {
            next.raw[X402PaymentIdentifierKey] = encoded
        }
        return next
    }

    /// Echo a server's inbound extensions blob into a typed
    /// `X402PaymentExtensions`. Returns `nil` when the inbound is `nil`
    /// (rust `echoing(None) -> Ok(None)`, `types.rs:559-565`). Unknown keys
    /// round-trip verbatim. Throws only when the inbound is not a JSON
    /// object.
    public static func echoing(_ inbound: JSONValue?) throws -> X402PaymentExtensions? {
        guard let inbound else { return nil }
        guard case let .object(object) = inbound else {
            throw MppError.invalidJSON("x402 extensions must be a JSON object")
        }
        return X402PaymentExtensions(raw: object)
    }
}

/// Generate a fresh `pay_`-prefixed idempotency id: `pay_` + 16 CSPRNG
/// bytes rendered as 32 lowercase hex chars (36 total). Satisfies the
/// `payment-identifier` spec pattern `^[A-Za-z0-9_-]{16,128}$` and the
/// canonical Solana `^pay_[a-zA-Z0-9_-]{10,120}$` shape. Mirrors rust
/// `generate_payment_identifier_id` (`types.rs:575-585`).
///
/// Per the spec, callers MUST reuse the same id across retries of the same
/// logical request so the server can return a cached 200 instead of charging
/// twice.
///
/// - Parameter randomBytes: Optional closure that returns 16 random bytes.
///   Defaults to `SystemRandomNumberGenerator`. Pass a fixed value in tests
///   to make the output deterministic.
public func generateX402PaymentIdentifierID(randomBytes: (() -> Data)? = nil) -> String {
    let bytes: Data
    if let randomBytes {
        bytes = randomBytes()
    } else {
        var rng = SystemRandomNumberGenerator()
        var raw = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { raw[i] = rng.next() }
        bytes = Data(raw)
    }
    return "pay_" + bytes.map { String(format: "%02x", $0) }.joined()
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
    /// Echoed extensions from the inbound `PAYMENT-REQUIRED` envelope, with
    /// any required client-supplied fields filled in (e.g.
    /// `payment-identifier.info.id`). Per x402 v2 §5.1.2 the client "must
    /// include at least the info received; it may append additional info but
    /// cannot delete or overwrite existing info". Omitted from the wire when
    /// `nil` or structurally empty so the envelope never carries an empty
    /// `extensions: {}` (rust `skip_serializing_if = "Option::is_none"` +
    /// `PaymentExtensions::is_empty`).
    public let extensions: X402PaymentExtensions?

    public init(
        x402Version: Int,
        scheme: String? = nil,
        network: String? = nil,
        accepted: X402AcceptsEntry?,
        payload: X402PaymentPayload,
        extensions: X402PaymentExtensions? = nil
    ) {
        self.x402Version = x402Version
        self.scheme = scheme
        self.network = network
        self.accepted = accepted
        self.payload = payload
        self.extensions = extensions
    }

    private enum CodingKeys: String, CodingKey {
        case x402Version, scheme, network, accepted, payload, extensions
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        x402Version = try container.decode(Int.self, forKey: .x402Version)
        scheme = try container.decodeIfPresent(String.self, forKey: .scheme)
        network = try container.decodeIfPresent(String.self, forKey: .network)
        accepted = try container.decodeIfPresent(X402AcceptsEntry.self, forKey: .accepted)
        payload = try container.decode(X402PaymentPayload.self, forKey: .payload)
        extensions = try container.decodeIfPresent(X402PaymentExtensions.self, forKey: .extensions)
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
        // Omit empty/absent extensions entirely (echo-and-omit rule).
        if let extensions, !extensions.isEmpty {
            try container.encode(extensions, forKey: .extensions)
        }
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
