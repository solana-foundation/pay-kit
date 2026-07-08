import Foundation

// MppError moved to PayCore/Errors.swift (shared payment-core error consumed by
// both the MPP and x402 protocol layers; keeps the protocols decoupled).

public struct PaymentChallenge: Codable, Equatable, Sendable {
    public let id: String
    public let realm: String
    public let method: String
    public let intent: String
    public let request: String
    public let expires: String?
    public let digest: String?
    public let opaque: String?

    public var chargeRequest: ChargeRequest {
        get throws {
            // Cap before decode/JSON-parse — mirrors the WWW-Authenticate parser
            // (audit #9). Closes the direct-construction bypass: a challenge built
            // without going through `parseWWWAuthenticate` must still be bounded.
            guard request.utf8.count <= MppHeaders.maxTokenLength else {
                throw MppError.invalidHeader
            }
            let data = try Base64URL.decode(request)
            do {
                return try JSONDecoder().decode(ChargeRequest.self, from: data)
            } catch {
                throw MppError.invalidJSON(String(describing: error))
            }
        }
    }

    public init(
        id: String,
        realm: String,
        method: String,
        intent: String,
        request: String,
        expires: String? = nil,
        digest: String? = nil,
        opaque: String? = nil
    ) throws {
        guard request.utf8.count <= MppHeaders.maxTokenLength else {
            throw MppError.invalidHeader
        }
        _ = try Base64URL.decode(request)
        self.id = id
        self.realm = realm
        self.method = method
        self.intent = intent
        self.request = request
        self.expires = expires
        self.digest = digest
        self.opaque = opaque
    }

    public func requireSolanaCharge() throws {
        guard method == "solana", intent == "charge" else {
            throw MppError.unsupportedChallenge(method: method, intent: intent)
        }
    }

    /// Returns `true` if the challenge carries an `expires` timestamp that
    /// is in the past (or is unparseable). Challenges with no `expires`
    /// are never considered expired — the protocol allows omitting it and
    /// the client has no anchor to check against. Mirrors the fail-closed
    /// RFC3339 parser in rust `protocol::core::challenge::is_expired`: an
    /// `expires` we cannot parse is treated as expired so a hostile server
    /// cannot bypass the gate with a malformed timestamp.
    public func isExpired(now: Date = Date()) -> Bool {
        guard let expires = expires else { return false }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let parsed = formatter.date(from: expires) {
            return parsed <= now
        }
        // Retry without fractional seconds (RFC3339 allows either form).
        formatter.formatOptions = [.withInternetDateTime]
        if let parsed = formatter.date(from: expires) {
            return parsed <= now
        }
        return true  // fail-closed: unparseable expiry refuses to sign
    }

    public func echo() -> ChallengeEcho {
        ChallengeEcho(
            id: id,
            realm: realm,
            method: method,
            intent: intent,
            request: request,
            expires: expires,
            digest: digest,
            opaque: opaque
        )
    }
}

public struct ChallengeEcho: Codable, Equatable, Sendable {
    public let id: String
    public let realm: String
    public let method: String
    public let intent: String
    public let request: String
    public let expires: String?
    public let digest: String?
    public let opaque: String?
}

public struct ChargeRequest: Codable, Equatable, Sendable {
    public let amount: String
    public let currency: String
    public let recipient: String
    public let externalId: String?
    public let methodDetails: SolanaChargeMethodDetails
}

public struct SolanaChargeMethodDetails: Codable, Equatable, Sendable {
    public let network: String?
    public let decimals: Int?
    public let feePayer: Bool?
    public let feePayerKey: String?
    public let recentBlockhash: String?
    public let splits: [SolanaChargeSplit]?
    public let tokenProgram: String?
}

public struct SolanaChargeSplit: Codable, Equatable, Sendable {
    public let recipient: String
    public let amount: String
    public let ataCreationRequired: Bool?
    public let memo: String?
}

public struct PaymentCredential: Codable, Equatable, Sendable {
    public let challenge: ChallengeEcho
    public let payload: CredentialPayload
    public let source: String?

    public init(challenge: ChallengeEcho, payload: CredentialPayload, source: String? = nil) {
        self.challenge = challenge
        self.payload = payload
        self.source = source
    }
}

public enum CredentialPayload: Codable, Equatable, Sendable {
    case transaction(String)
    case signature(String)

    private enum CodingKeys: String, CodingKey {
        case type
        case transaction
        case signature
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "transaction":
            self = .transaction(try container.decode(String.self, forKey: .transaction))
        case "signature":
            self = .signature(try container.decode(String.self, forKey: .signature))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "unsupported credential payload type"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .transaction(transaction):
            try container.encode("transaction", forKey: .type)
            try container.encode(transaction, forKey: .transaction)
        case let .signature(signature):
            try container.encode("signature", forKey: .type)
            try container.encode(signature, forKey: .signature)
        }
    }
}
