import Foundation

public enum MppError: Error, Equatable {
    case invalidBase64URL
    case invalidBase58
    case invalidHeader
    case invalidJSON(String)
    case invalidPaymentScheme
    case invalidPubkey(String)
    case invalidTransaction(String)
    case missingField(String)
    case rpcFailure(String)
    case signingFailure(String)
    case unsupportedChallenge(method: String, intent: String)
}

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
