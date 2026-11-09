import Foundation

// PayKitError moved to PayCore/Errors.swift (shared payment-core error consumed by
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
                throw PayKitError.invalidHeader
            }
            let data = try Base64URL.decode(request)
            do {
                return try JSONDecoder().decode(ChargeRequest.self, from: data)
            } catch {
                throw PayKitError.invalidJSON(String(describing: error))
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
            throw PayKitError.invalidHeader
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
            throw PayKitError.unsupportedChallenge(method: method, intent: intent)
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
        guard let parsed = PaymentChallenge.parseRFC3339(expires) else { return true }
        return parsed <= now
    }

    /// Strict RFC 3339 §5.6 date-time; ISO8601DateFormatter normalises out-of-range input instead of refusing it.
    private static func parseRFC3339(_ value: String) -> Date? {
        let b = Array(value.utf8)
        func num(_ at: Int, _ n: Int) -> Int? {
            var v = 0
            for k in at ..< (at + n) {
                guard k < b.count, b[k] >= 48, b[k] <= 57 else { return nil }
                v = v * 10 + Int(b[k] - 48)
            }
            return v
        }
        func matches(_ at: Int, _ lowercased: UInt8) -> Bool {
            at < b.count && (b[at] | 0x20) == lowercased
        }
        guard b.count >= 20, let year = num(0, 4), b[4] == 0x2D, let month = num(5, 2),
              b[7] == 0x2D, let day = num(8, 2), matches(10, 0x74), let hour = num(11, 2),
              b[13] == 0x3A, let minute = num(14, 2), b[16] == 0x3A, let second = num(17, 2),
              month >= 1, month <= 12, day >= 1, day <= daysIn(month, year),
              hour <= 23, minute <= 59, second <= 60
        else { return nil }
        var i = 19, nanos = 0
        if i < b.count, b[i] == 0x2E {
            i += 1
            var seen = 0
            while i < b.count, b[i] >= 48, b[i] <= 57 {
                if seen < 9 { nanos = nanos * 10 + Int(b[i] - 48) }
                seen += 1
                i += 1
            }
            guard seen > 0 else { return nil }
            for _ in min(seen, 9) ..< 9 { nanos *= 10 }
        }
        var offset = 0
        if matches(i, 0x7A) {
            i += 1
        } else {
            guard i + 6 == b.count, b[i] == 0x2B || b[i] == 0x2D, let oh = num(i + 1, 2),
                  b[i + 3] == 0x3A, let om = num(i + 4, 2), oh <= 23, om <= 59
            else { return nil }
            offset = (b[i] == 0x2D ? -1 : 1) * (oh * 3_600 + om * 60)
            i += 6
        }
        guard i == b.count else { return nil }
        var epoch = daysFromCivil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 - offset
        epoch += second == 60 ? 59 : second
        if second == 60 {
            let utcDay = epoch >= 0 ? epoch / 86_400 : (epoch - 86_399) / 86_400
            let utc = civilFromDays(utcDay)
            guard epoch - utcDay * 86_400 == 86_399, utc.day == daysIn(utc.month, utc.year)
            else { return nil }
            nanos = 999_999_999
        }
        return Date(timeIntervalSince1970: Double(epoch) + Double(nanos) / 1_000_000_000)
    }

    private static func daysIn(_ month: Int, _ year: Int) -> Int {
        if month == 2 { return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) ? 29 : 28 }
        return month == 4 || month == 6 || month == 9 || month == 11 ? 30 : 31
    }

    private static func daysFromCivil(_ year: Int, _ month: Int, _ day: Int) -> Int {
        let y = year - (month <= 2 ? 1 : 0)
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
        return era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
    }

    private static func civilFromDays(_ days: Int) -> (year: Int, month: Int, day: Int) {
        let z = days + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let month = mp + (mp < 10 ? 3 : -9)
        return (yoe + era * 400 + (month <= 2 ? 1 : 0), month, doy - (153 * mp + 2) / 5 + 1)
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
