import Foundation

public enum MppHeaders {
    public static let paymentScheme = "Payment"

    /// Upper bound on the base64url-encoded `request` parameter before it is
    /// decoded and JSON-parsed. Mirrors the rust `MAX_TOKEN_LEN = 16 * 1024`
    /// cap that the credential/receipt parsers already enforce (audit #9):
    /// an oversized `WWW-Authenticate` value must not drive unbounded
    /// base64url-decode + JSON-parse work.
    public static let maxTokenLength = 16 * 1024

    public static func parseWWWAuthenticate(_ header: String) throws -> PaymentChallenge {
        let rest = try paymentSchemePayload(header)
        let params = try parseAuthParams(rest)

        guard let request = params["request"], !request.isEmpty else {
            throw MppError.missingField("request")
        }
        // Cap the encoded `request` before any decode/JSON-parse work runs.
        guard request.utf8.count <= maxTokenLength else {
            throw MppError.invalidHeader
        }
        guard let id = params["id"], !id.isEmpty else {
            throw MppError.missingField("id")
        }
        guard let realm = params["realm"], !realm.isEmpty else {
            throw MppError.missingField("realm")
        }
        guard let method = params["method"], !method.isEmpty else {
            throw MppError.missingField("method")
        }
        guard let intent = params["intent"], !intent.isEmpty else {
            throw MppError.missingField("intent")
        }

        return try PaymentChallenge(
            id: id,
            realm: realm,
            method: method,
            intent: intent,
            request: request,
            expires: params["expires"],
            digest: params["digest"],
            opaque: params["opaque"]
        )
    }

    public static func formatAuthorization(_ credential: PaymentCredential) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(credential)
        return "\(paymentScheme) \(Base64URL.encode(data))"
    }

    private static func paymentSchemePayload(_ header: String) throws -> String {
        let trimmed = header.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix(paymentScheme.lowercased()) else {
            throw MppError.invalidPaymentScheme
        }
        let index = trimmed.index(trimmed.startIndex, offsetBy: paymentScheme.count)
        return String(trimmed[index...]).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func parseAuthParams(_ value: String) throws -> [String: String] {
        var params: [String: String] = [:]
        var index = value.startIndex

        while index < value.endIndex {
            while index < value.endIndex, value[index].isWhitespace || value[index] == "," {
                index = value.index(after: index)
            }
            if index == value.endIndex {
                break
            }

            let keyStart = index
            while index < value.endIndex, value[index] != "=" {
                index = value.index(after: index)
            }
            guard index < value.endIndex else {
                throw MppError.invalidHeader
            }
            let key = value[keyStart..<index].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else {
                throw MppError.invalidHeader
            }
            index = value.index(after: index)

            while index < value.endIndex, value[index].isWhitespace {
                index = value.index(after: index)
            }
            guard index < value.endIndex, value[index] == "\"" else {
                throw MppError.invalidHeader
            }
            index = value.index(after: index)

            var decoded = ""
            var escaped = false
            var closed = false
            while index < value.endIndex {
                let char = value[index]
                index = value.index(after: index)
                if escaped {
                    decoded.append(char)
                    escaped = false
                } else if char == "\\" {
                    escaped = true
                } else if char == "\"" {
                    closed = true
                    break
                } else {
                    decoded.append(char)
                }
            }
            guard closed, !escaped else {
                throw MppError.invalidHeader
            }
            params[key] = decoded
        }

        return params
    }
}
