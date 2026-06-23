import Foundation
import SwiftUI
import SolanaPayKit

/// Decodes the playground's `GET /openapi.json` discovery document into the
/// app's `[Endpoint]` collection.
///
/// The document is an OpenAPI 3.1 doc whose every priced operation under
/// `paths.<path>.<httpMethod>` carries an `x-payment-info` extension with an
/// `offers[]` list (the payment-discovery draft: `intent` / `method` /
/// `amount` per offer, plus pay-kit extras like `scheme` / `network` / `payTo`).
/// Operations with no `x-payment-info` (health, `/openapi.json`, docs) are free
/// and excluded.
///
/// Hyphenated extension keys and the arbitrarily-nested offers array are
/// awkward for synthesized `Codable`, so this parses with `JSONSerialization`
/// into `[String: Any]` — the same approach `ContentView` already uses for the
/// `Payment-Receipt` header.
enum OpenAPI {
    /// Build the priced-endpoint collection from a raw `/openapi.json` body.
    /// Returns endpoints in a stable order (sorted by path then method) so the
    /// per-index `tint` and the collection layout don't reshuffle between loads.
    static func endpoints(from data: Data) throws -> [Endpoint] {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw OpenAPIError.notAnObject
        }
        guard let paths = root["paths"] as? [String: Any] else {
            throw OpenAPIError.missingPaths
        }

        var parsed: [(path: String, method: String, operation: [String: Any])] = []
        for (path, item) in paths {
            guard let operations = item as? [String: Any] else { continue }
            for (method, op) in operations {
                guard let operation = op as? [String: Any] else { continue }
                // Only priced operations are tappable. Free routes (health,
                // docs, /openapi.json) carry no `x-payment-info`.
                guard operation["x-payment-info"] is [String: Any] else { continue }
                parsed.append((path: path, method: method.uppercased(), operation: operation))
            }
        }

        // Deterministic order: path, then method.
        parsed.sort { lhs, rhs in
            lhs.path == rhs.path ? lhs.method < rhs.method : lhs.path < rhs.path
        }

        return parsed.enumerated().map { index, entry in
            endpoint(path: entry.path, method: entry.method, operation: entry.operation, index: index)
        }
    }

    // MARK: - Single operation → Endpoint

    private static func endpoint(
        path: String,
        method: String,
        operation: [String: Any],
        index: Int
    ) -> Endpoint {
        let paymentInfo = operation["x-payment-info"] as? [String: Any]
        let offers = paymentInfo?["offers"] as? [[String: Any]] ?? []
        let firstOffer = offers.first

        let summary = (operation["summary"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let label = (summary?.isEmpty == false) ? summary! : path

        let intent = firstOffer?["intent"] as? String
        let scheme = firstOffer?["scheme"] as? String
        let payMethod = firstOffer?["method"] as? String

        return Endpoint(
            id: "\(method) \(path)",
            label: label,
            method: PayKit.HTTPMethod(rawValue: method),
            path: requestPath(from: path),
            priceUSD: priceString(from: firstOffer),
            systemImage: systemImage(intent: intent, scheme: scheme, method: payMethod),
            tint: tint(for: index),
            intent: (intent?.isEmpty == false) ? intent!.lowercased() : "charge",
            methods: methods(from: offers),
            selectedProtocol: selectedProtocol(from: offers, intent: intent)
        )
    }

    /// Accepted protocols (offer `method`s) de-duplicated in offer order, so the
    /// card can surface the MPP/x402 split. E.g. `["x402", "mpp"]`.
    static func methods(from offers: [[String: Any]]) -> [String] {
        var methods: [String] = []
        for offer in offers {
            if let m = offer["method"] as? String, !m.isEmpty, !methods.contains(m) {
                methods.append(m)
            }
        }
        return methods
    }

    /// The protocol the demo actually settles over: it drives charge endpoints
    /// through the MPP client, so `mpp` is selected whenever a charge endpoint
    /// advertises it. Non-charge flows aren't consumed here, so nothing is
    /// selected.
    static func selectedProtocol(from offers: [[String: Any]], intent: String?) -> String? {
        guard intent?.lowercased() ?? "charge" == "charge" else { return nil }
        let ms = methods(from: offers)
        return ms.contains("mpp") ? "mpp" : ms.first
    }

    // MARK: - Field derivation

    /// Turn a templated OpenAPI path (`/api/v1/quote/{symbol}`) into a concrete
    /// request path by filling each `{param}` with a placeholder, so the URL
    /// actually reaches the mounted route instead of 404-ing on the literal
    /// `{symbol}` segment.
    static func requestPath(from openApiPath: String) -> String {
        guard openApiPath.contains("{") else { return openApiPath }
        var result = ""
        var insideParam = false
        for char in openApiPath {
            switch char {
            case "{":
                insideParam = true
                result.append("demo")
            case "}":
                insideParam = false
            default:
                if !insideParam { result.append(char) }
            }
        }
        return result
    }

    /// Format the offer price as a dollar string. The offer's `amount` is a
    /// base-unit integer string (USDC has 6 decimals); fall back to the
    /// human-readable `description` (e.g. `"0.01 USDC"`) and finally a dash.
    static func priceString(from offer: [String: Any]?) -> String {
        if let amount = offer?["amount"] as? String,
           let baseUnits = Decimal(string: amount),
           let formatted = Self.dollarFormatter.string(from: (baseUnits / 1_000_000) as NSDecimalNumber) {
            // `upto` usage and `session` deposits are ceilings, not the amount
            // actually settled — label them so the card price isn't mistaken for
            // a fixed charge.
            let scheme = (offer?["scheme"] as? String)?.lowercased()
            let prefix = (scheme == "upto" || scheme == "session") ? "up to " : ""
            return prefix + "$" + formatted
        }
        if let description = offer?["description"] as? String, !description.isEmpty {
            return description
        }
        return "—"
    }

    private static let dollarFormatter: NumberFormatter = {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        f.minimumFractionDigits = 2
        f.maximumFractionDigits = 6
        return f
    }()

    /// Pick an SF Symbol by payment intent/scheme/method, with sensible
    /// fallbacks. `intent` is the discovery-draft field (`charge` / `session` /
    /// `subscription`); `scheme` distinguishes x402 `exact` / `upto`.
    static func systemImage(intent: String?, scheme: String?, method: String?) -> String {
        switch intent?.lowercased() {
        case "charge": return "creditcard"
        case "session": return "dot.radiowaves.left.and.right"
        case "subscription": return "repeat"
        case "usage": return "gauge"
        default: break
        }
        switch scheme?.lowercased() {
        case "exact": return "bolt"
        case "upto": return "gauge"
        case "subscription": return "repeat"
        case "session": return "dot.radiowaves.left.and.right"
        default: break
        }
        return method?.lowercased() == "x402" ? "bolt" : "creditcard"
    }

    /// Cycle through a fixed palette so each card gets a distinct tint.
    static func tint(for index: Int) -> Color {
        let palette: [Color] = [.blue, .indigo, .purple, .pink, .orange, .green, .red, .teal]
        return palette[index % palette.count]
    }
}

/// Failure modes when decoding `/openapi.json`.
enum OpenAPIError: Error, LocalizedError {
    case httpStatus(Int)
    case notAnObject
    case missingPaths

    var errorDescription: String? {
        switch self {
        case .httpStatus(let code): return "openapi.json returned HTTP \(code)."
        case .notAnObject: return "openapi.json was not a JSON object."
        case .missingPaths: return "openapi.json had no `paths`."
        }
    }
}
