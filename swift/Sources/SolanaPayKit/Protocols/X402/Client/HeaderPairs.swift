import Foundation

extension HTTPURLResponse {
    /// The response headers as `(name, value)` pairs, the shape the x402
    /// challenge parsers consume. Keys absent from `allHeaderFields` as strings,
    /// or with no resolvable value, are skipped.
    func headerPairs() -> [(name: String, value: String)] {
        var result: [(name: String, value: String)] = []
        for (rawKey, _) in allHeaderFields {
            guard let key = rawKey as? String,
                  let value = value(forHTTPHeaderField: key) else { continue }
            result.append((name: key, value: value))
        }
        return result
    }
}
