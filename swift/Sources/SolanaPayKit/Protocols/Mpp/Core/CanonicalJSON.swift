import Foundation

/// RFC 8785 JSON Canonicalization Scheme (JCS) serializer used for MPP wire
/// credentials. It canonicalizes Foundation JSON values using the same
/// UTF-16 key ordering and ECMAScript number semantics JCS requires.
public enum CanonicalJSON {
    /// Parses a JSON document and emits its canonical UTF-8 representation.
    public static func encode(json data: Data) throws -> Data {
        let value = try JSONSerialization.jsonObject(
            with: data,
            options: [.fragmentsAllowed]
        )
        return try encode(value)
    }

    /// Emits the canonical UTF-8 representation of a Foundation JSON value.
    ///
    /// This accepts the object graph returned by `JSONSerialization`, which
    /// also lets the conformance runner drive the SDK encoder directly.
    public static func encode(_ value: Any) throws -> Data {
        var output = ""
        try write(value, into: &output)
        return Data(output.utf8)
    }

    private static func write(_ value: Any, into output: inout String) throws {
        switch value {
        case is NSNull:
            output += "null"
        case let number as NSNumber:
            if String(cString: number.objCType) == "c" {
                output += number.boolValue ? "true" : "false"
            } else {
                output += try ecmaNumber(number.doubleValue)
            }
        case let string as String:
            writeString(string, into: &output)
        case let array as [Any]:
            output += "["
            for (index, item) in array.enumerated() {
                if index > 0 { output += "," }
                try write(item, into: &output)
            }
            output += "]"
        case let object as [String: Any]:
            output += "{"
            let keys = object.keys.sorted(by: utf16Precedes)
            for (index, key) in keys.enumerated() {
                if index > 0 { output += "," }
                writeString(key, into: &output)
                output += ":"
                try write(object[key]!, into: &output)
            }
            output += "}"
        default:
            throw PayKitError.invalidJSON("unsupported JSON value: \(type(of: value))")
        }
    }

    private static func utf16Precedes(_ lhs: String, _ rhs: String) -> Bool {
        var left = lhs.utf16.makeIterator()
        var right = rhs.utf16.makeIterator()

        while let l = left.next(), let r = right.next() {
            if l != r { return l < r }
        }
        return left.next() == nil && right.next() != nil
    }

    private static func writeString(_ value: String, into output: inout String) {
        output += "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22:
                output += "\\\""
            case 0x5C:
                output += "\\\\"
            case 0x08:
                output += "\\b"
            case 0x09:
                output += "\\t"
            case 0x0A:
                output += "\\n"
            case 0x0C:
                output += "\\f"
            case 0x0D:
                output += "\\r"
            case 0x00...0x1F:
                let hex = String(scalar.value, radix: 16)
                output += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
            default:
                output.unicodeScalars.append(scalar)
            }
        }
        output += "\""
    }

    /// Swift's shortest-roundtrip `Double.description` supplies the digits;
    /// JCS then applies ECMAScript's fixed/exponent thresholds and exponent
    /// spelling. This also collapses negative zero as ECMAScript does.
    private static func ecmaNumber(_ value: Double) throws -> String {
        guard value.isFinite else {
            throw PayKitError.invalidJSON("non-finite JSON number")
        }
        guard value != 0 else { return "0" }

        let source = value.description.lowercased()
        let sign = source.hasPrefix("-") ? "-" : ""
        let unsigned = sign.isEmpty ? source : String(source.dropFirst())
        let exponentParts = unsigned.split(separator: "e", maxSplits: 1, omittingEmptySubsequences: false)
        guard exponentParts.count <= 2 else {
            throw PayKitError.invalidJSON("invalid finite number \(source)")
        }

        let exponent = exponentParts.count == 2 ? Int(exponentParts[1]) : 0
        guard let exponent else {
            throw PayKitError.invalidJSON("invalid finite number \(source)")
        }

        let mantissa = String(exponentParts[0])
        let point = mantissa.firstIndex(of: ".")
        let beforePoint = point.map { String(mantissa[..<$0]) } ?? mantissa
        let afterPoint = point.map { String(mantissa[mantissa.index(after: $0)...]) } ?? ""
        let allDigits = beforePoint + afterPoint
        guard let firstSignificant = allDigits.firstIndex(where: { $0 != "0" }) else {
            return "0"
        }

        var digits = String(allDigits[firstSignificant...])
        while digits.last == "0" { digits.removeLast() }
        let leadingZeroCount = allDigits.distance(from: allDigits.startIndex, to: firstSignificant)
        let scientificExponent = exponent + beforePoint.count - 1 - leadingZeroCount

        if scientificExponent >= 0 && scientificExponent < 21 {
            let integerDigits = scientificExponent + 1
            if digits.count <= integerDigits {
                return sign + digits + String(repeating: "0", count: integerDigits - digits.count)
            }
            let split = digits.index(digits.startIndex, offsetBy: integerDigits)
            return sign + String(digits[..<split]) + "." + String(digits[split...])
        }

        if scientificExponent >= -6 && scientificExponent < 0 {
            return sign + "0." + String(repeating: "0", count: -scientificExponent - 1) + digits
        }

        let first = digits.removeFirst()
        let mantissaText = digits.isEmpty ? String(first) : String(first) + "." + digits
        let exponentText = scientificExponent >= 0 ? "+\(scientificExponent)" : "\(scientificExponent)"
        return sign + mantissaText + "e" + exponentText
    }
}
