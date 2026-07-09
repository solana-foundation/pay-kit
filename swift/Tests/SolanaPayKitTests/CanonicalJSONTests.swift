import Foundation
import Testing
@testable import SolanaPayKit

@Suite("Canonical JSON")
struct CanonicalJSONTests {
    private func canonicalData(_ json: String) throws -> Data {
        try CanonicalJSON.encode(json: Data(json.utf8))
    }

    private func canonical(_ json: String) throws -> String {
        let data = try canonicalData(json)
        return String(decoding: data, as: UTF8.self)
    }

    @Test
    func sortsKeysByUTF16CodeUnits() throws {
        let input = #"{"z":1,"\u20ac":2,"\ud83d\ude00":3,"\ufb03":4,"\u00e9":5}"#
        let expected = "{\"z\":1,\"\u{00e9}\":5,\"\u{20ac}\":2,\"\u{1f600}\":3,\"\u{fb03}\":4}"
        #expect(try canonical(input) == expected)
        #expect(try Base64URL.encode(canonicalData(input)) == "eyJ6IjoxLCLDqSI6NSwi4oKsIjoyLCLwn5iAIjozLCLvrIMiOjR9")
    }

    @Test
    func leavesLineAndParagraphSeparatorsRaw() throws {
        let result = try canonical(#"{"sep":"a\u2028b\u2029c"}"#)
        #expect(result == "{\"sep\":\"a\u{2028}b\u{2029}c\"}")
        #expect(!result.contains("\\u2028"))
        #expect(!result.contains("\\u2029"))
        #expect(try Base64URL.encode(canonicalData(#"{"sep":"a\u2028b\u2029c"}"#)) == "eyJzZXAiOiJh4oCoYuKAqWMifQ")
    }

    @Test
    func normalizesNumbersWithECMAScriptSemantics() throws {
        let result = try canonical(#"{"a":1.0,"b":1E2,"c":100.00,"d":1.50,"zero":-0}"#)
        #expect(result == #"{"a":1,"b":100,"c":100,"d":1.5,"zero":0}"#)
        #expect(try Base64URL.encode(canonicalData(#"{"a":1.0,"b":1E2,"c":100.00,"d":1.50,"zero":-0}"#)) == "eyJhIjoxLCJiIjoxMDAsImMiOjEwMCwiZCI6MS41LCJ6ZXJvIjowfQ")
    }

    @Test
    func canonicalizesEveryFoundationJSONShapeAndNumberBoundary() throws {
        let value: [String: Any] = [
            "small": NSNumber(value: 1e-7),
            "big": NSNumber(value: 1e21),
            "negative": NSNumber(value: -12.5),
            "array": [NSNull(), true, false, "line\n\t", NSNumber(value: 1e-6)],
        ]

        let result = String(decoding: try CanonicalJSON.encode(value), as: UTF8.self)
        #expect(result == #"{"array":[null,true,false,"line\n\t",0.000001],"big":1e+21,"negative":-12.5,"small":1e-7}"#)
    }

    @Test
    func escapesControlsAndRejectsInvalidFoundationValues() throws {
        let controls = "\u{0000}\u{0008}\u{0009}\u{000A}\u{000C}\u{000D}\\\"\u{001F}"
        let result = String(decoding: try CanonicalJSON.encode(["controls": controls]), as: UTF8.self)
        #expect(result == #"{"controls":"\u0000\b\t\n\f\r\\\"\u001f"}"#)

        #expect(throws: PayKitError.self) {
            _ = try CanonicalJSON.encode(NSNumber(value: Double.nan))
        }
        #expect(throws: PayKitError.self) {
            _ = try CanonicalJSON.encode(["unsupported": Date()])
        }
    }
}
