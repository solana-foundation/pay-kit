import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - JSONValue round-trip + codec branch coverage

@Suite("JSONValue codec branches")
struct JSONValueCodecTests {
    /// Decode every scalar/composite variant from raw JSON so each arm of
    /// `JSONValue.init(from:)` is exercised (null, bool, int, double, string,
    /// array, object), then re-encode and assert a byte-stable round trip.
    @Test
    func decodesAndEncodesEveryVariant() throws {
        let json = """
        {
          "s": "hello",
          "i": 42,
          "d": 3.5,
          "b": true,
          "n": null,
          "arr": [1, "two", false, null],
          "obj": { "nested": "value" }
        }
        """
        let value = try JSONDecoder().decode(JSONValue.self, from: Data(json.utf8))
        guard case let .object(root) = value else {
            Issue.record("top level must decode as object")
            return
        }
        #expect(root["s"] == .string("hello"))
        #expect(root["i"] == .int(42))
        #expect(root["d"] == .double(3.5))
        #expect(root["b"] == .bool(true))
        #expect(root["n"] == .null)
        #expect(root["arr"] == .array([.int(1), .string("two"), .bool(false), .null]))
        #expect(root["obj"] == .object(["nested": .string("value")]))

        // Re-encode and re-decode: JSONValue must be its own inverse.
        let reEncoded = try JSONEncoder().encode(value)
        let reDecoded = try JSONDecoder().decode(JSONValue.self, from: reEncoded)
        #expect(reDecoded == value)
    }

    /// A top-level JSON array (not an object) must decode as `.array`, so the
    /// array arm of the decoder is hit at the root.
    @Test
    func decodesTopLevelArray() throws {
        let value = try JSONDecoder().decode(JSONValue.self, from: Data("[1,2,3]".utf8))
        #expect(value == .array([.int(1), .int(2), .int(3)]))
    }

    /// Each scalar arm of `encode(to:)` is exercised individually so the
    /// switch does not rely on a single fixture for coverage.
    @Test
    func encodesEachScalarArm() throws {
        let encoder = JSONEncoder()
        #expect(String(decoding: try encoder.encode(JSONValue.string("x")), as: UTF8.self) == "\"x\"")
        #expect(String(decoding: try encoder.encode(JSONValue.int(7)), as: UTF8.self) == "7")
        #expect(String(decoding: try encoder.encode(JSONValue.bool(false)), as: UTF8.self) == "false")
        #expect(String(decoding: try encoder.encode(JSONValue.null), as: UTF8.self) == "null")
        // Double encodes to a JSON number.
        let d = String(decoding: try encoder.encode(JSONValue.double(1.25)), as: UTF8.self)
        #expect(d == "1.25")
    }

    /// `JSONValue.decode(_:)` round-trips a value into a typed `Decodable`.
    @Test
    func decodeIntoTypedValue() throws {
        struct Point: Decodable, Equatable { let x: Int; let y: Int }
        let value = JSONValue.object(["x": .int(3), "y": .int(4)])
        let point = try value.decode(Point.self)
        #expect(point == Point(x: 3, y: 4))
    }

    /// `JSONValue.encoding(_:)` builds a `JSONValue` from an `Encodable`,
    /// preserving its shape.
    @Test
    func encodingFromTypedValue() throws {
        struct Point: Encodable { let x: Int; let y: Int }
        let value = try JSONValue.encoding(Point(x: 1, y: 2))
        #expect(value == .object(["x": .int(1), "y": .int(2)]))
    }
}

// MARK: - X402AcceptsEntry extra accessors

@Suite("X402AcceptsEntry extra accessors")
struct X402AcceptsEntryExtraTests {
    private func entry(extra: [String: JSONValue]?) -> X402AcceptsEntry {
        X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: "1", maxAmountRequired: nil, asset: "SOL",
            payTo: "x", recipient: nil, extra: extra
        )
    }

    @Test
    func extraStringReturnsValueOrNil() {
        let e = entry(extra: ["k": .string("v"), "empty": .string(""), "notString": .int(5)])
        #expect(e.extraString("k") == "v")
        // Empty string is treated as absent.
        #expect(e.extraString("empty") == nil)
        // Wrong type is absent.
        #expect(e.extraString("notString") == nil)
        // Missing key is absent.
        #expect(e.extraString("missing") == nil)
        // nil extra dict is absent.
        #expect(entry(extra: nil).extraString("k") == nil)
    }

    @Test
    func extraIntReturnsValueOrNil() {
        let e = entry(extra: ["k": .int(9), "notInt": .string("nope")])
        #expect(e.extraInt("k") == 9)
        #expect(e.extraInt("notInt") == nil)
        #expect(e.extraInt("missing") == nil)
        #expect(entry(extra: nil).extraInt("k") == nil)
    }

    @Test
    func effectiveHelpersFallBack() {
        // amount falls back to maxAmountRequired; payTo to recipient.
        let e = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: nil, maxAmountRequired: "500", asset: nil,
            payTo: nil, recipient: "rcpt", extra: nil
        )
        #expect(e.effectiveAmount == "500")
        #expect(e.effectivePayTo == "rcpt")
    }
}

// MARK: - Envelope encode/decode round-trips

@Suite("X402 envelope round-trips")
struct X402EnvelopeRoundTripTests {
    @Test
    func paymentRequiredEnvelopeRoundTrips() throws {
        let entry = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: "1000", maxAmountRequired: nil, asset: "SOL",
            payTo: "x", recipient: nil, extra: nil
        )
        let envelope = X402PaymentRequiredEnvelope(
            x402Version: 2, accepts: [entry],
            extensions: .object(["foo": .string("bar")])
        )
        let data = try JSONEncoder().encode(envelope)
        let decoded = try JSONDecoder().decode(X402PaymentRequiredEnvelope.self, from: data)
        #expect(decoded.x402Version == 2)
        #expect(decoded.accepts.count == 1)
        #expect(decoded.accepts[0].effectiveAmount == "1000")
        #expect(decoded.extensions == .object(["foo": .string("bar")]))
    }

    /// The nil-extensions / nil-version path of the envelope must encode and
    /// decode without emitting the omitted keys.
    @Test
    func paymentRequiredEnvelopeOmitsNilFields() throws {
        let entry = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: "1000", maxAmountRequired: nil, asset: "SOL",
            payTo: "x", recipient: nil, extra: nil
        )
        let envelope = X402PaymentRequiredEnvelope(x402Version: nil, accepts: [entry])
        let data = try JSONEncoder().encode(envelope)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(obj["x402Version"] == nil)
        #expect(obj["extensions"] == nil)
        let decoded = try JSONDecoder().decode(X402PaymentRequiredEnvelope.self, from: data)
        #expect(decoded.x402Version == nil)
        #expect(decoded.extensions == nil)
    }

    /// A signature envelope built in code (raw == nil on accepted) encodes the
    /// typed accepted object, then decodes back with the modeled fields intact.
    @Test
    func signatureEnvelopeTypedFallbackRoundTrips() throws {
        let accepted = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: "1000", maxAmountRequired: nil, asset: "SOL",
            payTo: "rcpt", recipient: nil, extra: nil
        )
        let envelope = X402PaymentSignatureEnvelope(
            x402Version: 2, accepted: accepted,
            payload: X402PaymentPayload(transaction: "AA==")
        )
        let data = try JSONEncoder().encode(envelope)
        let decoded = try JSONDecoder().decode(X402PaymentSignatureEnvelope.self, from: data)
        #expect(decoded.x402Version == 2)
        #expect(decoded.accepted?.asset == "SOL")
        #expect(decoded.payload.transaction == "AA==")
        #expect(decoded.scheme == nil)
        #expect(decoded.network == nil)
    }

    /// A legacy-shape envelope (scheme + network siblings, no accepted) must
    /// encode those top-level fields and omit accepted.
    @Test
    func signatureEnvelopeLegacyShapeEncodesSchemeNetwork() throws {
        let envelope = X402PaymentSignatureEnvelope(
            x402Version: 1, scheme: "exact", network: "solana-devnet",
            accepted: nil, payload: X402PaymentPayload(transaction: "AA==")
        )
        let data = try JSONEncoder().encode(envelope)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(obj["scheme"] as? String == "exact")
        #expect(obj["network"] as? String == "solana-devnet")
        #expect(obj["accepted"] == nil)
        let decoded = try JSONDecoder().decode(X402PaymentSignatureEnvelope.self, from: data)
        #expect(decoded.scheme == "exact")
        #expect(decoded.network == "solana-devnet")
        #expect(decoded.accepted == nil)
    }

    /// When accepted carries a verbatim `raw`, the encoder must emit that raw
    /// object rather than the typed encoding (echo-verbatim path).
    @Test
    func signatureEnvelopeEchoesRawAcceptedVerbatim() throws {
        // Decode an entry from wire so its `raw` is captured, then embed it.
        let wire = """
        {
          "scheme": "exact",
          "network": "\(SolanaNetwork.devnet)",
          "amount": "1000",
          "asset": "SOL",
          "payTo": "rcpt",
          "serverOnlyField": "keep-me"
        }
        """
        let accepted = try JSONDecoder().decode(X402AcceptsEntry.self, from: Data(wire.utf8))
        #expect(accepted.raw != nil)
        let envelope = X402PaymentSignatureEnvelope(
            x402Version: 2, accepted: accepted,
            payload: X402PaymentPayload(transaction: "AA==")
        )
        let data = try JSONEncoder().encode(envelope)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let acceptedObj = obj["accepted"] as! [String: Any]
        // The unmodeled server field survives because raw was echoed verbatim.
        #expect(acceptedObj["serverOnlyField"] as? String == "keep-me")
    }

    /// An envelope carrying empty extensions must omit the `extensions` key
    /// (echo-and-omit rule).
    @Test
    func signatureEnvelopeOmitsEmptyExtensions() throws {
        let envelope = X402PaymentSignatureEnvelope(
            x402Version: 2, accepted: nil,
            payload: X402PaymentPayload(transaction: "AA=="),
            extensions: X402PaymentExtensions()
        )
        let data = try JSONEncoder().encode(envelope)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(obj["extensions"] == nil)
    }

    /// An envelope carrying a populated extensions map must emit it and decode
    /// it back.
    @Test
    func signatureEnvelopeEncodesNonEmptyExtensions() throws {
        let ext = X402PaymentExtensions(raw: ["custom": .string("v")])
        let envelope = X402PaymentSignatureEnvelope(
            x402Version: 2, accepted: nil,
            payload: X402PaymentPayload(transaction: "AA=="),
            extensions: ext
        )
        let data = try JSONEncoder().encode(envelope)
        let decoded = try JSONDecoder().decode(X402PaymentSignatureEnvelope.self, from: data)
        #expect(decoded.extensions?.raw["custom"] == .string("v"))
    }
}

// MARK: - Payment-identifier extension coverage

@Suite("X402 payment-identifier extensions")
struct X402PaymentIdentifierTests {
    @Test
    func infoAndExtensionRoundTrip() throws {
        let info = X402PaymentIdentifierInfo(required: true, id: "pay_abcdef0123456789")
        let ext = X402PaymentIdentifierExtension(info: info, schema: .object(["k": .string("v")]))
        let data = try JSONEncoder().encode(ext)
        let decoded = try JSONDecoder().decode(X402PaymentIdentifierExtension.self, from: data)
        #expect(decoded.info.required == true)
        #expect(decoded.info.id == "pay_abcdef0123456789")
        #expect(decoded.schema == .object(["k": .string("v")]))
    }

    /// The extension decoder defaults `info` to an empty object when the key
    /// is absent, and omits `schema` when nil.
    @Test
    func extensionDefaultsInfoWhenAbsent() throws {
        let decoded = try JSONDecoder().decode(
            X402PaymentIdentifierExtension.self, from: Data("{}".utf8)
        )
        #expect(decoded.info.required == nil)
        #expect(decoded.info.id == nil)
        #expect(decoded.schema == nil)
    }

    @Test
    func emptyExtensionsIsEmptyAndHasNoIdentifier() {
        let ext = X402PaymentExtensions()
        #expect(ext.isEmpty)
        #expect(ext.paymentIdentifier == nil)
        #expect(ext.requiresPaymentIdentifier == false)
    }

    /// `paymentIdentifier` decodes the typed extension out of the verbatim map.
    @Test
    func paymentIdentifierDecodesFromRaw() throws {
        let inner = try JSONValue.encoding(
            X402PaymentIdentifierExtension(
                info: X402PaymentIdentifierInfo(required: true, id: nil)
            )
        )
        let ext = X402PaymentExtensions(raw: [X402PaymentIdentifierKey: inner])
        #expect(!ext.isEmpty)
        #expect(ext.paymentIdentifier?.info.required == true)
        #expect(ext.requiresPaymentIdentifier == true)
    }

    /// `withPaymentIdentifierID` fills in the client-side id while preserving
    /// the server's `required` flag and `schema`.
    @Test
    func withPaymentIdentifierIDPreservesServerFields() throws {
        let serverExt = X402PaymentIdentifierExtension(
            info: X402PaymentIdentifierInfo(required: true, id: nil),
            schema: .object(["shape": .string("thing")])
        )
        let ext = X402PaymentExtensions(
            raw: [X402PaymentIdentifierKey: try JSONValue.encoding(serverExt)]
        )
        let updated = ext.withPaymentIdentifierID("pay_deadbeefcafebabe01020304")
        let pid = updated.paymentIdentifier
        #expect(pid?.info.id == "pay_deadbeefcafebabe01020304")
        #expect(pid?.info.required == true)
        #expect(pid?.schema == .object(["shape": .string("thing")]))
    }

    /// `withPaymentIdentifierID` creates the entry even when the server did not
    /// advertise one.
    @Test
    func withPaymentIdentifierIDCreatesEntryWhenAbsent() {
        let ext = X402PaymentExtensions()
        let updated = ext.withPaymentIdentifierID("pay_0123456789abcdef01020304")
        #expect(updated.paymentIdentifier?.info.id == "pay_0123456789abcdef01020304")
        #expect(updated.paymentIdentifier?.info.required == nil)
    }

    /// `echoing(nil)` returns nil; `echoing` of a non-object throws; `echoing`
    /// of an object round-trips the map verbatim.
    @Test
    func echoingBranches() throws {
        #expect(try X402PaymentExtensions.echoing(nil) == nil)

        #expect(throws: MppError.self) {
            _ = try X402PaymentExtensions.echoing(.string("not an object"))
        }

        let echoed = try X402PaymentExtensions.echoing(.object(["k": .string("v")]))
        #expect(echoed?.raw["k"] == .string("v"))
    }
}

// MARK: - Payment-identifier id generation

@Suite("generateX402PaymentIdentifierID")
struct GeneratePaymentIdentifierTests {
    @Test
    func deterministicWithInjectedBytes() {
        let bytes = Data([
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ])
        let id = generateX402PaymentIdentifierID(randomBytes: { bytes })
        #expect(id == "pay_deadbeefcafebabe0102030405060708")
    }

    @Test
    func defaultGeneratorProducesValidShape() {
        let id = generateX402PaymentIdentifierID()
        #expect(id.hasPrefix("pay_"))
        // pay_ + 32 hex chars.
        #expect(id.count == 36)
        let hex = id.dropFirst(4)
        #expect(hex.allSatisfy { $0.isHexDigit })
        // Satisfies the spec pattern length (16..128).
        #expect(id.count >= 16 && id.count <= 128)
    }

    @Test
    func distinctAcrossCalls() {
        // Two default-random ids should (overwhelmingly) differ.
        #expect(generateX402PaymentIdentifierID() != generateX402PaymentIdentifierID())
    }
}

// MARK: - Challenge selection value type

@Suite("X402ChallengeSelection")
struct X402ChallengeSelectionTests {
    @Test
    func defaultInitLeavesFieldsNil() {
        let sel = X402ChallengeSelection()
        #expect(sel.network == nil)
        #expect(sel.currencies == nil)
    }

    @Test
    func customInitStoresFields() {
        let sel = X402ChallengeSelection(network: "devnet", currencies: ["USDC", "SOL"])
        #expect(sel.network == "devnet")
        #expect(sel.currencies == ["USDC", "SOL"])
    }
}
