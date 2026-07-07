import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - Fixtures

private enum UptoFixture {
    static let operatorAddr = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
    static let payTo = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
    static let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    static let blockhash = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
    static let network = SolanaNetwork.devnet
    static let amount = "1000000"
    static let recentSlot = "1000"
    static let recentSlotValue: UInt64 = 1000

    /// Deterministic 32-byte seed signer.
    static func signer() throws -> MemorySigner {
        try MemorySigner(secretKey: Data(repeating: 7, count: 32))
    }

    static func extra(
        facilitatorAddress: String = operatorAddr,
        facilitatorFee: Int = 0,
        assetTransferMethod: String = X402UptoAssetTransferMethod,
        recentBlockhash: String? = blockhash,
        tokenProgram: String? = nil,
        channelProgram: String? = nil,
        recentSlot: String? = recentSlot,
        validAfter: Int? = nil
    ) -> X402UptoExtra {
        X402UptoExtra(
            assetTransferMethod: assetTransferMethod,
            tokenProgram: tokenProgram,
            facilitatorAddress: facilitatorAddress,
            facilitatorFee: facilitatorFee,
            channelProgram: channelProgram,
            recentBlockhash: recentBlockhash,
            lastValidBlockHeight: nil,
            recentSlot: recentSlot,
            validAfter: validAfter
        )
    }

    static func requirements(
        payTo: String = payTo,
        amount: String = amount,
        extra: X402UptoExtra? = nil
    ) -> X402UptoRequirements {
        X402UptoRequirements(
            scheme: X402UptoScheme,
            network: network,
            amount: amount,
            asset: mint,
            payTo: payTo,
            maxTimeoutSeconds: 300,
            extra: extra ?? Self.extra()
        )
    }
}

// MARK: - Minimal legacy transaction decoder (test-only)

/// Just enough of the legacy transaction wire format to assert the channel
/// `open` instruction data the upto builder embeds (no version prefix byte).
private struct DecodedOpen {
    let salt: UInt64
    let deposit: UInt64
    let gracePeriod: UInt32
    let openSlot: UInt64
    let recipientBps: [UInt16]
    let signatureCount: Int
    /// True when the signer slot at the payer's account index carries a
    /// non-zero (i.e. populated) signature.
    let payerSlotSigned: Bool
    /// True when the fee-payer (account index 0) signature slot is all zero.
    let feePayerSlotEmpty: Bool
    let payerIndex: Int
}

private enum LegacyTxDecoder {
    static func shortVec(_ data: Data, _ off: inout Int) -> Int {
        var value = 0, shift = 0
        while true {
            let byte = data[data.startIndex + off]; off += 1
            value |= Int(byte & 0x7F) << shift
            if (byte & 0x80) == 0 { return value }
            shift += 7
        }
    }

    static func le64(_ d: Data, _ o: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(d[d.startIndex + o + i]) << (8 * i) }
        return v
    }

    static func le32(_ d: Data, _ o: Int) -> UInt32 {
        var v: UInt32 = 0
        for i in 0..<4 { v |= UInt32(d[d.startIndex + o + i]) << (8 * i) }
        return v
    }

    static func le16(_ d: Data, _ o: Int) -> UInt16 {
        UInt16(d[d.startIndex + o]) | (UInt16(d[d.startIndex + o + 1]) << 8)
    }

    static func decode(base64: String, payer: Pubkey) throws -> DecodedOpen {
        guard let data = Data(base64Encoded: base64) else {
            throw PayKitError.invalidTransaction("not base64")
        }
        var off = 0
        let sigCount = shortVec(data, &off)
        var sigs: [Data] = []
        for _ in 0..<sigCount {
            sigs.append(data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + 64)))
            off += 64
        }
        let numRequired = Int(data[data.startIndex + off]); off += 1
        _ = data[data.startIndex + off]; off += 1 // readonly signed
        _ = data[data.startIndex + off]; off += 1 // readonly unsigned
        let keyCount = shortVec(data, &off)
        var keys: [Pubkey] = []
        for _ in 0..<keyCount {
            let raw = data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + 32))
            keys.append(try Pubkey(bytes: raw)); off += 32
        }
        off += 32 // blockhash
        let ixCount = shortVec(data, &off)
        var openData = Data()
        for _ in 0..<ixCount {
            off += 1 // programIdIndex
            let acctCount = shortVec(data, &off)
            off += acctCount // 1 byte per account index
            let dataLen = shortVec(data, &off)
            openData = data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + dataLen))
            off += dataLen
        }
        // open data: disc(1) salt(8) deposit(8) gracePeriod(4) openSlot(8) count(4) [pk(32) bps(2)]*
        let salt = le64(openData, 1)
        let deposit = le64(openData, 9)
        let gracePeriod = le32(openData, 17)
        let openSlot = le64(openData, 21)
        let count = Int(le32(openData, 29))
        var bps: [UInt16] = []
        var p = 33
        for _ in 0..<count {
            p += 32
            bps.append(le16(openData, p)); p += 2
        }
        let payerIndex = keys.firstIndex(of: payer) ?? -1
        let payerSig = (payerIndex >= 0 && payerIndex < sigs.count) ? sigs[payerIndex] : Data()
        let feePayerSig = sigs.first ?? Data()
        return DecodedOpen(
            salt: salt,
            deposit: deposit,
            gracePeriod: gracePeriod,
            openSlot: openSlot,
            recipientBps: bps,
            signatureCount: numRequired,
            payerSlotSigned: payerSig.contains { $0 != 0 },
            feePayerSlotEmpty: feePayerSig.allSatisfy { $0 == 0 },
            payerIndex: payerIndex
        )
    }
}

// MARK: - Build error tests

@Suite("x402 upto build errors")
struct X402UptoBuildErrorTests {
    @Test
    func rejectsWrongAssetTransferMethod() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(
            extra: UptoFixture.extra(assetTransferMethod: "permit2")
        )
        await #expect(throws: (any Error).self) {
            _ = try await buildUptoPayload(signer: signer, requirements: req, expiresAt: 1000)
        }
    }

    @Test
    func rejectsMissingFacilitatorAddress() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(
            extra: UptoFixture.extra(facilitatorAddress: "")
        )
        await #expect(throws: (any Error).self) {
            _ = try await buildUptoPayload(signer: signer, requirements: req, expiresAt: 1000)
        }
    }

    @Test
    func rejectsMissingRecentBlockhash() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(
            extra: UptoFixture.extra(recentBlockhash: nil)
        )
        await #expect(throws: (any Error).self) {
            _ = try await buildUptoPayload(signer: signer, requirements: req, expiresAt: 1000)
        }
    }

    @Test
    func rejectsFacilitatorFeeOutOfRange() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(
            extra: UptoFixture.extra(facilitatorFee: 10_001)
        )
        await #expect(throws: (any Error).self) {
            _ = try await buildUptoPayload(signer: signer, requirements: req, expiresAt: 1000)
        }
    }

    @Test
    func rejectsMissingRecentSlot() async throws {
        // recentSlot carries the channel-PDA openSlot seed; with neither an
        // explicit parameter nor extra.recentSlot the open cannot be derived.
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(
            extra: UptoFixture.extra(recentSlot: nil)
        )
        await #expect(throws: (any Error).self) {
            _ = try await buildUptoPayload(signer: signer, requirements: req, expiresAt: 1000)
        }
    }

    @Test
    func rejectsMalformedExtraRecentSlot() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(
            extra: UptoFixture.extra(recentSlot: "not-a-slot")
        )
        await #expect(throws: (any Error).self) {
            _ = try await buildUptoPayload(signer: signer, requirements: req, expiresAt: 1000)
        }
    }
}

// MARK: - Build behaviour tests

@Suite("x402 upto build behaviour")
struct X402UptoBuildTests {
    @Test
    func depositEqualsMaxAmountAndAuthorizedSignerIsOperator() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 4_102_444_800, salt: 42
        )
        #expect(payload.maxAmount == UptoFixture.amount)
        #expect(payload.deposit == UptoFixture.amount)
        #expect(payload.deposit == payload.maxAmount)
        #expect(payload.authorizedSigner == UptoFixture.operatorAddr)
        #expect(payload.from == signer.address)
        #expect(payload.expiresAt == 4_102_444_800)
        #expect(payload.openTransaction != nil)
    }

    @Test
    func validAfterDefaultsToZeroAndIsOverridden() async throws {
        let signer = try UptoFixture.signer()
        let defaultReq = UptoFixture.requirements()
        let defaultPayload = try await buildUptoPayload(
            signer: signer, requirements: defaultReq, expiresAt: 1000, salt: 1
        )
        #expect(defaultPayload.validAfter == 0)

        let withValidAfter = UptoFixture.requirements(
            extra: UptoFixture.extra(validAfter: 1_700_000_000)
        )
        let payload = try await buildUptoPayload(
            signer: signer, requirements: withValidAfter, expiresAt: 1000, salt: 1
        )
        #expect(payload.validAfter == 1_700_000_000)
    }

    @Test
    func channelIdEqualsFindChannelPda() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        let salt: UInt64 = 0xDEAD_BEEF_0000_0001
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: salt
        )
        let payer = try Pubkey(bytes: signer.publicKey)
        let op = try Pubkey(base58: UptoFixture.operatorAddr)
        let mint = try Pubkey(base58: UptoFixture.mint)
        let expected = try PaymentChannels.findChannelPda(
            payer: payer, payee: op, mint: mint, authorizedSigner: op,
            salt: salt, openSlot: UptoFixture.recentSlotValue, programId: PaymentChannels.programId
        )
        #expect(payload.channelId == expected.base58)
    }

    @Test
    func explicitOpenSlotOverridesExtraRecentSlot() async throws {
        // An explicit openSlot override wins over the server-prefetched
        // extra.recentSlot, and lands in both the PDA and the open data.
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        let salt: UInt64 = 11
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: salt, openSlot: 2222
        )
        let payer = try Pubkey(bytes: signer.publicKey)
        let op = try Pubkey(base58: UptoFixture.operatorAddr)
        let mint = try Pubkey(base58: UptoFixture.mint)
        let expected = try PaymentChannels.findChannelPda(
            payer: payer, payee: op, mint: mint, authorizedSigner: op,
            salt: salt, openSlot: 2222, programId: PaymentChannels.programId
        )
        #expect(payload.channelId == expected.base58)
        let decoded = try LegacyTxDecoder.decode(
            base64: try #require(payload.openTransaction), payer: payer
        )
        #expect(decoded.openSlot == 2222)
    }

    @Test
    func payToEqualsOperatorYieldsEmptyRecipients() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(payTo: UptoFixture.operatorAddr)
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: 99
        )
        let payer = try Pubkey(bytes: signer.publicKey)
        let decoded = try LegacyTxDecoder.decode(
            base64: try #require(payload.openTransaction), payer: payer
        )
        #expect(decoded.recipientBps.isEmpty)
        #expect(decoded.salt == 99)
        #expect(decoded.deposit == 1_000_000)
        #expect(decoded.gracePeriod == 900)
        // extra.recentSlot rides into openArgs as openSlot, after gracePeriod.
        #expect(decoded.openSlot == UptoFixture.recentSlotValue)
    }

    @Test
    func payToDifferentFromOperatorYieldsOneDistribution() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(
            extra: UptoFixture.extra(facilitatorFee: 250)
        )
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: 7
        )
        let payer = try Pubkey(bytes: signer.publicKey)
        let decoded = try LegacyTxDecoder.decode(
            base64: try #require(payload.openTransaction), payer: payer
        )
        #expect(decoded.recipientBps == [9_750]) // 10000 - 250
    }

    @Test
    func feeZeroYieldsFullBps() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: 7
        )
        let payer = try Pubkey(bytes: signer.publicKey)
        let decoded = try LegacyTxDecoder.decode(
            base64: try #require(payload.openTransaction), payer: payer
        )
        #expect(decoded.recipientBps == [10_000])
    }

    @Test
    func feeTenThousandYieldsZeroBpsDistribution() async throws {
        // A 100% facilitator fee leaves payTo with pay_to_bps = 10000 - 10000 = 0.
        // The spec requires encoding payTo as a recipient whenever payTo differs
        // from the operator, and the Rust/Go/Python clients emit the same 0-bps
        // entry, so the client keeps wire parity rather than eliding it.
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(
            extra: UptoFixture.extra(facilitatorFee: 10_000)
        )
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: 7
        )
        let payer = try Pubkey(bytes: signer.publicKey)
        let decoded = try LegacyTxDecoder.decode(
            base64: try #require(payload.openTransaction), payer: payer
        )
        #expect(decoded.recipientBps == [0])
    }

    @Test
    func openTransactionIsPayerSignedFeePayerUnsigned() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: 7
        )
        let payer = try Pubkey(bytes: signer.publicKey)
        let decoded = try LegacyTxDecoder.decode(
            base64: try #require(payload.openTransaction), payer: payer
        )
        // operator is the fee payer (account index 0) and is unsigned; the
        // payer slot carries the client's signature.
        #expect(decoded.signatureCount == 2)
        #expect(decoded.payerSlotSigned)
        #expect(decoded.feePayerSlotEmpty)
        #expect(decoded.payerIndex > 0)
    }

    @Test
    func explicitNonceIsPreserved() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, nonce: "fixed-nonce", salt: 7
        )
        #expect(payload.nonce == "fixed-nonce")
    }

    @Test
    func defaultNonceIsRandomHexAndIndependentOfSalt() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        // Same fixed salt, default (random) nonce on each call -> nonces differ.
        let a = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: 5
        )
        let b = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: 5
        )
        #expect(a.nonce != b.nonce)
        #expect(a.nonce.count == 32)
        #expect(a.nonce.allSatisfy { $0.isHexDigit })
        // Same channel for the same salt; the nonce is not the salt.
        #expect(a.channelId == b.channelId)

        // Different salts -> different channels, even with a pinned nonce.
        let c = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, nonce: "n", salt: 1
        )
        let d = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, nonce: "n", salt: 2
        )
        #expect(c.channelId != d.channelId)
    }

    @Test
    func defaultNonceUsesInjectedGenerator() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000,
            nonceGenerator: { Data(repeating: 0xAB, count: 16) }, salt: 1
        )
        #expect(payload.nonce == String(repeating: "ab", count: 16))
    }

    @Test
    func tokenProgramAndChannelProgramOverridesAreAccepted() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements(
            extra: UptoFixture.extra(
                tokenProgram: Pubkey.token2022Program.base58,
                channelProgram: PaymentChannels.programId.base58
            )
        )
        let payload = try await buildUptoPayload(
            signer: signer, requirements: req, expiresAt: 1000, salt: 3
        )
        #expect(payload.openTransaction != nil)
    }
}

// MARK: - Encoding / round-trip tests

@Suite("x402 upto encoding")
struct X402UptoEncodingTests {
    @Test
    func feeZeroOmittedFromExtraJSON() throws {
        let extra = UptoFixture.extra(facilitatorFee: 0)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let json = String(decoding: try encoder.encode(extra), as: UTF8.self)
        #expect(!json.contains("facilitatorFee"))
    }

    @Test
    func feeNonZeroPresentInExtraJSON() throws {
        let extra = UptoFixture.extra(facilitatorFee: 250)
        let json = String(decoding: try JSONEncoder().encode(extra), as: UTF8.self)
        #expect(json.contains("facilitatorFee"))
        #expect(json.contains("250"))
    }

    @Test
    func envelopeRoundTrips() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        let header = try await buildUptoHeader(
            signer: signer, requirements: req, expiresAt: 4_102_444_800, nonce: "n-1", salt: 7
        )
        let data = try #require(Data(base64Encoded: header))
        let envelope = try JSONDecoder().decode(X402UptoSignatureEnvelope.self, from: data)
        #expect(envelope.x402Version == X402Version)
        #expect(envelope.payload.maxAmount == UptoFixture.amount)
        #expect(envelope.payload.deposit == UptoFixture.amount)
        #expect(envelope.payload.nonce == "n-1")
        #expect(envelope.payload.authorizedSigner == UptoFixture.operatorAddr)

        guard case let .object(accepted) = envelope.accepted else {
            Issue.record("accepted is not a JSON object")
            return
        }
        #expect(accepted["scheme"] == .string(X402UptoScheme))
        #expect(accepted["network"] == .string(UptoFixture.network))
        // Payload carries no profile / signature fields.
        let payloadJSON = String(decoding: try JSONEncoder().encode(envelope.payload), as: UTF8.self)
        #expect(!payloadJSON.contains("\"signature\""))
        #expect(!payloadJSON.contains("\"profile\""))
    }

    @Test
    func headerIsStandardBase64WithPadding() async throws {
        let signer = try UptoFixture.signer()
        let req = UptoFixture.requirements()
        let header = try await buildUptoHeader(
            signer: signer, requirements: req, expiresAt: 1000, nonce: "n", salt: 7
        )
        // Standard base64 (not base64url): no '-' or '_' substitutions.
        #expect(!header.contains("-"))
        #expect(!header.contains("_"))
        #expect(Data(base64Encoded: header) != nil)
    }

    @Test
    func acceptedEchoesVerbatimWireExtras() throws {
        // A challenge object carrying a field the typed struct does not model
        // (e.g. `resource`) must survive into the echoed `accepted`.
        let envelopeJSON = """
        {
          "x402Version": 2,
          "accepts": [{
            "scheme": "upto",
            "network": "\(UptoFixture.network)",
            "amount": "\(UptoFixture.amount)",
            "asset": "\(UptoFixture.mint)",
            "payTo": "\(UptoFixture.payTo)",
            "maxTimeoutSeconds": 300,
            "resource": "https://example.com/x",
            "extra": {
              "assetTransferMethod": "payment-channel",
              "facilitatorAddress": "\(UptoFixture.operatorAddr)",
              "recentBlockhash": "\(UptoFixture.blockhash)"
            }
          }]
        }
        """
        let header = [(name: "PAYMENT-REQUIRED", value: Data(envelopeJSON.utf8).base64EncodedString())]
        let req = try #require(parseUptoChallenge(headers: header, body: nil))
        let accepted = try req.acceptedValue()
        guard case let .object(obj) = accepted else {
            Issue.record("accepted not an object"); return
        }
        #expect(obj["resource"] == .string("https://example.com/x"))
    }
}

// MARK: - Challenge parsing tests

@Suite("x402 upto challenge parsing")
struct X402UptoParseTests {
    private func encodedEnvelope(extraEntries: String = "") -> String {
        let json = """
        {
          "x402Version": 2,
          "accepts": [
            {
              "scheme": "exact",
              "network": "\(UptoFixture.network)",
              "amount": "5",
              "asset": "\(UptoFixture.mint)",
              "payTo": "\(UptoFixture.payTo)",
              "extra": {}
            },
            {
              "scheme": "upto",
              "network": "\(UptoFixture.network)",
              "amount": "\(UptoFixture.amount)",
              "asset": "\(UptoFixture.mint)",
              "payTo": "\(UptoFixture.payTo)",
              "maxTimeoutSeconds": 300,
              "extra": {
                "assetTransferMethod": "payment-channel",
                "facilitatorAddress": "\(UptoFixture.operatorAddr)",
                "recentBlockhash": "\(UptoFixture.blockhash)"
              }
            }\(extraEntries)
          ]
        }
        """
        return Data(json.utf8).base64EncodedString()
    }

    @Test
    func parsesPaymentRequiredHeaderCaseInsensitive() throws {
        let headers = [(name: "payment-required", value: encodedEnvelope())]
        let req = try #require(parseUptoChallenge(headers: headers, body: nil))
        #expect(req.scheme == X402UptoScheme)
        #expect(req.amount == UptoFixture.amount)
        #expect(req.extra.facilitatorAddress == UptoFixture.operatorAddr)
    }

    @Test
    func parsesBodyFallback() throws {
        let json = String(decoding: try #require(Data(base64Encoded: encodedEnvelope())), as: UTF8.self)
        let req = try #require(parseUptoChallenge(headers: [], body: json))
        #expect(req.scheme == X402UptoScheme)
    }

    @Test
    func parseUptoAcceptsSkipsNonUptoEntries() throws {
        let extra = """
        ,
        {
          "scheme": "upto",
          "network": "\(UptoFixture.network)",
          "amount": "2000000",
          "asset": "\(UptoFixture.mint)",
          "payTo": "\(UptoFixture.payTo)",
          "maxTimeoutSeconds": 60,
          "extra": {
            "assetTransferMethod": "payment-channel",
            "facilitatorAddress": "\(UptoFixture.operatorAddr)",
            "recentBlockhash": "\(UptoFixture.blockhash)"
          }
        }
        """
        let headers = [(name: "PAYMENT-REQUIRED", value: encodedEnvelope(extraEntries: extra))]
        let all = parseUptoAccepts(headers: headers, body: nil)
        #expect(all.count == 2) // the exact entry is skipped
        #expect(all.allSatisfy { $0.scheme == X402UptoScheme })
    }

    @Test
    func returnsNilWithoutUptoOffer() {
        #expect(parseUptoChallenge(headers: [], body: nil) == nil)
        #expect(parseUptoAccepts(headers: [], body: nil).isEmpty)
    }

    @Test
    func returnsNilForMalformedHeader() {
        let headers = [(name: "PAYMENT-REQUIRED", value: "not-base64!!!")]
        #expect(parseUptoChallenge(headers: headers, body: nil) == nil)
    }
}

// MARK: - Wire type coverage tests

@Suite("x402 upto wire types")
struct X402UptoTypeTests {
    @Test
    func settlementResponseOmitsNilFields() throws {
        let resp = X402UptoSettlementResponse(
            success: true, transaction: "sig", network: UptoFixture.network, amount: "500000"
        )
        let json = String(decoding: try JSONEncoder().encode(resp), as: UTF8.self)
        #expect(!json.contains("errorReason"))
        #expect(!json.contains("payer"))
        #expect(json.contains("500000"))
    }

    @Test
    func settlementResponseRoundTrips() throws {
        let json = """
        {"success":false,"errorReason":"boom","payer":"P","transaction":"sig","network":"\(UptoFixture.network)","amount":"0"}
        """
        let resp = try JSONDecoder().decode(X402UptoSettlementResponse.self, from: Data(json.utf8))
        #expect(resp.success == false)
        #expect(resp.errorReason == "boom")
        #expect(resp.payer == "P")
        #expect(resp.amount == "0")
    }

    @Test
    func payloadDecodeRoundTripAndOmitsOpenTransactionWhenNil() throws {
        let payload = X402UptoPayload(
            from: "P", maxAmount: "10", expiresAt: 5, validAfter: 0, nonce: "n",
            channelId: "C", deposit: "10", authorizedSigner: "Op", openTransaction: nil
        )
        let data = try JSONEncoder().encode(payload)
        let json = String(decoding: data, as: UTF8.self)
        #expect(!json.contains("openTransaction"))
        let decoded = try JSONDecoder().decode(X402UptoPayload.self, from: data)
        #expect(decoded == payload)
    }

    @Test
    func extraDecodesLastValidBlockHeightAndDefaultsFee() throws {
        let json = """
        {"assetTransferMethod":"payment-channel","facilitatorAddress":"\(UptoFixture.operatorAddr)","lastValidBlockHeight":"123","recentBlockhash":"\(UptoFixture.blockhash)"}
        """
        let extra = try JSONDecoder().decode(X402UptoExtra.self, from: Data(json.utf8))
        #expect(extra.lastValidBlockHeight == "123")
        #expect(extra.facilitatorFee == 0)
        let reencoded = String(decoding: try JSONEncoder().encode(extra), as: UTF8.self)
        #expect(reencoded.contains("lastValidBlockHeight"))
    }

    @Test
    func requirementsSchemeDefaultsToUptoWhenOmitted() throws {
        let json = """
        {"network":"\(UptoFixture.network)","amount":"1","asset":"\(UptoFixture.mint)","payTo":"\(UptoFixture.payTo)","maxTimeoutSeconds":300,"extra":{"assetTransferMethod":"payment-channel","facilitatorAddress":"\(UptoFixture.operatorAddr)","recentBlockhash":"\(UptoFixture.blockhash)"}}
        """
        let req = try JSONDecoder().decode(X402UptoRequirements.self, from: Data(json.utf8))
        #expect(req.scheme == X402UptoScheme)
    }

    @Test
    func maxAmountThrowsOnInvalidAmount() {
        let req = UptoFixture.requirements(amount: "not-a-number")
        #expect(throws: (any Error).self) { _ = try req.maxAmount() }
    }

    @Test
    func acceptedValueUsesTypedEncodingForInCodeEntry() throws {
        // No `raw` captured (built in code) -> typed encode path.
        let req = UptoFixture.requirements()
        let accepted = try req.acceptedValue()
        guard case let .object(obj) = accepted else {
            Issue.record("accepted not an object"); return
        }
        #expect(obj["scheme"] == .string(X402UptoScheme))
        #expect(obj["network"] == .string(UptoFixture.network))
        // facilitatorFee == 0 is omitted from the typed extra encoding.
        guard case let .object(extra)? = obj["extra"] else {
            Issue.record("extra not an object"); return
        }
        #expect(extra["facilitatorFee"] == nil)
    }

    @Test
    func envelopeDecodesErrorField() throws {
        let json = """
        {"x402Version":2,"accepts":[],"error":"payment required"}
        """
        let env = try JSONDecoder().decode(X402UptoRequiredEnvelope.self, from: Data(json.utf8))
        #expect(env.error == "payment required")
        #expect(env.accepts.isEmpty)
    }
}

// MARK: - Transport tests

/// Canned response for `X402UptoStubURLProtocol`. Kept separate from the exact
/// suite's stub so the two transport suites never race on shared static state.
struct X402UptoStubResponse {
    let statusCode: Int
    let headers: [String: String]
    let body: Data
}

final class X402UptoStubURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var responder: ((URLRequest) -> X402UptoStubResponse)?
    nonisolated(unsafe) static var requestCount = 0
    nonisolated(unsafe) static var capturedRequests: [URLRequest] = []

    static func reset() {
        responder = nil
        requestCount = 0
        capturedRequests = []
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requestCount += 1
        Self.capturedRequests.append(request)
        guard let responder = Self.responder else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "stub", code: 0))
            return
        }
        let stub = responder(request)
        let response = HTTPURLResponse(
            url: request.url!, statusCode: stub.statusCode,
            httpVersion: "HTTP/1.1", headerFields: stub.headers
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: stub.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@Suite("PayKit.HttpClient x402 upto transport", .serialized)
struct X402UptoTransportTests {
    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [X402UptoStubURLProtocol.self]
        return URLSession(configuration: config)
    }

    static func challengeBody() -> Data {
        let json = """
        {
          "x402Version": 2,
          "accepts": [{
            "scheme": "upto",
            "network": "\(UptoFixture.network)",
            "amount": "\(UptoFixture.amount)",
            "asset": "\(UptoFixture.mint)",
            "payTo": "\(UptoFixture.payTo)",
            "maxTimeoutSeconds": 300,
            "extra": {
              "assetTransferMethod": "payment-channel",
              "facilitatorAddress": "\(UptoFixture.operatorAddr)",
              "recentBlockhash": "\(UptoFixture.blockhash)",
              "recentSlot": "\(UptoFixture.recentSlot)"
            }
          }]
        }
        """
        return Data(json.utf8)
    }

    @Test
    func retryCarriesPaymentSignatureOn402() async throws {
        X402UptoStubURLProtocol.reset()
        X402UptoStubURLProtocol.responder = { req in
            if let psig = req.value(forHTTPHeaderField: "Payment-Signature"), !psig.isEmpty {
                return X402UptoStubResponse(
                    statusCode: 200,
                    headers: ["x-payment-settlement-signature": "SETTLED_UPTO"],
                    body: Data(#"{"ok":true}"#.utf8)
                )
            }
            return X402UptoStubResponse(
                statusCode: 402,
                headers: ["Content-Type": "application/json"],
                body: Self.challengeBody()
            )
        }

        let signer = try UptoFixture.signer()
        let client = PayKit.HttpClient.x402Upto(signer: signer, urlSession: Self.makeSession())
        let response = try await client.request(URL(string: "https://example.test/metered")!).response()

        #expect(response.status == 200)
        #expect(X402UptoStubURLProtocol.requestCount == 2)
        #expect(response.settlementSignature == "SETTLED_UPTO")
        #expect(response.paymentSent != nil)

        let retry = X402UptoStubURLProtocol.capturedRequests.last
        let sent = try #require(retry?.value(forHTTPHeaderField: "Payment-Signature"))
        // What was replayed is a decodable upto envelope.
        let envData = try #require(Data(base64Encoded: sent))
        let env = try JSONDecoder().decode(X402UptoSignatureEnvelope.self, from: envData)
        #expect(env.payload.deposit == UptoFixture.amount)
    }

    @Test
    func expiresAtDerivesFromNowPlusMaxTimeout() async throws {
        let signer = try UptoFixture.signer()
        let fixedNow = Date(timeIntervalSince1970: 1_000_000)
        let interceptor = X402.UptoInterceptor(signer: signer, now: { fixedNow })
        let url = URL(string: "https://example.test/metered")!
        let http = HTTPURLResponse(
            url: url, statusCode: 402, httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        let result = try await interceptor.retry(
            URLRequest(url: url), for: http, body: Self.challengeBody()
        )
        guard case let .retry(_, paymentSent) = result else {
            Issue.record("expected retry"); return
        }
        let envData = try #require(Data(base64Encoded: paymentSent))
        let env = try JSONDecoder().decode(X402UptoSignatureEnvelope.self, from: envData)
        #expect(env.payload.expiresAt == 1_000_000 + 300)
    }

    @Test
    func nonUptoChallengeThrows() async throws {
        let signer = try UptoFixture.signer()
        let interceptor = X402.UptoInterceptor(signer: signer)
        let url = URL(string: "https://example.test/metered")!
        let http = HTTPURLResponse(
            url: url, statusCode: 402, httpVersion: "HTTP/1.1", headerFields: [:]
        )!
        await #expect(throws: (any Error).self) {
            _ = try await interceptor.retry(
                URLRequest(url: url), for: http, body: Data(#"{"accepts":[]}"#.utf8)
            )
        }
    }
}

// A hostile 402 endpoint controls maxTimeoutSeconds; the expiry math must
// reject out-of-range values instead of trapping on Int overflow.
@Test
func uptoExpiresAtRejectsOutOfRangeTimeouts() throws {
    #expect(throws: (any Error).self) {
        _ = try uptoExpiresAt(nowSeconds: 1_000_000, maxTimeoutSeconds: Int.max)
    }
    #expect(throws: (any Error).self) {
        _ = try uptoExpiresAt(nowSeconds: 1_000_000, maxTimeoutSeconds: -1)
    }
    #expect(try uptoExpiresAt(nowSeconds: 1_000_000, maxTimeoutSeconds: 300) == 1_000_300)
    #expect(
        try uptoExpiresAt(nowSeconds: 1_000_000, maxTimeoutSeconds: uptoMaxTimeoutCeilingSeconds)
            == 1_000_000 + uptoMaxTimeoutCeilingSeconds
    )
}
