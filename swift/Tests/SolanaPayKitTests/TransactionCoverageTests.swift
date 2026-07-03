import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - ShortVec decode + Transaction error-path coverage

@Suite("ShortVec decodeLength")
struct ShortVecDecodeTests {
    /// Round-trip every boundary through encode then decode so the production
    /// `ShortVec.decodeLength` (never hit by the golden-vector tests, which use
    /// a test-local decoder) is exercised on all 1/2/3-byte encodings.
    @Test
    func decodesAllBoundaries() throws {
        for value in [0, 1, 127, 128, 16383, 16384, 65535] {
            let encoded = ShortVec.encodeLength(value)
            var offset = 0
            let decoded = try ShortVec.decodeLength(encoded, at: &offset)
            #expect(decoded == value, "value \(value)")
            // Offset advanced past the whole encoding.
            #expect(offset == encoded.count, "offset for \(value)")
        }
    }

    /// Decoding from a non-zero start index (Data with a non-zero startIndex,
    /// simulated with a slice) still resolves relative to startIndex.
    @Test
    func decodesFromSlicedData() throws {
        // Prepend a byte, slice it off; startIndex is now 1.
        var buffer = Data([0xFF])
        buffer.append(ShortVec.encodeLength(300))
        let slice = buffer.dropFirst() // startIndex == 1
        var offset = 0
        let decoded = try ShortVec.decodeLength(slice, at: &offset)
        #expect(decoded == 300)
    }

    /// A truncated buffer (length prefix cut short) throws `invalidTransaction`.
    @Test
    func throwsOnTruncatedLength() {
        // 0x80 says "more bytes follow", but the buffer ends.
        let truncated = Data([0x80])
        var offset = 0
        #expect(throws: MppError.self) {
            _ = try ShortVec.decodeLength(truncated, at: &offset)
        }
    }

    /// A length that never terminates within 3 bytes throws.
    @Test
    func throwsWhenExceedsThreeBytes() {
        // Three continuation bytes, all with the high bit set.
        let overlong = Data([0x80, 0x80, 0x80, 0x01])
        var offset = 0
        #expect(throws: MppError.self) {
            _ = try ShortVec.decodeLength(overlong, at: &offset)
        }
    }
}

@Suite("TransactionMessage error paths")
struct TransactionMessageErrorTests {
    static func pubkeyOf(_ byte: UInt8) -> Pubkey {
        var bytes = Data(repeating: 0, count: 32)
        bytes[31] = byte
        return try! Pubkey(bytes: bytes)
    }

    /// A blockhash that is not 32 bytes must be rejected at construction.
    @Test
    func rejectsNon32ByteBlockhash() {
        let header = TransactionMessage.MessageHeader(
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0
        )
        #expect(throws: MppError.self) {
            _ = try TransactionMessage(
                version: .legacy, header: header,
                accountKeys: [Self.pubkeyOf(1)],
                recentBlockhash: Data(repeating: 9, count: 31), // wrong length
                instructions: []
            )
        }
    }

    /// A legacy message with no instructions still serializes (exercises the
    /// legacy branch and the empty-instruction loop).
    @Test
    func serializesLegacyMessageWithNoInstructions() throws {
        let header = TransactionMessage.MessageHeader(
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0
        )
        let message = try TransactionMessage(
            version: .legacy, header: header,
            accountKeys: [Self.pubkeyOf(1)],
            recentBlockhash: Data(repeating: 9, count: 32),
            instructions: []
        )
        let bytes = message.serialize()
        // Legacy: no 0x80 prefix; first byte is numRequiredSignatures.
        #expect(bytes.first == 1)
    }
}

@Suite("SignedTransaction validation")
struct SignedTransactionValidationTests {
    static func pubkeyOf(_ byte: UInt8) -> Pubkey {
        var bytes = Data(repeating: 0, count: 32)
        bytes[31] = byte
        return try! Pubkey(bytes: bytes)
    }

    /// A signature that is not 64 bytes is rejected.
    @Test
    func rejectsNon64ByteSignature() throws {
        let header = TransactionMessage.MessageHeader(
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0
        )
        let message = try TransactionMessage(
            version: .v0, header: header,
            accountKeys: [Self.pubkeyOf(1)],
            recentBlockhash: Data(repeating: 9, count: 32),
            instructions: []
        )
        #expect(throws: MppError.self) {
            _ = try SignedTransaction(
                signatures: [Data(repeating: 0xAB, count: 63)], // wrong length
                message: message
            )
        }
    }

    @Test
    func emptySignatureSlotsAreZeroFilled() {
        let slots = SignedTransaction.emptySignatureSlots(count: 3)
        #expect(slots.count == 3)
        for slot in slots {
            #expect(slot == Data(repeating: 0, count: 64))
        }
    }
}

@Suite("TransactionBuilder account-cap guards")
struct TransactionBuilderCapTests {
    /// Building a transaction whose distinct account count exceeds the u8 wire
    /// limit (255) must throw rather than silently truncating indices.
    @Test
    func rejectsMoreThan255Accounts() {
        // Fee payer + one program id + 300 distinct readonly non-signer
        // accounts = 302 keys, over the 255 cap.
        func keyOf(_ i: Int) -> Pubkey {
            var bytes = Data(repeating: 0, count: 32)
            bytes[30] = UInt8(i >> 8)
            bytes[31] = UInt8(i & 0xFF)
            return try! Pubkey(bytes: bytes)
        }
        let feePayer = keyOf(1)
        let program = keyOf(2)
        let accounts = (10..<320).map { AccountMeta.readonly(keyOf($0)) }
        let ix = SolanaInstruction(programId: program, accounts: accounts, data: Data())

        #expect(throws: MppError.self) {
            _ = try TransactionBuilder.compile(
                version: .v0, feePayer: feePayer,
                instructions: [ix],
                recentBlockhash: Data(repeating: 9, count: 32)
            )
        }
    }
}
