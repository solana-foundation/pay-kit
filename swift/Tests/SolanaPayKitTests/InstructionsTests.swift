import Foundation
import Testing
@testable import SolanaPayKit

@Suite("Instruction builders")
struct InstructionsTests {
    @Test
    func systemTransferEncodesDiscriminator2AndLamports() {
        let source = TransactionTests.pubkeyOf(1)
        let destination = TransactionTests.pubkeyOf(2)
        let ix = Instructions.systemTransfer(from: source, to: destination, lamports: 1_000_000)

        #expect(ix.programId == .systemProgram)
        #expect(ix.accounts.count == 2)
        #expect(ix.accounts[0].isSigner && ix.accounts[0].isWritable)
        #expect(!ix.accounts[1].isSigner && ix.accounts[1].isWritable)

        // First 4 bytes are u32 = 2.
        let discriminator = ix.data.prefix(4)
        #expect(discriminator == Data([0x02, 0x00, 0x00, 0x00]))
        // Next 8 bytes are u64 = 1_000_000.
        let lamports = ix.data.suffix(8)
        var expected = Data()
        expected.append(contentsOf: withUnsafeBytes(of: UInt64(1_000_000).littleEndian, Array.init))
        #expect(lamports == expected)
    }

    @Test
    func splTransferCheckedMatchesWireDiscriminator() {
        let source = TransactionTests.pubkeyOf(20)
        let mint = TransactionTests.pubkeyOf(10)
        let destination = TransactionTests.pubkeyOf(30)
        let authority = TransactionTests.pubkeyOf(1)
        let ix = Instructions.splTransferChecked(
            programId: .tokenProgram,
            source: source,
            mint: mint,
            destination: destination,
            authority: authority,
            amount: 500,
            decimals: 6
        )

        #expect(ix.programId == .tokenProgram)
        #expect(ix.data.count == 1 + 8 + 1)
        #expect(ix.data[0] == 12)
        // amount little-endian
        let amountBytes = ix.data.subdata(in: 1..<9)
        var expectedAmount = Data()
        expectedAmount.append(contentsOf: withUnsafeBytes(of: UInt64(500).littleEndian, Array.init))
        #expect(amountBytes == expectedAmount)
        #expect(ix.data.last == 6)

        #expect(ix.accounts.count == 4)
        #expect(ix.accounts[0].pubkey == source && ix.accounts[0].isWritable && !ix.accounts[0].isSigner)
        #expect(ix.accounts[1].pubkey == mint && !ix.accounts[1].isWritable)
        #expect(ix.accounts[2].pubkey == destination && ix.accounts[2].isWritable)
        #expect(ix.accounts[3].pubkey == authority && ix.accounts[3].isSigner && !ix.accounts[3].isWritable)
    }

    @Test
    func ataCreateAndCreateIdempotentDifferOnlyInDiscriminator() {
        let payer = TransactionTests.pubkeyOf(1)
        let ata = TransactionTests.pubkeyOf(40)
        let owner = TransactionTests.pubkeyOf(2)
        let mint = TransactionTests.pubkeyOf(10)
        let plain = Instructions.createAssociatedTokenAccount(
            payer: payer,
            ata: ata,
            owner: owner,
            mint: mint,
            tokenProgram: .tokenProgram,
            idempotent: false
        )
        let idem = Instructions.createAssociatedTokenAccount(
            payer: payer,
            ata: ata,
            owner: owner,
            mint: mint,
            tokenProgram: .tokenProgram,
            idempotent: true
        )

        #expect(plain.data == Data([0]))
        #expect(idem.data == Data([1]))
        #expect(plain.accounts.map { $0.pubkey } == idem.accounts.map { $0.pubkey })
        #expect(plain.programId == .associatedTokenProgram)
        #expect(idem.accounts.count == 6)
        #expect(idem.accounts[4].pubkey == .systemProgram)
        #expect(idem.accounts[5].pubkey == .tokenProgram)
    }

    @Test
    func computeBudgetSetLimitDiscriminator2WithU32Units() {
        let ix = Instructions.computeBudgetSetUnitLimit(units: 200_000)
        #expect(ix.programId == .computeBudgetProgram)
        #expect(ix.accounts.isEmpty)
        #expect(ix.data.count == 1 + 4)
        #expect(ix.data[0] == 2)
        let units = ix.data.subdata(in: 1..<5)
        var expected = Data()
        expected.append(contentsOf: withUnsafeBytes(of: UInt32(200_000).littleEndian, Array.init))
        #expect(units == expected)
    }

    @Test
    func computeBudgetSetPriceDiscriminator3WithU64MicroLamports() {
        let ix = Instructions.computeBudgetSetUnitPrice(microLamports: 1)
        #expect(ix.data.count == 1 + 8)
        #expect(ix.data[0] == 3)
        let lamports = ix.data.subdata(in: 1..<9)
        var expected = Data()
        expected.append(contentsOf: withUnsafeBytes(of: UInt64(1).littleEndian, Array.init))
        #expect(lamports == expected)
    }

    @Test
    func memoEncodesUtf8AndBoundsCheck() throws {
        let ix = try Instructions.memo("hello world")
        #expect(ix.programId == .memoProgram)
        #expect(ix.accounts.isEmpty)
        #expect(ix.data == Data("hello world".utf8))

        let big = String(repeating: "x", count: 567)
        #expect(throws: MppError.invalidTransaction("memo exceeds 566 bytes")) {
            _ = try Instructions.memo(big)
        }
    }
}
