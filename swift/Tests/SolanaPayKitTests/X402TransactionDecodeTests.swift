import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - Minimal v0 transaction decoder (test-only)

/// A decoded Solana v0 transaction: signatures, account keys, blockhash, and
/// compiled instructions. Just enough of the wire format to assert the x402
/// payment builder produces the verifier-expected instruction set.
struct DecodedTx {
    struct Ix {
        let programIdIndex: Int
        let accountIndices: [Int]
        let data: Data
    }
    let signatures: [Data]
    let numRequiredSignatures: Int
    let accountKeys: [Pubkey]
    let blockhash: Data
    let instructions: [Ix]

    var programIds: [Pubkey] { instructions.map { accountKeys[$0.programIdIndex] } }
}

enum TxDecoder {
    static func decodeShortVec(_ data: Data, _ offset: inout Int) -> Int {
        var value = 0
        var shift = 0
        while true {
            let byte = data[data.startIndex + offset]
            offset += 1
            value |= Int(byte & 0x7F) << shift
            if (byte & 0x80) == 0 { return value }
            shift += 7
        }
    }

    static func decode(base64: String) throws -> DecodedTx {
        guard let data = Data(base64Encoded: base64) else {
            throw MppError.invalidTransaction("not base64")
        }
        var off = 0
        let sigCount = decodeShortVec(data, &off)
        var sigs: [Data] = []
        for _ in 0..<sigCount {
            sigs.append(data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + 64)))
            off += 64
        }
        // v0 prefix
        let prefix = data[data.startIndex + off]
        #expect(prefix == 0x80, "expected v0 message prefix")
        off += 1
        let numRequired = Int(data[data.startIndex + off]); off += 1
        _ = data[data.startIndex + off]; off += 1 // readonly signed
        _ = data[data.startIndex + off]; off += 1 // readonly unsigned

        let keyCount = decodeShortVec(data, &off)
        var keys: [Pubkey] = []
        for _ in 0..<keyCount {
            let raw = data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + 32))
            keys.append(try Pubkey(bytes: raw))
            off += 32
        }
        let blockhash = data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + 32))
        off += 32

        let ixCount = decodeShortVec(data, &off)
        var ixs: [DecodedTx.Ix] = []
        for _ in 0..<ixCount {
            let progIdx = Int(data[data.startIndex + off]); off += 1
            let acctCount = decodeShortVec(data, &off)
            var accts: [Int] = []
            for _ in 0..<acctCount {
                accts.append(Int(data[data.startIndex + off])); off += 1
            }
            let dataLen = decodeShortVec(data, &off)
            let ixData = data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + dataLen))
            off += dataLen
            ixs.append(DecodedTx.Ix(programIdIndex: progIdx, accountIndices: accts, data: ixData))
        }
        return DecodedTx(
            signatures: sigs,
            numRequiredSignatures: numRequired,
            accountKeys: keys,
            blockhash: blockhash,
            instructions: ixs
        )
    }
}

private func u32le(_ value: UInt32) -> [UInt8] {
    withUnsafeBytes(of: value.littleEndian, Array.init)
}

private func u64le(_ value: UInt64) -> [UInt8] {
    withUnsafeBytes(of: value.littleEndian, Array.init)
}

// MARK: - Shared fixtures

private enum Fixture {
    static let blockhash = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
    static let payTo = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"

    /// A fixed deterministic 16-byte nonce for tests. Hex-encoded it becomes
    /// the 32-char string "deadbeefcafebabe0102030405060708".
    static let fixedNonce = Data([
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ])
    static let fixedNonceHex = "deadbeefcafebabe0102030405060708"

    /// Nonce generator closure that returns the fixed nonce above.
    static func fixedNonceGenerator() -> (() -> Data) { { fixedNonce } }

    static func signer() throws -> MemorySigner {
        try MemorySigner(secretKey: Data(repeating: 0x01, count: 32))
    }

    static func rpc() -> RpcClient {
        RpcClient(endpoint: URL(string: "http://localhost:8899")!)
    }

    static func decodePayload(_ header: String) throws -> DecodedTx {
        let envData = Data(base64Encoded: header)!
        let env = try JSONDecoder().decode(X402PaymentSignatureEnvelope.self, from: envData)
        return try TxDecoder.decode(base64: env.payload.transaction)
    }
}

// MARK: - SPL decode + verifier parity

@Suite("x402 SPL transaction decode + verifier parity")
struct X402SplDecodeTests {
    static func splOffer(memo: String? = nil) -> X402AcceptsEntry {
        var extra: [String: JSONValue] = [
            "recentBlockhash": .string(Fixture.blockhash),
            "tokenProgram": .string(Mints.tokenProgram),
            "decimals": .int(6),
        ]
        if let memo { extra["memo"] = .string(memo) }
        return X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "20000",
            maxAmountRequired: nil,
            asset: Mints.usdcDevnet,
            payTo: Fixture.payTo,
            recipient: nil,
            extra: extra
        )
    }

    @Test
    func splThreeInstructionsMatchVerifierShape() async throws {
        let header = try await buildX402PaymentHeader(
            signer: try Fixture.signer(), rpc: Fixture.rpc(), offer: Self.splOffer(),
            nonceGenerator: Fixture.fixedNonceGenerator()
        )
        let tx = try Fixture.decodePayload(header)

        // No memo on this offer -> exactly 4 instructions (3 core + nonce memo).
        #expect(tx.instructions.count == 4)

        // ix0: ComputeBudget SetUnitLimit = [2] + u32le(20000), len 5.
        let ix0 = tx.instructions[0]
        #expect(Array(ix0.data) == [2] + u32le(20_000))
        #expect(ix0.data.count == 5)
        #expect(tx.accountKeys[ix0.programIdIndex] == Pubkey.computeBudgetProgram)

        // ix1: ComputeBudget SetUnitPrice = [3] + u64le(1), len 9.
        let ix1 = tx.instructions[1]
        #expect(Array(ix1.data) == [3] + u64le(1))
        #expect(ix1.data.count == 9)
        #expect(tx.accountKeys[ix1.programIdIndex] == Pubkey.computeBudgetProgram)

        // ix2: SPL transferChecked = [12] + u64le(20000) + [6 decimals], len 10.
        let ix2 = tx.instructions[2]
        #expect(Array(ix2.data) == [12] + u64le(20_000) + [6])
        #expect(ix2.data.count == 10)
        #expect(tx.accountKeys[ix2.programIdIndex] == Pubkey.tokenProgram)

        // transferChecked accounts: [sourceAta, mint, destAta, signer].
        let signerPk = try Pubkey(bytes: try Fixture.signer().publicKey)
        let recipientPk = try Pubkey(base58: Fixture.payTo)
        let mintPk = try Pubkey(base58: Mints.usdcDevnet)
        let expectedSourceAta = try AssociatedTokenAccount.address(
            owner: signerPk, mint: mintPk, tokenProgram: .tokenProgram
        )
        let expectedDestAta = try AssociatedTokenAccount.address(
            owner: recipientPk, mint: mintPk, tokenProgram: .tokenProgram
        )

        #expect(ix2.accountIndices.count == 4)
        let sourceAta = tx.accountKeys[ix2.accountIndices[0]]
        let mint = tx.accountKeys[ix2.accountIndices[1]]
        let destAta = tx.accountKeys[ix2.accountIndices[2]]
        let authority = tx.accountKeys[ix2.accountIndices[3]]

        #expect(sourceAta == expectedSourceAta)
        #expect(mint == mintPk)
        #expect(destAta == expectedDestAta)
        #expect(authority == signerPk)
    }

    @Test
    func memoAppendedAsFourthInstructionWhenPresent() async throws {
        let header = try await buildX402PaymentHeader(
            signer: try Fixture.signer(), rpc: Fixture.rpc(),
            offer: Self.splOffer(memo: "order_42")
        )
        let tx = try Fixture.decodePayload(header)
        #expect(tx.instructions.count == 4)
        let memoIx = tx.instructions[3]
        #expect(tx.accountKeys[memoIx.programIdIndex] == Pubkey.memoProgram)
        #expect(String(decoding: memoIx.data, as: UTF8.self) == "order_42")
    }

    /// Verifies that when no `extra.memo` is provided, a random nonce memo is
    /// still appended (making the transaction unique). The nonce generator is
    /// injected so the output is deterministic in this test.
    @Test
    func nonceMemoAppendedWhenNoExplicitMemo() async throws {
        let header = try await buildX402PaymentHeader(
            signer: try Fixture.signer(), rpc: Fixture.rpc(), offer: Self.splOffer(),
            nonceGenerator: Fixture.fixedNonceGenerator()
        )
        let tx = try Fixture.decodePayload(header)
        // Always 4 instructions: 2 compute-budget + 1 transfer + 1 nonce memo.
        #expect(tx.instructions.count == 4)
        let memoIx = tx.instructions[3]
        #expect(tx.accountKeys[memoIx.programIdIndex] == Pubkey.memoProgram)
        // Nonce is 32-char hex of the 16 fixed bytes.
        #expect(String(decoding: memoIx.data, as: UTF8.self) == Fixture.fixedNonceHex)
    }

    @Test
    func token2022CurrencyDerivesToken2022Ata() async throws {
        // USDG omits extra.tokenProgram -> builder must default Token-2022.
        let offer = X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "20000",
            maxAmountRequired: nil,
            asset: Mints.usdgDevnet,
            payTo: Fixture.payTo,
            recipient: nil,
            extra: ["recentBlockhash": .string(Fixture.blockhash), "decimals": .int(6)]
        )
        let header = try await buildX402PaymentHeader(
            signer: try Fixture.signer(), rpc: Fixture.rpc(), offer: offer,
            nonceGenerator: Fixture.fixedNonceGenerator()
        )
        let tx = try Fixture.decodePayload(header)
        let transferIx = tx.instructions[2]
        #expect(tx.accountKeys[transferIx.programIdIndex] == Pubkey.token2022Program)

        let recipientPk = try Pubkey(base58: Fixture.payTo)
        let mintPk = try Pubkey(base58: Mints.usdgDevnet)
        let expectedDestAta = try AssociatedTokenAccount.address(
            owner: recipientPk, mint: mintPk, tokenProgram: .token2022Program
        )
        #expect(tx.accountKeys[transferIx.accountIndices[2]] == expectedDestAta)
    }
}

// MARK: - SOL decode

@Suite("x402 SOL transaction decode")
struct X402SolDecodeTests {
    static func solOffer() -> X402AcceptsEntry {
        X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "5000",
            maxAmountRequired: nil,
            asset: "SOL",
            payTo: Fixture.payTo,
            recipient: nil,
            extra: ["recentBlockhash": .string(Fixture.blockhash)]
        )
    }

    @Test
    func solTransferShape() async throws {
        let header = try await buildX402PaymentHeader(
            signer: try Fixture.signer(), rpc: Fixture.rpc(), offer: Self.solOffer(),
            nonceGenerator: Fixture.fixedNonceGenerator()
        )
        let tx = try Fixture.decodePayload(header)

        // Always 4: 2 compute-budget + 1 system transfer + 1 nonce memo.
        #expect(tx.instructions.count == 4)

        let transfer = tx.instructions[2]
        #expect(tx.accountKeys[transfer.programIdIndex] == Pubkey.systemProgram)
        // SystemProgram::Transfer = u32le(2) + u64le(amount), len 12.
        #expect(Array(transfer.data) == u32le(2) + u64le(5000))
        #expect(transfer.data.count == 12)

        // Accounts: [from (signer), to].
        let signerPk = try Pubkey(bytes: try Fixture.signer().publicKey)
        let recipientPk = try Pubkey(base58: Fixture.payTo)
        #expect(tx.accountKeys[transfer.accountIndices[0]] == signerPk)
        #expect(tx.accountKeys[transfer.accountIndices[1]] == recipientPk)

        // Blockhash carried through verbatim.
        #expect(tx.blockhash == (try Base58.decode(Fixture.blockhash)))
    }
}

// MARK: - Fee-payer index

@Suite("x402 fee-payer indexing")
struct X402FeePayerTests {
    @Test
    func explicitFeePayerOccupiesAccountIndexZeroWithSignatureInSignerSlot() async throws {
        // Distinct fee payer (not the signer): the compiled message must put
        // the fee payer at account index 0, and the signer's signature must
        // land in the signer's slot, not slot 0.
        let feePayer = "11111111111111111111111111111112" // != signer, != recipient
        let offer = X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "5000",
            maxAmountRequired: nil,
            asset: "SOL",
            payTo: Fixture.payTo,
            recipient: nil,
            extra: [
                "recentBlockhash": .string(Fixture.blockhash),
                "feePayer": .string(feePayer),
            ]
        )
        let signer = try Fixture.signer()
        let header = try await buildX402PaymentHeader(
            signer: signer, rpc: Fixture.rpc(), offer: offer,
            nonceGenerator: Fixture.fixedNonceGenerator()
        )
        let tx = try Fixture.decodePayload(header)

        let feePayerPk = try Pubkey(base58: feePayer)
        let signerPk = try Pubkey(bytes: try signer.publicKey)

        // Fee payer leads the account list.
        #expect(tx.accountKeys[0] == feePayerPk)

        // The signer is a required signer somewhere after slot 0.
        guard let signerIndex = tx.accountKeys.firstIndex(of: signerPk) else {
            Issue.record("signer not present in account keys")
            return
        }
        #expect(signerIndex != 0)
        #expect(signerIndex < tx.numRequiredSignatures)

        // The signer's signature slot is populated; slot 0 (fee payer, who
        // did not sign here) stays all-zero.
        let zero = Data(repeating: 0, count: 64)
        #expect(tx.signatures[0] == zero)
        #expect(tx.signatures[signerIndex] != zero)
    }

    // MARK: - Top-level feePayerKey (managed fee-payer offer shape)

    /// Regression: a top-level `feePayerKey` (no extra.feePayer) must be
    /// resolved by `effectiveFeePayerKey` and compiled to accountKeys[0].
    ///
    /// This matches the Kotlin/Rust managed-fee-payer offer shape where the
    /// server stamps the key at the top level of the offer object rather than
    /// inside the `extra` dict.
    @Test
    func topLevelFeePayerKeyBecomesAccountKeysZero() async throws {
        let feePayer = "11111111111111111111111111111112" // distinct from signer and recipient
        let offer = X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "5000",
            maxAmountRequired: nil,
            asset: "SOL",
            payTo: Fixture.payTo,
            recipient: nil,
            extra: ["recentBlockhash": .string(Fixture.blockhash)],
            feePayerKey: feePayer   // top-level; no extra.feePayer
        )

        // effectiveFeePayerKey must return the top-level key (feePayer toggle
        // absent => defaults to true).
        #expect(offer.effectiveFeePayerKey == feePayer)

        let signer = try Fixture.signer()
        let header = try await buildX402PaymentHeader(
            signer: signer, rpc: Fixture.rpc(), offer: offer,
            nonceGenerator: Fixture.fixedNonceGenerator()
        )
        let tx = try Fixture.decodePayload(header)

        let feePayerPk = try Pubkey(base58: feePayer)
        let signerPk = try Pubkey(bytes: try signer.publicKey)

        // The managed fee payer must occupy account index 0.
        #expect(tx.accountKeys[0] == feePayerPk)

        // The signer must appear somewhere after slot 0 and still sign.
        guard let signerIndex = tx.accountKeys.firstIndex(of: signerPk) else {
            Issue.record("signer not found in account keys")
            return
        }
        #expect(signerIndex != 0)
        #expect(signerIndex < tx.numRequiredSignatures)

        // Slot 0 (unattached fee payer) stays all-zero; signer slot is filled.
        let zero = Data(repeating: 0, count: 64)
        #expect(tx.signatures[0] == zero)
        #expect(tx.signatures[signerIndex] != zero)
    }

    /// Regression: top-level `feePayerKey` + explicit `feePayer: false` must
    /// opt out -- `effectiveFeePayerKey` returns nil and the signer pays
    /// (accountKeys[0] == signer).
    @Test
    func topLevelFeePayerKeyWithFeePayerFalseOptOutMeansSignerPays() async throws {
        let feePayer = "11111111111111111111111111111112"
        let offer = X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "5000",
            maxAmountRequired: nil,
            asset: "SOL",
            payTo: Fixture.payTo,
            recipient: nil,
            extra: ["recentBlockhash": .string(Fixture.blockhash)],
            feePayerKey: feePayer,
            feePayer: false          // explicit opt-out
        )

        // feePayer: false gates the key => nil.
        #expect(offer.effectiveFeePayerKey == nil)

        let signer = try Fixture.signer()
        let header = try await buildX402PaymentHeader(
            signer: signer, rpc: Fixture.rpc(), offer: offer,
            nonceGenerator: Fixture.fixedNonceGenerator()
        )
        let tx = try Fixture.decodePayload(header)

        let signerPk = try Pubkey(bytes: try signer.publicKey)

        // Signer is fee payer (index 0).
        #expect(tx.accountKeys[0] == signerPk)
    }

    /// Regression: `extra.feePayer` (back-compat path) combined with top-level
    /// `feePayer: false` must also opt out -- `effectiveFeePayerKey` returns
    /// nil. Ensures the gate applies regardless of which dict the key came from.
    @Test
    func extraFeePayerWithFeePayerFalseOptOutMeansSignerPays() async throws {
        let feePayer = "11111111111111111111111111111112"
        let offer = X402AcceptsEntry(
            scheme: "exact",
            network: SolanaNetwork.devnet,
            amount: "5000",
            maxAmountRequired: nil,
            asset: "SOL",
            payTo: Fixture.payTo,
            recipient: nil,
            extra: [
                "recentBlockhash": .string(Fixture.blockhash),
                "feePayer": .string(feePayer),  // legacy extra path
            ],
            feePayer: false          // top-level toggle opts out
        )

        // feePayer: false gates the extra.feePayer key => nil.
        #expect(offer.effectiveFeePayerKey == nil)

        let signer = try Fixture.signer()
        let header = try await buildX402PaymentHeader(
            signer: signer, rpc: Fixture.rpc(), offer: offer,
            nonceGenerator: Fixture.fixedNonceGenerator()
        )
        let tx = try Fixture.decodePayload(header)

        let signerPk = try Pubkey(bytes: try signer.publicKey)

        // Signer is fee payer (index 0).
        #expect(tx.accountKeys[0] == signerPk)
    }
}
