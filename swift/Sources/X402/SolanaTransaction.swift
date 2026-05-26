import Foundation
import Crypto

public protocol RecentBlockhashProvider {
    func getLatestBlockhash() async throws -> String
}

public protocol AssociatedTokenAddressResolver {
    func associatedTokenAddress(owner: SolanaPublicKey, mint: SolanaPublicKey, tokenProgram: SolanaPublicKey) throws -> SolanaPublicKey
}

public struct DefaultAssociatedTokenAddressResolver: AssociatedTokenAddressResolver {
    public init() {}

    public func associatedTokenAddress(owner: SolanaPublicKey, mint: SolanaPublicKey, tokenProgram: SolanaPublicKey) throws -> SolanaPublicKey {
        let program = try SolanaPublicKey(X402.associatedTokenProgram)
        for bump in stride(from: UInt8.max, through: 0, by: -1) {
            var seed = Data()
            seed.append(owner.bytes)
            seed.append(tokenProgram.bytes)
            seed.append(mint.bytes)
            seed.append(bump)
            seed.append(program.bytes)
            seed.append("ProgramDerivedAddress".data(using: .utf8)!)
            let digest = SHA256.hash(data: seed)
            let candidate = Data(digest)
            if !Ed25519CompressedPoint.isOnCurve(candidate) {
                return try SolanaPublicKey(bytes: candidate)
            }
        }
        throw X402Error.invalidBase58("unable to derive associated token account")
    }
}

struct AccountMeta {
    let publicKey: SolanaPublicKey
    let isSigner: Bool
    let isWritable: Bool
}

struct TransactionInstruction {
    let programId: SolanaPublicKey
    let accounts: [AccountMeta]
    let data: Data
}

public struct ExactTransactionBuilder {
    private let signer: SolanaSigner
    private let blockhashProvider: RecentBlockhashProvider?
    private let ataResolver: AssociatedTokenAddressResolver

    public init(
        signer: SolanaSigner,
        blockhashProvider: RecentBlockhashProvider? = nil,
        ataResolver: AssociatedTokenAddressResolver = DefaultAssociatedTokenAddressResolver()
    ) {
        self.signer = signer
        self.blockhashProvider = blockhashProvider
        self.ataResolver = ataResolver
    }

    public func buildPaymentHeader(for requirement: PaymentRequirement) async throws -> String {
        let transaction = try await buildTransaction(for: requirement)
        let payload = PaymentSignatureEnvelope(
            x402Version: X402.x402Version,
            accepted: requirement,
            payload: ExactPayload(transaction: transaction.base64EncodedString())
        )
        let json = try JSONEncoder().encode(payload)
        return json.base64EncodedString()
    }

    public func buildTransaction(for requirement: PaymentRequirement) async throws -> Data {
        guard requirement.scheme == X402.exactScheme else {
            throw X402Error.unsupportedScheme(requirement.scheme)
        }
        guard requirement.network.starts(with: "solana:") else {
            throw X402Error.unsupportedNetwork(requirement.network)
        }
        guard let amount = UInt64(requirement.amount) else {
            throw X402Error.invalidAmount(requirement.amount)
        }
        guard let feePayer = requirement.feePayer else {
            throw X402Error.missingFeePayer
        }
        let recentBlockhash = try await blockhashProvider?.getLatestBlockhash()
        guard let recentBlockhash else {
            throw X402Error.missingBlockhash
        }

        let payer = try SolanaPublicKey(feePayer)
        let mint = try SolanaPublicKey(requirement.asset)
        let payTo = try SolanaPublicKey(requirement.payTo)
        // Independent defense-in-depth allowlist check: even if a caller bypasses
        // `parseX402Challenge` and constructs a `PaymentRequirement` directly, the
        // builder must refuse to sign for an arbitrary executable program.
        let tokenProgram = try SolanaPublicKey(requirement.validatedTokenProgram())
        let sourceATA = try ataResolver.associatedTokenAddress(owner: signer.address, mint: mint, tokenProgram: tokenProgram)
        let destinationATA = try ataResolver.associatedTokenAddress(owner: payTo, mint: mint, tokenProgram: tokenProgram)
        // Compute budget. The canonical SVM exact facilitator validates these
        // by index, so the values are pinned to the Rust spine at
        // rust/crates/x402/src/client/exact/payment.rs:55-57
        // (`compute_unit_limit_ix(20_000)` then `compute_unit_price_ix(1)`).
        // Tests below pin the serialized bytes so any drift surfaces in CI.
        let instructions = [
            computeUnitLimitInstruction(units: 20_000),
            computeUnitPriceInstruction(microLamports: 1),
            transferCheckedInstruction(
                tokenProgram: tokenProgram,
                source: sourceATA,
                mint: mint,
                destination: destinationATA,
                authority: signer.address,
                amount: amount,
                decimals: try requirement.decimals()
            ),
            try memoInstruction(requirement.memo),
        ]
        let compiled = try compileV0Message(
            feePayer: payer,
            authority: signer.address,
            recentBlockhash: try SolanaPublicKey(recentBlockhash).bytes,
            instructions: instructions
        )
        let signature = try await signer.sign(message: compiled.data)
        guard signature.count == 64 else {
            throw X402Error.invalidSignatureLength(signature.count)
        }
        return serializeVersionedTransaction(message: compiled.data, authority: signer.address, signature: signature, accountKeys: compiled.accountKeys)
    }
}

private struct ExactPayload: Codable {
    let transaction: String
}

private struct PaymentSignatureEnvelope: Codable {
    let x402Version: Int
    let accepted: PaymentRequirement
    let payload: ExactPayload
}

private struct CompiledMessage {
    let data: Data
    let accountKeys: [SolanaPublicKey]
}

private func computeUnitLimitInstruction(units: UInt32) -> TransactionInstruction {
    var data = Data([2])
    data.appendLittleEndian(units)
    return TransactionInstruction(programId: try! SolanaPublicKey(X402.computeBudgetProgram), accounts: [], data: data)
}

private func computeUnitPriceInstruction(microLamports: UInt64) -> TransactionInstruction {
    var data = Data([3])
    data.appendLittleEndian(microLamports)
    return TransactionInstruction(programId: try! SolanaPublicKey(X402.computeBudgetProgram), accounts: [], data: data)
}

private func transferCheckedInstruction(
    tokenProgram: SolanaPublicKey,
    source: SolanaPublicKey,
    mint: SolanaPublicKey,
    destination: SolanaPublicKey,
    authority: SolanaPublicKey,
    amount: UInt64,
    decimals: UInt8
) -> TransactionInstruction {
    var data = Data([12])
    data.appendLittleEndian(amount)
    data.append(decimals)
    return TransactionInstruction(
        programId: tokenProgram,
        accounts: [
            AccountMeta(publicKey: source, isSigner: false, isWritable: true),
            AccountMeta(publicKey: mint, isSigner: false, isWritable: false),
            AccountMeta(publicKey: destination, isSigner: false, isWritable: true),
            AccountMeta(publicKey: authority, isSigner: true, isWritable: false),
        ],
        data: data
    )
}

private func memoInstruction(_ memo: String?) throws -> TransactionInstruction {
    let bytes: Data
    if let memo {
        bytes = Data(memo.utf8)
        if bytes.count > X402.maxMemoBytes {
            throw X402Error.memoTooLarge(bytes.count)
        }
    } else {
        bytes = Data(UUID().uuidString.replacingOccurrences(of: "-", with: "").utf8)
    }
    return TransactionInstruction(programId: try SolanaPublicKey(X402.memoProgram), accounts: [], data: bytes)
}

private func compileV0Message(
    feePayer: SolanaPublicKey,
    authority: SolanaPublicKey,
    recentBlockhash: Data,
    instructions: [TransactionInstruction]
) throws -> CompiledMessage {
    var keys: [SolanaPublicKey] = [feePayer]
    if authority != feePayer {
        keys.append(authority)
    }
    func appendKey(_ key: SolanaPublicKey) {
        if !keys.contains(key) {
            keys.append(key)
        }
    }
    let metas = instructions.flatMap(\.accounts)
    for meta in metas where !meta.isSigner && meta.isWritable { appendKey(meta.publicKey) }
    for meta in metas where !meta.isSigner && !meta.isWritable { appendKey(meta.publicKey) }
    for instruction in instructions { appendKey(instruction.programId) }

    var message = Data([0x80])
    message.append(UInt8(authority == feePayer ? 1 : 2))
    message.append(UInt8(authority == feePayer ? 0 : 1))
    message.append(0)
    let readonlyUnsigned = keys.enumerated().filter { index, key in
        index >= (authority == feePayer ? 1 : 2)
            && !metas.contains(where: { $0.publicKey == key && $0.isWritable })
    }.count
    message[3] = UInt8(readonlyUnsigned)
    message.appendShortVec(keys.count)
    for key in keys { message.append(key.bytes) }
    message.append(recentBlockhash)
    message.appendShortVec(instructions.count)
    for instruction in instructions {
        message.append(UInt8(keys.firstIndex(of: instruction.programId)!))
        message.appendShortVec(instruction.accounts.count)
        for account in instruction.accounts {
            message.append(UInt8(keys.firstIndex(of: account.publicKey)!))
        }
        message.appendShortVec(instruction.data.count)
        message.append(instruction.data)
    }
    message.appendShortVec(0)
    return CompiledMessage(data: message, accountKeys: keys)
}

private func serializeVersionedTransaction(message: Data, authority: SolanaPublicKey, signature: Data, accountKeys: [SolanaPublicKey]) -> Data {
    let signatureCount = accountKeys.firstIndex(of: authority).map { max($0 + 1, 1) } ?? 1
    var signatures = Array(repeating: Data(repeating: 0, count: 64), count: signatureCount)
    if let index = accountKeys.firstIndex(of: authority), index < signatures.count {
        signatures[index] = signature
    } else {
        signatures[0] = signature
    }
    var tx = Data()
    tx.appendShortVec(signatures.count)
    for sig in signatures { tx.append(sig) }
    tx.append(message)
    return tx
}

extension Data {
    mutating func appendShortVec(_ value: Int) {
        var remaining = value
        while true {
            var elem = UInt8(remaining & 0x7f)
            remaining >>= 7
            if remaining == 0 {
                append(elem)
                break
            }
            elem |= 0x80
            append(elem)
        }
    }

    mutating func appendLittleEndian<T: FixedWidthInteger>(_ value: T) {
        var little = value.littleEndian
        Swift.withUnsafeBytes(of: &little) { append(contentsOf: $0) }
    }
}
