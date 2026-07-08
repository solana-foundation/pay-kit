import Foundation

/// Solana account metadata as it appears in an `Instruction`.
public struct AccountMeta: Hashable, Sendable {
    public let pubkey: Pubkey
    public let isSigner: Bool
    public let isWritable: Bool

    public init(pubkey: Pubkey, isSigner: Bool, isWritable: Bool) {
        self.pubkey = pubkey
        self.isSigner = isSigner
        self.isWritable = isWritable
    }

    public static func writableSigner(_ pubkey: Pubkey) -> AccountMeta {
        .init(pubkey: pubkey, isSigner: true, isWritable: true)
    }

    public static func readonlySigner(_ pubkey: Pubkey) -> AccountMeta {
        .init(pubkey: pubkey, isSigner: true, isWritable: false)
    }

    public static func writable(_ pubkey: Pubkey) -> AccountMeta {
        .init(pubkey: pubkey, isSigner: false, isWritable: true)
    }

    public static func readonly(_ pubkey: Pubkey) -> AccountMeta {
        .init(pubkey: pubkey, isSigner: false, isWritable: false)
    }
}

/// One Solana instruction prior to message compilation.
public struct SolanaInstruction: Sendable {
    public let programId: Pubkey
    public let accounts: [AccountMeta]
    public let data: Data

    public init(programId: Pubkey, accounts: [AccountMeta], data: Data) {
        self.programId = programId
        self.accounts = accounts
        self.data = data
    }
}

/// Solana message version. `legacy` omits the version prefix byte; `v0`
/// prepends `0x80` and serializes a zero-length address-table-lookup
/// vector, matching the Rust `VersionedMessage::Legacy` / `::V0`
/// serialize outputs in solana-message 3.x.
public enum TransactionVersion: Sendable, Equatable {
    case legacy
    case v0
}

/// Compact short-vec (compact-u16) encoding used by Solana wire format.
///
/// Same algorithm as `solana-short-vec`: emit 7 bits per byte, set the
/// high bit on every byte except the last. Max value is u16::MAX
/// (65 535), encoded as 3 bytes.
enum ShortVec {
    static func encodeLength(_ length: Int) -> Data {
        precondition(length >= 0 && length <= 0xFFFF, "short-vec length out of range")
        var value = length
        var out = Data()
        while true {
            var byte = UInt8(value & 0x7F)
            value >>= 7
            if value == 0 {
                out.append(byte)
                return out
            }
            byte |= 0x80
            out.append(byte)
        }
    }

    static func decodeLength(_ data: Data, at offset: inout Int) throws -> Int {
        var value = 0
        var shift = 0
        for _ in 0..<3 {
            guard offset < data.count else {
                throw MppError.invalidTransaction("short-vec length truncated")
            }
            let byte = data[data.startIndex + offset]
            offset += 1
            value |= Int(byte & 0x7F) << shift
            if (byte & 0x80) == 0 {
                return value
            }
            shift += 7
        }
        throw MppError.invalidTransaction("short-vec length exceeds 3 bytes")
    }
}

/// Compiled instruction (post message-build form): program-id index plus
/// account-index compact array plus data compact array.
public struct CompiledInstruction: Sendable {
    public let programIdIndex: UInt8
    public let accountIndices: [UInt8]
    public let data: Data
}

/// Solana transaction message ready for signing.
public struct TransactionMessage: Sendable {
    public let version: TransactionVersion
    public let header: MessageHeader
    public let accountKeys: [Pubkey]
    public let recentBlockhash: Data
    public let instructions: [CompiledInstruction]

    public struct MessageHeader: Sendable, Equatable {
        public let numRequiredSignatures: UInt8
        public let numReadonlySignedAccounts: UInt8
        public let numReadonlyUnsignedAccounts: UInt8
    }

    public init(
        version: TransactionVersion,
        header: MessageHeader,
        accountKeys: [Pubkey],
        recentBlockhash: Data,
        instructions: [CompiledInstruction]
    ) throws {
        guard recentBlockhash.count == 32 else {
            throw MppError.invalidTransaction("recentBlockhash must be 32 bytes")
        }
        self.version = version
        self.header = header
        self.accountKeys = accountKeys
        self.recentBlockhash = recentBlockhash
        self.instructions = instructions
    }

    /// Wire-format serialization. The byte sequence matches the Rust
    /// `solana_message::legacy::Message::serialize` (legacy) and the
    /// `solana_message::VersionedMessage::serialize` (v0) outputs.
    public func serialize() -> Data {
        var out = Data()
        if version == .v0 {
            out.append(0x80) // version prefix for v0
        }
        out.append(header.numRequiredSignatures)
        out.append(header.numReadonlySignedAccounts)
        out.append(header.numReadonlyUnsignedAccounts)

        out.append(ShortVec.encodeLength(accountKeys.count))
        for key in accountKeys { out.append(key.bytes) }

        out.append(recentBlockhash)

        out.append(ShortVec.encodeLength(instructions.count))
        for ix in instructions {
            out.append(ix.programIdIndex)
            out.append(ShortVec.encodeLength(ix.accountIndices.count))
            out.append(contentsOf: ix.accountIndices)
            out.append(ShortVec.encodeLength(ix.data.count))
            out.append(ix.data)
        }

        if version == .v0 {
            // Zero-length address table lookup vector. The SDK does not
            // emit ALT lookups; the Rust spine still expects the field.
            out.append(ShortVec.encodeLength(0))
        }

        return out
    }
}

/// Compiles a list of `SolanaInstruction` plus a fee payer into a
/// `TransactionMessage`. Mirrors `solana_message::v0::Message::try_compile`
/// account ordering: the fee payer occupies index 0; remaining accounts
/// are partitioned into [writable-signers, readonly-signers,
/// writable-non-signers, readonly-non-signers], with each partition
/// sorted lexicographically by raw pubkey bytes. The Rust spine uses
/// `BTreeMap<Pubkey>` so the on-wire order is deterministic and
/// independent of instruction insertion order.
public enum TransactionBuilder {
    public static func compile(
        version: TransactionVersion,
        feePayer: Pubkey,
        instructions: [SolanaInstruction],
        recentBlockhash: Data
    ) throws -> TransactionMessage {
        struct Slot {
            var isSigner: Bool
            var isWritable: Bool
        }
        var slots: [Pubkey: Slot] = [:]

        func touch(_ pubkey: Pubkey, isSigner: Bool, isWritable: Bool) {
            if var existing = slots[pubkey] {
                existing.isSigner = existing.isSigner || isSigner
                existing.isWritable = existing.isWritable || isWritable
                slots[pubkey] = existing
            } else {
                slots[pubkey] = Slot(isSigner: isSigner, isWritable: isWritable)
            }
        }

        for ix in instructions {
            // Rust touches the program id first (`is_invoked = true`)
            // before any account metas. The ordering inside the BTreeMap
            // is by Pubkey, so insertion order does not matter, but the
            // flags must accumulate correctly.
            touch(ix.programId, isSigner: false, isWritable: false)
            for meta in ix.accounts {
                touch(meta.pubkey, isSigner: meta.isSigner, isWritable: meta.isWritable)
            }
        }
        // Fee payer wins the writable + signer flags on the spine.
        touch(feePayer, isSigner: true, isWritable: true)

        // Partition + sort lexicographically by pubkey bytes within each.
        var writableSigners: [Pubkey] = []
        var readonlySigners: [Pubkey] = []
        var writableNonSigners: [Pubkey] = []
        var readonlyNonSigners: [Pubkey] = []

        for (pubkey, slot) in slots where pubkey != feePayer {
            switch (slot.isSigner, slot.isWritable) {
            case (true, true): writableSigners.append(pubkey)
            case (true, false): readonlySigners.append(pubkey)
            case (false, true): writableNonSigners.append(pubkey)
            case (false, false): readonlyNonSigners.append(pubkey)
            }
        }

        let byBytes: (Pubkey, Pubkey) -> Bool = { lhs, rhs in
            lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
        }
        writableSigners.sort(by: byBytes)
        readonlySigners.sort(by: byBytes)
        writableNonSigners.sort(by: byBytes)
        readonlyNonSigners.sort(by: byBytes)

        // Fee payer leads writable signers.
        writableSigners.insert(feePayer, at: 0)

        let accountKeys = writableSigners + readonlySigners + writableNonSigners + readonlyNonSigners
        guard accountKeys.count <= 255 else {
            throw MppError.invalidTransaction(
                "transaction has \(accountKeys.count) accounts; the Solana wire format caps account indices at u8 (255)"
            )
        }
        var keyIndex: [Pubkey: UInt8] = [:]
        for (index, key) in accountKeys.enumerated() {
            keyIndex[key] = UInt8(index)
        }

        let totalSigners = writableSigners.count + readonlySigners.count
        guard totalSigners <= 255,
              readonlySigners.count <= 255,
              readonlyNonSigners.count <= 255
        else {
            throw MppError.invalidTransaction(
                "header counts exceed u8: signers=\(totalSigners), readonlySigners=\(readonlySigners.count), readonlyNonSigners=\(readonlyNonSigners.count)"
            )
        }
        let header = TransactionMessage.MessageHeader(
            numRequiredSignatures: UInt8(totalSigners),
            numReadonlySignedAccounts: UInt8(readonlySigners.count),
            numReadonlyUnsignedAccounts: UInt8(readonlyNonSigners.count)
        )

        // Resolve compiled instructions through the key index. The index
        // is built from the same `slots` map that observed every
        // program-id and account pubkey above, so every lookup should
        // succeed; surface a domain error (not a SIGTRAP) on the
        // pathological case where it does not, to keep production paths
        // free of force-unwraps on derived-from-input data.
        var compiled: [CompiledInstruction] = []
        compiled.reserveCapacity(instructions.count)
        for ix in instructions {
            guard let programIdIndex = keyIndex[ix.programId] else {
                throw MppError.invalidTransaction(
                    "program id \(ix.programId.base58) is missing from compiled account keys"
                )
            }
            var accountIndices: [UInt8] = []
            accountIndices.reserveCapacity(ix.accounts.count)
            for meta in ix.accounts {
                guard let idx = keyIndex[meta.pubkey] else {
                    throw MppError.invalidTransaction(
                        "account \(meta.pubkey.base58) is missing from compiled account keys"
                    )
                }
                accountIndices.append(idx)
            }
            compiled.append(CompiledInstruction(
                programIdIndex: programIdIndex,
                accountIndices: accountIndices,
                data: ix.data
            ))
        }

        return try TransactionMessage(
            version: version,
            header: header,
            accountKeys: accountKeys,
            recentBlockhash: recentBlockhash,
            instructions: compiled
        )
    }
}

/// Full signed Solana transaction. Wire form is `compact-array of
/// 64-byte signatures` then `message bytes`.
public struct SignedTransaction: Sendable {
    public let signatures: [Data]
    public let message: TransactionMessage

    public init(signatures: [Data], message: TransactionMessage) throws {
        for sig in signatures {
            guard sig.count == 64 else {
                throw MppError.invalidTransaction("signature must be 64 bytes, got \(sig.count)")
            }
        }
        self.signatures = signatures
        self.message = message
    }

    public func serialize() -> Data {
        var out = Data()
        out.append(ShortVec.encodeLength(signatures.count))
        for sig in signatures { out.append(sig) }
        out.append(message.serialize())
        return out
    }

    /// Convenience: 1 signature slot per required signer. Slots without a
    /// concrete signature (partial-sign path) carry 64 zero bytes.
    public static func emptySignatureSlots(count: Int) -> [Data] {
        Array(repeating: Data(repeating: 0, count: 64), count: count)
    }
}
