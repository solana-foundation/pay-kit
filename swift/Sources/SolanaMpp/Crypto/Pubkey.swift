import Foundation

/// 32-byte Solana account identifier.
///
/// Mirrors `solana-pubkey` on the Rust spine: the wire form is always 32
/// raw bytes; the human-readable form is base58. `Pubkey` is Hashable so
/// it can deduplicate accounts when compiling instructions into a message.
public struct Pubkey: Hashable, Equatable, Sendable {
    public static let length = 32

    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == Self.length else {
            throw MppError.invalidPubkey("expected 32 bytes, got \(bytes.count)")
        }
        self.bytes = bytes
    }

    public init(base58 string: String) throws {
        let decoded = try Base58.decode(string)
        guard decoded.count == Self.length else {
            throw MppError.invalidPubkey("decoded length \(decoded.count) is not 32")
        }
        self.bytes = decoded
    }

    public var base58: String { Base58.encode(bytes) }

    public static let systemProgram = try! Pubkey(bytes: Data(repeating: 0, count: 32))

    public static let tokenProgram = try! Pubkey(
        base58: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    )

    public static let token2022Program = try! Pubkey(
        base58: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
    )

    public static let associatedTokenProgram = try! Pubkey(
        base58: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
    )

    public static let memoProgram = try! Pubkey(
        base58: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
    )

    public static let computeBudgetProgram = try! Pubkey(
        base58: "ComputeBudget111111111111111111111111111111"
    )

    public static let sysvarRent = try! Pubkey(
        base58: "SysvarRent111111111111111111111111111111111"
    )
}
