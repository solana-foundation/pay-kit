import Foundation
import CryptoKit

/// Program Derived Address (PDA) helpers.
///
/// Solana PDA derivation: hash = SHA-256(seed1 || seed2 || ... ||
/// bump || program_id || "ProgramDerivedAddress"). Iterate bump from
/// 255 down to 0; return the first hash whose 32 bytes do *not* lie on
/// the Ed25519 curve. On-curve hashes are rejected because the PDA
/// must not have a matching secret key.
public enum ProgramDerivedAddress {
    public static let marker = Data("ProgramDerivedAddress".utf8)

    public struct DerivationFailedError: Error, Equatable {}

    public static func find(seeds: [Data], programId: Pubkey) throws -> (address: Pubkey, bump: UInt8) {
        var bump: Int = 255
        while bump >= 0 {
            var hasher = SHA256()
            for seed in seeds {
                hasher.update(data: seed)
            }
            hasher.update(data: Data([UInt8(bump)]))
            hasher.update(data: programId.bytes)
            hasher.update(data: marker)
            let digest = Data(hasher.finalize())

            if !Curve25519OnCurve.isOnCurve(digest) {
                return (address: try Pubkey(bytes: digest), bump: UInt8(bump))
            }

            bump -= 1
        }
        throw DerivationFailedError()
    }
}

/// Associated Token Account derivation. The seeds are
/// [owner, token_program, mint] in that order, programmed under the
/// canonical ATA program id.
public enum AssociatedTokenAccount {
    public static func address(owner: Pubkey, mint: Pubkey, tokenProgram: Pubkey) throws -> Pubkey {
        let seeds: [Data] = [owner.bytes, tokenProgram.bytes, mint.bytes]
        let (addr, _) = try ProgramDerivedAddress.find(seeds: seeds, programId: .associatedTokenProgram)
        return addr
    }
}
