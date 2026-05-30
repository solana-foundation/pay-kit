import Foundation

/// Solana instruction builders for the program set the MPP charge
/// intent depends on:
///
/// - SystemProgram.transfer (native SOL)
/// - SPL Token / Token-2022 transferChecked
/// - Associated Token Account create + create-idempotent
/// - ComputeBudget SetComputeUnitLimit + SetComputeUnitPrice
/// - SPL Memo (memo)
///
/// All discriminators and account orderings match the Rust spine
/// (`rust/src/client/charge.rs`) and the canonical TypeScript client
/// (`@solana-program/system`, `@solana-program/token`,
/// `@solana-program/compute-budget`). The instruction-level parity is
/// further locked by the transaction-codec parity tests in
/// `TransactionTests`: those tests already round-trip a SystemTransfer
/// + ComputeBudget + SPL transferChecked transaction byte-for-byte
/// against Rust's serialized output.
public enum Instructions {
    // MARK: System program

    /// SystemProgram::Transfer.
    /// Wire form: u32 discriminator = 2, u64 lamports (little-endian).
    public static func systemTransfer(from source: Pubkey, to destination: Pubkey, lamports: UInt64) -> SolanaInstruction {
        var data = Data()
        data.append(contentsOf: withUnsafeBytes(of: UInt32(2).littleEndian, Array.init))
        data.append(contentsOf: withUnsafeBytes(of: lamports.littleEndian, Array.init))
        return SolanaInstruction(
            programId: .systemProgram,
            accounts: [
                .writableSigner(source),
                .writable(destination),
            ],
            data: data
        )
    }

    // MARK: SPL Token / Token-2022

    /// TokenInstruction::TransferChecked.
    /// Wire form: u8 discriminator = 12, u64 amount (little-endian), u8 decimals.
    /// Account order: [source, mint (readonly), destination, authority (signer)].
    public static func splTransferChecked(
        programId: Pubkey,
        source: Pubkey,
        mint: Pubkey,
        destination: Pubkey,
        authority: Pubkey,
        amount: UInt64,
        decimals: UInt8
    ) -> SolanaInstruction {
        var data = Data([12])
        data.append(contentsOf: withUnsafeBytes(of: amount.littleEndian, Array.init))
        data.append(decimals)
        return SolanaInstruction(
            programId: programId,
            accounts: [
                .writable(source),
                .readonly(mint),
                .writable(destination),
                .readonlySigner(authority),
            ],
            data: data
        )
    }

    // MARK: Associated Token Account

    /// ATA Create (discriminator 0) or CreateIdempotent (discriminator 1).
    /// Account order matches `@solana-program/token`:
    /// [payer (writable signer), ata (writable), owner (readonly),
    ///  mint (readonly), system program (readonly), token program (readonly)].
    public static func createAssociatedTokenAccount(
        payer: Pubkey,
        ata: Pubkey,
        owner: Pubkey,
        mint: Pubkey,
        tokenProgram: Pubkey,
        idempotent: Bool
    ) -> SolanaInstruction {
        let discriminator: UInt8 = idempotent ? 1 : 0
        return SolanaInstruction(
            programId: .associatedTokenProgram,
            accounts: [
                .writableSigner(payer),
                .writable(ata),
                .readonly(owner),
                .readonly(mint),
                .readonly(.systemProgram),
                .readonly(tokenProgram),
            ],
            data: Data([discriminator])
        )
    }

    // MARK: Compute Budget

    /// SetComputeUnitLimit. Discriminator 2, u32 units (little-endian).
    public static func computeBudgetSetUnitLimit(units: UInt32) -> SolanaInstruction {
        var data = Data([2])
        data.append(contentsOf: withUnsafeBytes(of: units.littleEndian, Array.init))
        return SolanaInstruction(
            programId: .computeBudgetProgram,
            accounts: [],
            data: data
        )
    }

    /// SetComputeUnitPrice. Discriminator 3, u64 micro-lamports (little-endian).
    public static func computeBudgetSetUnitPrice(microLamports: UInt64) -> SolanaInstruction {
        var data = Data([3])
        data.append(contentsOf: withUnsafeBytes(of: microLamports.littleEndian, Array.init))
        return SolanaInstruction(
            programId: .computeBudgetProgram,
            accounts: [],
            data: data
        )
    }

    // MARK: Memo

    public static let memoMaxBytes = 566

    /// SPL Memo (memo) instruction.
    public static func memo(_ text: String) throws -> SolanaInstruction {
        let bytes = Data(text.utf8)
        guard bytes.count <= memoMaxBytes else {
            throw MppError.invalidTransaction("memo exceeds \(memoMaxBytes) bytes")
        }
        return SolanaInstruction(
            programId: .memoProgram,
            accounts: [],
            data: bytes
        )
    }
}
