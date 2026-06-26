import Foundation

/// Client-side payment-channels primitives: PDA/ATA derivation, the 48-byte
/// voucher preimage, and the `open` instruction + partially-signed open
/// transaction the session client broadcasts via the operator.
///
/// Mirrors the client-facing subset of `solana_pay_core::payment_channels`
/// (`rust/crates/core/src/payment_channels.rs`). The server-only primitives
/// (ed25519 verify precompile, settle/finalize/distribute, the BLAKE3
/// distribution hash) are intentionally omitted: this SDK is client-only, and
/// the channel `open` passes its recipients inline rather than hashed.
public enum PaymentChannels {
    private static let canonicalProgramId = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"

    /// Canonical payment-channels program ID deployed to Surfnet.
    public static let programId: Pubkey = {
        guard let id = try? Pubkey(base58: canonicalProgramId) else {
            preconditionFailure("invalid canonical payment-channels program ID")
        }
        return id
    }()

    /// Channel PDA seed prefix.
    static let channelSeed = Data("channel".utf8)

    /// Event-authority PDA seed prefix.
    static let eventAuthoritySeed = Data("event_authority".utf8)

    /// Default payment-channel close grace period, in seconds.
    public static let defaultGracePeriodSeconds: UInt32 = 900

    /// `open` instruction discriminator (codama `OPEN_DISCRIMINATOR`).
    static let openDiscriminator: UInt8 = 1

    /// A recipient split: `bps` basis points of the settled balance.
    public struct Distribution: Equatable, Sendable {
        public let recipient: Pubkey
        public let bps: UInt16

        public init(recipient: Pubkey, bps: UInt16) {
            self.recipient = recipient
            self.bps = bps
        }
    }

    /// Inputs to the channel `open` instruction.
    public struct OpenChannelParams: Sendable {
        public let payer: Pubkey
        /// Operator / fee-payer that funds the channel PDA + escrow-ATA rent at
        /// open (SIGNER + WRITABLE). Always the same key that co-signs `open` as
        /// fee payer; never a separate wire field.
        public let rentPayer: Pubkey
        public let payee: Pubkey
        public let mint: Pubkey
        public let authorizedSigner: Pubkey
        public let salt: UInt64
        public let deposit: UInt64
        public let gracePeriod: UInt32
        public let recipients: [Distribution]
        public let tokenProgram: Pubkey
        public let programId: Pubkey

        public init(
            payer: Pubkey,
            rentPayer: Pubkey,
            payee: Pubkey,
            mint: Pubkey,
            authorizedSigner: Pubkey,
            salt: UInt64,
            deposit: UInt64,
            gracePeriod: UInt32,
            recipients: [Distribution],
            tokenProgram: Pubkey,
            programId: Pubkey
        ) {
            self.payer = payer
            self.rentPayer = rentPayer
            self.payee = payee
            self.mint = mint
            self.authorizedSigner = authorizedSigner
            self.salt = salt
            self.deposit = deposit
            self.gracePeriod = gracePeriod
            self.recipients = recipients
            self.tokenProgram = tokenProgram
            self.programId = programId
        }
    }

    /// Output of ``buildOpenTransaction(payer:payee:mint:authorizedSigner:salt:deposit:gracePeriod:recipients:tokenProgram:programId:feePayer:recentBlockhash:)``:
    /// the derived channel PDA and the base64 (payer-signed, fee-payer-unsigned)
    /// open transaction.
    public struct OpenTransaction: Sendable {
        public let channelId: Pubkey
        public let transaction: String
    }

    // MARK: - Voucher preimage

    /// The 48-byte Ed25519 voucher preimage:
    /// `channelId(32) || cumulativeAmount(u64 LE) || expiresAt(i64 LE)`.
    /// Matches `voucher_message_bytes` (Borsh of a fixed `[u8;32]` + scalars,
    /// no discriminator or length prefix).
    public static func voucherMessageBytes(channelId: Pubkey, cumulative: UInt64, expiresAt: Int64) -> Data {
        var out = Data(capacity: 48)
        out.append(channelId.bytes)
        out.append(littleEndian(cumulative))
        out.append(littleEndian(UInt64(bitPattern: expiresAt)))
        return out
    }

    // MARK: - PDA derivation

    public static func findChannelPda(
        payer: Pubkey,
        payee: Pubkey,
        mint: Pubkey,
        authorizedSigner: Pubkey,
        salt: UInt64,
        programId: Pubkey
    ) throws -> Pubkey {
        let seeds: [Data] = [
            channelSeed,
            payer.bytes,
            payee.bytes,
            mint.bytes,
            authorizedSigner.bytes,
            littleEndian(salt),
        ]
        return try ProgramDerivedAddress.find(seeds: seeds, programId: programId).address
    }

    public static func findEventAuthorityPda(programId: Pubkey) throws -> Pubkey {
        try ProgramDerivedAddress.find(seeds: [eventAuthoritySeed], programId: programId).address
    }

    /// Generate a random `u64` channel salt so concurrent opens derive distinct
    /// channel PDAs. Mirrors `random_salt`/`unique_salt` on the spine.
    public static func uniqueSalt() -> UInt64 {
        UInt64.random(in: UInt64.min...UInt64.max)
    }

    // MARK: - Open instruction + transaction

    public static func buildOpenInstruction(_ params: OpenChannelParams) throws -> SolanaInstruction {
        let channel = try findChannelPda(
            payer: params.payer,
            payee: params.payee,
            mint: params.mint,
            authorizedSigner: params.authorizedSigner,
            salt: params.salt,
            programId: params.programId
        )
        let payerTokenAccount = try AssociatedTokenAccount.address(
            owner: params.payer, mint: params.mint, tokenProgram: params.tokenProgram
        )
        let channelTokenAccount = try AssociatedTokenAccount.address(
            owner: channel, mint: params.mint, tokenProgram: params.tokenProgram
        )
        let eventAuthority = try findEventAuthorityPda(programId: params.programId)

        // Account order matches the codama-generated `Open` builder exactly.
        // `rentPayer` (operator / fee payer) sits right after `payer` as a
        // second writable signer; everything after it shifts by +1 (14 total).
        let accounts: [AccountMeta] = [
            .writableSigner(params.payer),
            .writableSigner(params.rentPayer),
            .readonly(params.payee),
            .readonly(params.mint),
            .readonly(params.authorizedSigner),
            .writable(channel),
            .writable(payerTokenAccount),
            .writable(channelTokenAccount),
            .readonly(params.tokenProgram),
            .readonly(.systemProgram),
            .readonly(.sysvarRent),
            .readonly(.associatedTokenProgram),
            .readonly(eventAuthority),
            .readonly(params.programId),
        ]

        // data = discriminator(1) || borsh(OpenArgs { salt, deposit, gracePeriod, recipients }).
        var data = Data([openDiscriminator])
        data.append(littleEndian(params.salt))
        data.append(littleEndian(params.deposit))
        data.append(littleEndian(params.gracePeriod))
        data.append(littleEndian(UInt32(params.recipients.count)))
        for entry in params.recipients {
            data.append(entry.recipient.bytes)
            data.append(littleEndian(entry.bps))
        }

        return SolanaInstruction(programId: params.programId, accounts: accounts, data: data)
    }

    /// Build a payer-signed (fee-payer-unsigned) channel `open` transaction. The
    /// `payer` signs to authorize the deposit; the `feePayer` (operator) slot is
    /// left empty for the server to co-sign before broadcast. Returns the derived
    /// channel PDA and the base64-encoded transaction.
    public static func buildOpenTransaction(
        payer: SolanaSigner,
        payee: Pubkey,
        mint: Pubkey,
        authorizedSigner: Pubkey,
        salt: UInt64,
        deposit: UInt64,
        gracePeriod: UInt32,
        recipients: [Distribution],
        tokenProgram: Pubkey,
        programId: Pubkey,
        feePayer: Pubkey,
        recentBlockhash: Data
    ) async throws -> OpenTransaction {
        let payerPubkey = try Pubkey(bytes: payer.publicKey)
        let params = OpenChannelParams(
            payer: payerPubkey,
            // rentPayer is always the operator / fee payer already in scope.
            rentPayer: feePayer,
            payee: payee,
            mint: mint,
            authorizedSigner: authorizedSigner,
            salt: salt,
            deposit: deposit,
            gracePeriod: gracePeriod,
            recipients: recipients,
            tokenProgram: tokenProgram,
            programId: programId
        )
        let channelId = try findChannelPda(
            payer: payerPubkey,
            payee: payee,
            mint: mint,
            authorizedSigner: authorizedSigner,
            salt: salt,
            programId: programId
        )
        let instruction = try buildOpenInstruction(params)
        let message = try TransactionBuilder.compile(
            version: .legacy,
            feePayer: feePayer,
            instructions: [instruction],
            recentBlockhash: recentBlockhash
        )
        let signature = try await payer.sign(message: message.serialize())
        guard signature.count == Ed25519.signatureLength else {
            throw MppError.signingFailure("payment-channel open signature must be 64 bytes, got \(signature.count)")
        }
        guard let signerIndex = message.accountKeys.firstIndex(of: payerPubkey) else {
            throw MppError.invalidTransaction("payer is not in the open transaction account list")
        }
        var signatures = SignedTransaction.emptySignatureSlots(count: Int(message.header.numRequiredSignatures))
        // The payer must land in the signer prefix of the account list; guard the
        // subscript so a non-signer index throws instead of crashing.
        guard signerIndex < signatures.count else {
            throw MppError.invalidTransaction("payer signer index \(signerIndex) is outside the required-signer range")
        }
        signatures[signerIndex] = signature
        let transaction = try SignedTransaction(signatures: signatures, message: message)
        return OpenTransaction(channelId: channelId, transaction: transaction.serialize().base64EncodedString())
    }

    // MARK: - Little-endian helpers

    static func littleEndian(_ value: UInt64) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }

    static func littleEndian(_ value: UInt32) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }

    static func littleEndian(_ value: UInt16) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }
}
