import Foundation

// MARK: - Charge transaction provider (PR #83 abstraction)

/// Provides an already-signed base64 transaction for a charge request.
/// Preserved verbatim from PR #83 for callers that build their own
/// Solana transactions and just want the MPP credential framing.
public protocol ChargeTransactionProviding: Sendable {
    func buildTransaction(for request: ChargeRequest) async throws -> String
}

public struct StaticChargeTransactionProvider: ChargeTransactionProviding, Sendable {
    private let transaction: String

    public init(transaction: String) {
        self.transaction = transaction
    }

    public func buildTransaction(for request: ChargeRequest) async throws -> String {
        transaction
    }
}

public struct ChargeCredentialBuilder: Sendable {
    private let transactionProvider: any ChargeTransactionProviding

    public init(transactionProvider: any ChargeTransactionProviding) {
        self.transactionProvider = transactionProvider
    }

    public func authorizationHeader(for challenge: PaymentChallenge) async throws -> String {
        try challenge.requireSolanaCharge()

        let transaction = try await transactionProvider.buildTransaction(for: challenge.chargeRequest)
        let credential = PaymentCredential(
            challenge: challenge.echo(),
            payload: .transaction(transaction)
        )
        return try MppHeaders.formatAuthorization(credential)
    }
}

// MARK: - Full wire-signing charge client

/// High-level entry points for the Solana charge client. Mirrors the
/// Rust spine `solana_mpp::client::charge` and the TypeScript canonical
/// `Charge.ts`: parse a `WWW-Authenticate: Payment ...` header (or pick
/// one from a multi-challenge response), build the signed transaction
/// for the decoded `ChargeRequest`, and emit the `Authorization:
/// Payment ...` header value.
public enum Charge {
    public struct Options: Sendable {
        public var computeUnitLimit: UInt32
        public var computeUnitPrice: UInt64

        public init(computeUnitLimit: UInt32 = 200_000, computeUnitPrice: UInt64 = 1) {
            self.computeUnitLimit = computeUnitLimit
            self.computeUnitPrice = computeUnitPrice
        }
    }

    /// Returns the first solana + charge challenge in a list of raw
    /// `WWW-Authenticate` header values whose embedded `ChargeRequest`
    /// also decodes cleanly. The spine returns multi-value
    /// `WWW-Authenticate` for the same resource (e.g. one challenge per
    /// supported stablecoin); the client picks the first compatible one.
    ///
    /// Decoding the request during selection avoids choosing a
    /// structurally valid header whose payload is malformed JSON or
    /// missing required fields, which would otherwise surface as a late
    /// failure inside `buildChargeTransaction`.
    public static func pickChallenge(wwwAuthenticateHeaders: [String]) throws -> PaymentChallenge {
        for header in wwwAuthenticateHeaders {
            guard let challenge = try? MppHeaders.parseWWWAuthenticate(header),
                  challenge.method == "solana", challenge.intent == "charge" else {
                continue
            }
            // Schema-validate the embedded ChargeRequest before
            // returning. A challenge whose request payload does not
            // decode is not compatible, even if the header framing is.
            guard (try? challenge.chargeRequest) != nil else { continue }
            return challenge
        }
        throw MppError.unsupportedChallenge(method: "(missing)", intent: "(missing)")
    }

    /// Resolves a currency string (symbol or mint) to a mint base58 or
    /// `nil` for native SOL. Mirrors `protocol::solana::resolve_stablecoin_mint`.
    public static func resolveStablecoinMint(currency: String, network: String?) -> String? {
        switch currency.uppercased() {
        case "SOL": return nil
        case "USDC":
            switch network {
            case "devnet": return "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
            case "testnet": return "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
            default: return "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
            }
        case "USDT": return "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
        case "USDG":
            switch network {
            case "devnet", "testnet": return "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
            default: return "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
            }
        case "PYUSD":
            switch network {
            case "devnet", "testnet": return "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
            default: return "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
            }
        case "CASH": return "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"
        default: return currency
        }
    }

    /// Builds and signs the Solana transaction for an MPP charge request,
    /// returning the base64-encoded wire transaction. Mirrors the Rust
    /// `build_charge_transaction_with_options` entry point.
    ///
    /// `recentBlockhash` is taken from `methodDetails.recentBlockhash`
    /// when present; otherwise the optional `rpc` argument is used to
    /// fetch one. The interop harness always provides
    /// `recentBlockhash`, so `rpc` is only needed for ad-hoc callers.
    public static func buildChargeTransaction(
        request: ChargeRequest,
        signer: any SolanaSigner,
        rpc: RpcClient? = nil,
        options: Options = Options()
    ) async throws -> String {
        let methodDetails = request.methodDetails
        let signerPubkey = try Pubkey(bytes: signer.publicKey)
        let recipientPubkey = try Pubkey(base58: request.recipient)

        let amount = try parseU64(request.amount, field: "amount")
        let splits = methodDetails.splits ?? []
        // Spine cap: Rust (`rust/src/client/charge.rs`) and TypeScript
        // (`typescript/packages/mpp/src/server/Charge.ts`) both reject
        // requests with more than 8 splits. Enforce here so Swift never
        // signs a credential the verifier will reject.
        guard splits.count <= 8 else {
            throw MppError.invalidTransaction("too many splits: \(splits.count) > 8")
        }
        var splitsTotal: UInt64 = 0
        for split in splits {
            let value = try parseU64(split.amount, field: "split amount")
            let (sum, overflow) = splitsTotal.addingReportingOverflow(value)
            guard !overflow else {
                throw MppError.invalidTransaction("splits total overflows u64")
            }
            splitsTotal = sum
        }
        guard splitsTotal < amount else {
            throw MppError.invalidTransaction(
                "Splits consume the entire amount; primary recipient must receive a positive amount"
            )
        }
        let primaryAmount = amount - splitsTotal

        let mint = resolveStablecoinMint(currency: request.currency, network: methodDetails.network)
        let hasAtaCreationSplits = splits.contains { $0.ataCreationRequired == true }
        if hasAtaCreationSplits {
            guard let mintStr = mint else {
                throw MppError.invalidTransaction("ataCreationRequired requires an SPL token charge")
            }
            // Spine parity: Rust (`rust/src/server/charge.rs`
            // `validate_charge_options`) requires the request currency to
            // be the resolved mint address itself, not a symbol like
            // "USDC". Symbol-form charges with `ataCreationRequired`
            // would be rejected by Rust/TS verifiers, so reject them
            // client-side too instead of signing a credential that fails
            // downstream.
            guard mintStr == request.currency, isLikelyBase58MintAddress(mintStr) else {
                throw MppError.invalidTransaction(
                    "ataCreationRequired requires currency to be an SPL token mint address (got \"\(request.currency)\")"
                )
            }
        }

        let serverPaysFees = methodDetails.feePayer == true
        let feePayerPubkey: Pubkey?
        if serverPaysFees {
            guard let key = methodDetails.feePayerKey else {
                throw MppError.invalidTransaction("feePayer=true requires feePayerKey in methodDetails")
            }
            feePayerPubkey = try Pubkey(base58: key)
        } else {
            feePayerPubkey = nil
        }
        let actualFeePayer = feePayerPubkey ?? signerPubkey

        var instructions: [SolanaInstruction] = []
        instructions.append(Instructions.computeBudgetSetUnitPrice(microLamports: options.computeUnitPrice))
        instructions.append(Instructions.computeBudgetSetUnitLimit(units: options.computeUnitLimit))

        if let mintStr = mint {
            let mintPk = try Pubkey(base58: mintStr)
            let tokenProgram = try await resolveTokenProgram(
                methodDetails: methodDetails,
                mintBase58: mintStr,
                rpc: rpc
            )
            let rawDecimals = methodDetails.decimals ?? 6
            guard rawDecimals >= 0, rawDecimals <= 255 else {
                // SPL TokenChecked encodes decimals as u8; an out-of-range
                // server value must not crash the client (would `UInt8(_:)`
                // trap on a negative or oversized Int). Surface as a domain
                // error so the caller sees a clean failure instead of a
                // SIGTRAP.
                throw MppError.invalidTransaction(
                    "methodDetails.decimals out of range [0, 255]: \(rawDecimals)"
                )
            }
            let decimals = UInt8(rawDecimals)
            let sourceAta = try AssociatedTokenAccount.address(
                owner: signerPubkey,
                mint: mintPk,
                tokenProgram: tokenProgram
            )
            // Primary recipient transfer (no ATA creation for primary).
            try appendSplTransfer(
                into: &instructions,
                payer: actualFeePayer,
                serverPaysFees: serverPaysFees,
                signer: signerPubkey,
                sourceAta: sourceAta,
                mint: mintPk,
                tokenProgram: tokenProgram,
                destinationOwner: recipientPubkey,
                amount: primaryAmount,
                decimals: decimals,
                createAta: false
            )
            try appendMemo(into: &instructions, memo: request.externalId)

            for split in splits {
                let destinationOwner = try Pubkey(base58: split.recipient)
                let splitAmount = try parseU64(split.amount, field: "split amount")
                // Spine semantics: when no server fee payer, every split
                // owner gets an idempotent ATA-create; when server pays
                // fees, only splits with ataCreationRequired == true do.
                let createAta = !serverPaysFees || split.ataCreationRequired == true
                try appendSplTransfer(
                    into: &instructions,
                    payer: actualFeePayer,
                    serverPaysFees: serverPaysFees,
                    signer: signerPubkey,
                    sourceAta: sourceAta,
                    mint: mintPk,
                    tokenProgram: tokenProgram,
                    destinationOwner: destinationOwner,
                    amount: splitAmount,
                    decimals: decimals,
                    createAta: createAta
                )
                try appendMemo(into: &instructions, memo: split.memo)
            }
        } else {
            // Native SOL path.
            instructions.append(Instructions.systemTransfer(
                from: signerPubkey,
                to: recipientPubkey,
                lamports: primaryAmount
            ))
            try appendMemo(into: &instructions, memo: request.externalId)

            for split in splits {
                let destination = try Pubkey(base58: split.recipient)
                let splitAmount = try parseU64(split.amount, field: "split amount")
                instructions.append(Instructions.systemTransfer(
                    from: signerPubkey,
                    to: destination,
                    lamports: splitAmount
                ))
                try appendMemo(into: &instructions, memo: split.memo)
            }
        }

        // Resolve the blockhash. Method-details takes precedence; fall
        // back to the RPC client if provided.
        let blockhash: Data
        if let bh = methodDetails.recentBlockhash {
            let decoded = try Base58.decode(bh)
            guard decoded.count == 32 else {
                throw MppError.invalidTransaction("recentBlockhash decodes to \(decoded.count) bytes, expected 32")
            }
            blockhash = decoded
        } else if let rpc = rpc {
            blockhash = try await rpc.getLatestBlockhash().bytes
        } else {
            throw MppError.invalidTransaction(
                "methodDetails.recentBlockhash is required when no RPC client is provided"
            )
        }

        // Compile + sign (legacy message form, matching the spine).
        let message = try TransactionBuilder.compile(
            version: .legacy,
            feePayer: actualFeePayer,
            instructions: instructions,
            recentBlockhash: blockhash
        )

        let messageBytes = message.serialize()
        let signature = try await signer.sign(message: messageBytes)
        guard signature.count == 64 else {
            throw MppError.signingFailure("signer returned \(signature.count) bytes, expected 64")
        }

        // Place the signer's signature at its index in the account keys
        // array. Other required signers (notably the server fee payer)
        // get a zero-filled placeholder signature; the server fills it
        // in before broadcasting.
        var signatures = SignedTransaction.emptySignatureSlots(count: Int(message.header.numRequiredSignatures))
        guard let signerIndex = message.accountKeys.firstIndex(of: signerPubkey) else {
            throw MppError.signingFailure("signer pubkey is not in the account keys")
        }
        guard signerIndex < signatures.count else {
            throw MppError.signingFailure("signer index \(signerIndex) exceeds required signature count")
        }
        signatures[signerIndex] = signature

        let signedTx = try SignedTransaction(signatures: signatures, message: message)
        return signedTx.serialize().base64EncodedString()
    }

    /// Builds the pull-mode `Authorization: Payment ...` header value
    /// for a charge challenge. The client signs the transaction; the
    /// server broadcasts it.
    public static func buildPullCredential(
        challenge: PaymentChallenge,
        signer: any SolanaSigner,
        rpc: RpcClient? = nil,
        options: Options = Options()
    ) async throws -> String {
        try challenge.requireSolanaCharge()
        let request = try challenge.chargeRequest
        let encodedTx = try await buildChargeTransaction(
            request: request,
            signer: signer,
            rpc: rpc,
            options: options
        )
        let credential = PaymentCredential(
            challenge: challenge.echo(),
            payload: .transaction(encodedTx)
        )
        return try MppHeaders.formatAuthorization(credential)
    }

    // MARK: - Internal helpers

    private static func resolveTokenProgram(
        methodDetails: SolanaChargeMethodDetails,
        mintBase58: String,
        rpc: RpcClient?
    ) async throws -> Pubkey {
        if let explicit = methodDetails.tokenProgram {
            let pk = try Pubkey(base58: explicit)
            if pk == .tokenProgram || pk == .token2022Program { return pk }
            throw MppError.invalidTransaction("unsupported tokenProgram \(explicit)")
        }
        // No explicit token program: mirror the Rust client and resolve
        // the program id by reading the mint account's owner field. A
        // hard-coded allow-list (the previous behaviour) silently
        // mis-derives ATAs for any Token-2022 mint that is not in the
        // set, so we either query the mint account or reject the
        // challenge with a clean error.
        guard let rpc = rpc else {
            throw MppError.invalidTransaction(
                "methodDetails.tokenProgram omitted and no RpcClient was provided to resolve mint \(mintBase58)"
            )
        }
        let ownerStr = try await rpc.getAccountOwner(pubkeyBase58: mintBase58)
        let owner = try Pubkey(base58: ownerStr)
        guard owner == .tokenProgram || owner == .token2022Program else {
            throw MppError.invalidTransaction(
                "mint \(mintBase58) is owned by unsupported program \(ownerStr)"
            )
        }
        return owner
    }

    private static func appendSplTransfer(
        into instructions: inout [SolanaInstruction],
        payer: Pubkey,
        serverPaysFees: Bool,
        signer: Pubkey,
        sourceAta: Pubkey,
        mint: Pubkey,
        tokenProgram: Pubkey,
        destinationOwner: Pubkey,
        amount: UInt64,
        decimals: UInt8,
        createAta: Bool
    ) throws {
        let destAta = try AssociatedTokenAccount.address(
            owner: destinationOwner,
            mint: mint,
            tokenProgram: tokenProgram
        )
        if createAta {
            instructions.append(
                Instructions.createAssociatedTokenAccount(
                    payer: payer,
                    ata: destAta,
                    owner: destinationOwner,
                    mint: mint,
                    tokenProgram: tokenProgram,
                    idempotent: true
                )
            )
        }
        instructions.append(Instructions.splTransferChecked(
            programId: tokenProgram,
            source: sourceAta,
            mint: mint,
            destination: destAta,
            authority: signer,
            amount: amount,
            decimals: decimals
        ))
    }

    private static func appendMemo(into instructions: inout [SolanaInstruction], memo: String?) throws {
        guard let memo = memo, !memo.isEmpty else { return }
        instructions.append(try Instructions.memo(memo))
    }

    private static func parseU64(_ value: String, field: String) throws -> UInt64 {
        guard let parsed = UInt64(value) else {
            throw MppError.invalidTransaction("\(field) \"\(value)\" is not a u64")
        }
        return parsed
    }

    /// Heuristic check that a string is plausibly a base58-encoded
    /// 32-byte Solana mint address. Avoids round-tripping through
    /// `Base58.decode` for hot paths but is strict enough to reject
    /// short symbols like "USDC" or empty strings that
    /// `resolveStablecoinMint` would have passed through unchanged.
    private static func isLikelyBase58MintAddress(_ value: String) -> Bool {
        guard (32...44).contains(value.count) else { return false }
        return (try? Pubkey(base58: value)) != nil
    }
}
