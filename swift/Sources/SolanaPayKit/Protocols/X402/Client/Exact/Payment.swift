import Foundation

// MARK: - x402 exact challenge parsing and payment building

/// ComputeBudget SetComputeUnitLimit units for x402 exact transactions.
///
/// Canonical value from the rust spine
/// (`rust/crates/x402/src/client/exact/payment.rs:56`). The MPP charge
/// client uses 200_000 for its own transactions; x402 uses 20_000.
let X402ComputeUnitLimit: UInt32 = 20_000

/// ComputeBudget SetComputeUnitPrice micro-lamports.
let X402ComputeUnitPrice: UInt64 = 1

/// Default SPL decimals when the offer omits `extra.decimals`.
let X402DefaultDecimals: UInt8 = 6

// MARK: - Challenge parsing

/// Parse an x402 challenge from response headers and/or body, applying the
/// client's network + currency-preference selection.
///
/// Checks (in order):
/// 1. `PAYMENT-REQUIRED` header containing standard-base64 JSON.
/// 2. Response body with `{ "accepts": [...] }`.
///
/// Returns `nil` when no supported Solana x402 exact offer matches.
/// Mirrors the rust `parse_x402_challenge_with_selection`.
public func parseX402Challenge(
    headers: [(name: String, value: String)],
    body: String?,
    selection: X402ChallengeSelection = X402ChallengeSelection()
) -> X402AcceptsEntry? {
    if let headerValue = headers.first(where: { $0.name.lowercased() == "payment-required" })?.value,
       let offer = _selectFromHeader(headerValue, selection: selection) {
        return offer
    }

    if let body = body,
       let offer = _selectFromBody(body, selection: selection) {
        return offer
    }

    return nil
}

// MARK: - Payment header building

/// x402 exact Memo size cap, matching the spec MAX (256 bytes UTF-8).
///
/// The x402 spec limits the memo field to 256 bytes. This is more
/// conservative than the SPL Memo program's own limit (566 bytes).
let X402MemoMaxBytes: Int = 256

/// Build the standard-base64 `Payment-Signature` header value for an x402
/// exact offer.
///
/// Transaction shape (v0, fee-payer from `extra.feePayer` or client):
///   1. `ComputeBudgetSetUnitLimit(20_000)`
///   2. `ComputeBudgetSetUnitPrice(1)`
///   3. `splTransferChecked` (SPL) **or** `systemTransfer` (native SOL)
///   4. Memo instruction: `extra.memo` when present, else a random 16-byte
///      hex-encoded nonce (always appended to guarantee transaction
///      uniqueness). Mirrors the Rust `build_payment_transaction` which
///      generates a random nonce when `extra.memo` is absent.
///
/// Blockhash: `offer.extra.recentBlockhash` when present, else
/// `rpc.getLatestBlockhash()`.
///
/// The output is standard base64 (not base64url); the header name is
/// `Payment-Signature`.
///
/// - Parameters:
///   - nonceGenerator: Optional closure that returns 16 random bytes.
///     Defaults to `SystemRandomNumberGenerator`. Pass a fixed value in
///     tests to make the output deterministic.
public func buildX402PaymentHeader(
    signer: any SolanaSigner,
    rpc: RpcClient,
    offer: X402AcceptsEntry,
    nonceGenerator: (() -> Data)? = nil
) async throws -> String {
    let payload = try await _buildPaymentPayload(
        signer: signer, rpc: rpc, offer: offer, nonceGenerator: nonceGenerator
    )
    let envelope = X402PaymentSignatureEnvelope(
        x402Version: X402Version,
        accepted: offer,
        payload: payload
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let json = try encoder.encode(envelope)
    return json.base64EncodedString()
}

// MARK: - Internal payment builder

private func _buildPaymentPayload(
    signer: any SolanaSigner,
    rpc: RpcClient,
    offer: X402AcceptsEntry,
    nonceGenerator: (() -> Data)? = nil
) async throws -> X402PaymentPayload {
    guard let amountStr = offer.effectiveAmount, let amount = UInt64(amountStr) else {
        throw MppError.invalidTransaction(
            "x402 offer has missing or invalid amount: \(offer.effectiveAmount ?? "nil")"
        )
    }
    guard let payToStr = offer.effectivePayTo, !payToStr.isEmpty else {
        throw MppError.invalidTransaction("x402 offer is missing payTo / recipient")
    }
    guard let assetStr = offer.effectiveAsset, !assetStr.isEmpty else {
        throw MppError.invalidTransaction("x402 offer is missing asset")
    }

    let signerPubkey = try Pubkey(bytes: signer.publicKey)
    let recipientPubkey = try Pubkey(base58: payToStr)

    // Managed fee payer: prefer the top-level `feePayerKey`, then the nested
    // `extra.feePayer` alias, gated by the `feePayer` toggle (rust types.rs
    // normalization). When absent, the local signer pays.
    let feePayerPubkey: Pubkey
    if let fpStr = offer.effectiveFeePayerKey {
        feePayerPubkey = try Pubkey(base58: fpStr)
    } else {
        feePayerPubkey = signerPubkey
    }

    var instructions: [SolanaInstruction] = []
    instructions.append(Instructions.computeBudgetSetUnitLimit(units: X402ComputeUnitLimit))
    instructions.append(Instructions.computeBudgetSetUnitPrice(microLamports: X402ComputeUnitPrice))

    let clusterLabel = SolanaNetwork.clusterLabel(for: offer.network)
    let mintAddress = Mints.resolveMint(currency: assetStr, cluster: clusterLabel)

    if let mintStr = mintAddress {
        // Default the token program from the currency (Token vs Token-2022)
        // when the offer omits `extra.tokenProgram`, so Token-2022 mints
        // (USDG / PYUSD / CASH) derive the correct ATA. Mirrors rust
        // `default_token_program_for_currency`.
        let tokenProgramStr = offer.effectiveTokenProgram
            ?? Mints.defaultTokenProgram(currency: assetStr, cluster: clusterLabel)
        let tokenProgram = try Pubkey(base58: tokenProgramStr)
        let mint = try Pubkey(base58: mintStr)
        let decimals: UInt8
        if let d = offer.effectiveDecimals, d >= 0, d <= 255 {
            decimals = UInt8(d)
        } else {
            decimals = X402DefaultDecimals
        }
        let sourceAta = try AssociatedTokenAccount.address(
            owner: signerPubkey, mint: mint, tokenProgram: tokenProgram
        )
        let destAta = try AssociatedTokenAccount.address(
            owner: recipientPubkey, mint: mint, tokenProgram: tokenProgram
        )
        instructions.append(Instructions.splTransferChecked(
            programId: tokenProgram,
            source: sourceAta,
            mint: mint,
            destination: destAta,
            authority: signerPubkey,
            amount: amount,
            decimals: decimals
        ))
    } else {
        instructions.append(Instructions.systemTransfer(
            from: signerPubkey, to: recipientPubkey, lamports: amount
        ))
    }

    try _appendX402Memo(into: &instructions, offer: offer, nonceGenerator: nonceGenerator)

    // Blockhash: prefer offer's stamp; fall back to RPC.
    let blockhash: Data
    if let bhStr = offer.effectiveRecentBlockhash {
        let decoded = try Base58.decode(bhStr)
        guard decoded.count == 32 else {
            throw MppError.invalidTransaction(
                "x402 recentBlockhash decodes to \(decoded.count) bytes, expected 32"
            )
        }
        blockhash = decoded
    } else {
        blockhash = try await rpc.getLatestBlockhash().bytes
    }

    // Compile v0 message.
    let message = try TransactionBuilder.compile(
        version: .v0,
        feePayer: feePayerPubkey,
        instructions: instructions,
        recentBlockhash: blockhash
    )

    let messageBytes = message.serialize()
    let signature = try await signer.sign(message: messageBytes)
    guard signature.count == 64 else {
        throw MppError.signingFailure("signer returned \(signature.count) bytes, expected 64")
    }

    var signatures = SignedTransaction.emptySignatureSlots(
        count: Int(message.header.numRequiredSignatures)
    )
    guard let signerIndex = message.accountKeys.firstIndex(of: signerPubkey) else {
        throw MppError.signingFailure("signer pubkey not found in transaction accounts")
    }
    guard signerIndex < signatures.count else {
        throw MppError.signingFailure(
            "signer index \(signerIndex) exceeds required signature count"
        )
    }
    signatures[signerIndex] = signature

    let signedTx = try SignedTransaction(signatures: signatures, message: message)
    return X402PaymentPayload(transaction: signedTx.serialize().base64EncodedString())
}

/// Append a Memo instruction to every x402 payment transaction.
///
/// When `offer.extra.memo` is present, use it as the memo text (the Rust
/// verifier asserts the memo equals the stamped value). When absent,
/// generate a random 16-byte nonce and hex-encode it as UTF-8 to make
/// the transaction unique and prevent replay of otherwise-identical
/// payments. Mirrors the Rust `build_payment_transaction` memo path.
///
/// The memo is capped at `X402MemoMaxBytes` (256 bytes UTF-8).
///
/// - Parameter nonceGenerator: A closure producing 16 random bytes.
///   Pass a deterministic value in tests; defaults to
///   `SystemRandomNumberGenerator`.
private func _appendX402Memo(
    into instructions: inout [SolanaInstruction],
    offer: X402AcceptsEntry,
    nonceGenerator: (() -> Data)? = nil
) throws {
    let memoText: String
    if let memo = offer.extraString("memo") {
        memoText = memo
    } else {
        // Generate a random 16-byte nonce and hex-encode it.
        let nonceBytes: Data
        if let generator = nonceGenerator {
            nonceBytes = generator()
        } else {
            var rng = SystemRandomNumberGenerator()
            var bytes = [UInt8](repeating: 0, count: 16)
            for i in 0..<16 { bytes[i] = rng.next() }
            nonceBytes = Data(bytes)
        }
        memoText = nonceBytes.map { String(format: "%02x", $0) }.joined()
    }
    let memoBytes = Data(memoText.utf8)
    guard memoBytes.count <= X402MemoMaxBytes else {
        throw MppError.invalidTransaction(
            "x402 memo exceeds \(X402MemoMaxBytes) bytes"
        )
    }
    instructions.append(SolanaInstruction(
        programId: .memoProgram,
        accounts: [],
        data: memoBytes
    ))
}

// MARK: - Selection helpers

private func _selectFromHeader(
    _ headerValue: String,
    selection: X402ChallengeSelection
) -> X402AcceptsEntry? {
    guard let data = Data(base64Encoded: headerValue),
          let envelope = try? JSONDecoder().decode(X402PaymentRequiredEnvelope.self, from: data)
    else { return nil }
    return _selectRequirement(from: envelope.accepts, selection: selection)
}

private func _selectFromBody(
    _ body: String,
    selection: X402ChallengeSelection
) -> X402AcceptsEntry? {
    guard let data = body.data(using: .utf8),
          let envelope = try? JSONDecoder().decode(X402PaymentRequiredEnvelope.self, from: data)
    else { return nil }
    return _selectRequirement(from: envelope.accepts, selection: selection)
}

private func _selectRequirement(
    from accepts: [X402AcceptsEntry],
    selection: X402ChallengeSelection
) -> X402AcceptsEntry? {
    let preferredNetwork = SolanaNetwork.caip2(for: selection.network)
    let clusterLabel = SolanaNetwork.clusterLabel(for: preferredNetwork)

    let solana = accepts.filter { _isSolanaExact($0) }
    let onPreferred = solana.filter { $0.network == preferredNetwork }

    if let currencies = selection.currencies {
        for wanted in currencies {
            for offer in onPreferred {
                if let asset = offer.effectiveAsset,
                   _currenciesMatch(offered: asset, accepted: wanted, label: clusterLabel) {
                    return offer
                }
            }
        }
        return nil
    }

    let candidates = onPreferred.isEmpty ? solana : onPreferred
    return candidates.min(by: { _effectiveAmountOf($0) < _effectiveAmountOf($1) })
}

private func _isSolanaExact(_ offer: X402AcceptsEntry) -> Bool {
    // Require an explicit `scheme == "exact"` (python parity): offers
    // without a scheme, or with a different scheme, are not eligible.
    guard offer.scheme == "exact" else { return false }
    return offer.network == SolanaNetwork.mainnet
        || offer.network == SolanaNetwork.devnet
        || offer.network == SolanaNetwork.testnet
}

private func _effectiveAmountOf(_ offer: X402AcceptsEntry) -> UInt64 {
    UInt64(offer.effectiveAmount ?? "") ?? UInt64.max
}

private func _currenciesMatch(offered: String, accepted: String, label: String) -> Bool {
    let offeredMint = Mints.resolveMint(currency: offered, cluster: label) ?? offered
    let acceptedMint = Mints.resolveMint(currency: accepted, cluster: label) ?? accepted
    return offeredMint == acceptedMint
}
