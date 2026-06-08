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

/// A selected x402 offer together with the protocol version the server's
/// challenge declared. The version drives which payment shape the client
/// emits in reply: legacy `X-PAYMENT` when the challenge declared `1`,
/// otherwise the canonical `PAYMENT-SIGNATURE`.
public struct X402ParsedChallenge: Sendable {
    /// The selected offer to pay.
    public let offer: X402AcceptsEntry
    /// The `x402Version` the challenge declared, or `nil` when the source
    /// (e.g. a bare express body) carried no version. A `nil` or non-1
    /// version keeps the canonical producer; only an explicit `1` selects
    /// the legacy producer.
    public let declaredVersion: Int?

    public init(offer: X402AcceptsEntry, declaredVersion: Int?) {
        self.offer = offer
        self.declaredVersion = declaredVersion
    }
}

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
    parseX402ChallengeWithVersion(headers: headers, body: body, selection: selection)?.offer
}

/// Parse an x402 challenge and surface the version it declared.
///
/// Source precedence mirrors the rust client
/// (client/exact/payment.rs:232-262):
/// 1. canonical `PAYMENT-REQUIRED` header (standard-base64 JSON);
/// 2. legacy `X-PAYMENT-REQUIRED` header (RAW JSON per the rust spine; a
///    base64 envelope is also accepted for robustness);
/// 3. the 402 JSON body (`{ "accepts": [...] }`), legacy/express fallback.
///
/// The legacy header and body carry plain SVM network slugs and
/// `maxAmountRequired`; both are handled natively by the same selection +
/// `effective*` accessors. Returns `nil` when no supported Solana exact
/// offer matches.
public func parseX402ChallengeWithVersion(
    headers: [(name: String, value: String)],
    body: String?,
    selection: X402ChallengeSelection = X402ChallengeSelection()
) -> X402ParsedChallenge? {
    func header(_ name: String) -> String? {
        headers.first { $0.name.lowercased() == name.lowercased() }?.value
    }

    if let value = header(X402PaymentRequiredHeaderName),
       let parsed = _selectFromHeader(value, selection: selection) {
        return parsed
    }

    // The rust spine parses X-PAYMENT-REQUIRED as RAW JSON
    // (client/exact/payment.rs: serde_json::from_str on the header value),
    // not base64. Accept a base64 envelope first, then fall back to raw JSON
    // (rust parity), so we interoperate with either producer.
    if let value = header(X402LegacyPaymentRequiredHeader),
       let parsed = _selectFromHeader(value, selection: selection)
        ?? _selectFromBody(value, selection: selection) {
        return parsed
    }

    if let body = body,
       let parsed = _selectFromBody(body, selection: selection) {
        return parsed
    }

    return nil
}

/// Canonical v2 server challenge header name (lower-cased compare).
let X402PaymentRequiredHeaderName = "PAYMENT-REQUIRED"

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
    return try _encodePaymentEnvelope(envelope)
}

/// Build the standard-base64 legacy `X-PAYMENT` header value for an x402
/// exact offer.
///
/// The legacy envelope is `{ x402Version: 1, scheme: "exact",
/// network: <plain SVM slug>, payload: { transaction } }` — `scheme` and
/// `network` are top-level siblings of `payload` and there is NO `accepted`
/// object (the legacy wire binds only scheme + network, unlike the canonical
/// shape). The network is the plain slug (`solana` / `solana-devnet`), never
/// the CAIP-2 id. Mirrors rust `build_payment_header_v1`
/// (client/exact/payment.rs:153-170) + `v1_network_for_requirements`
/// (payment.rs:393-404).
///
/// The transaction is built identically to the canonical path (same
/// compute-budget + transfer + memo instructions); only the envelope shape
/// differs. The output is standard base64 (not base64url).
public func buildX402LegacyPaymentHeader(
    signer: any SolanaSigner,
    rpc: RpcClient,
    offer: X402AcceptsEntry,
    nonceGenerator: (() -> Data)? = nil
) async throws -> String {
    let payload = try await _buildPaymentPayload(
        signer: signer, rpc: rpc, offer: offer, nonceGenerator: nonceGenerator
    )
    let envelope = X402PaymentSignatureEnvelope(
        x402Version: X402VersionLegacy,
        scheme: "exact",
        network: SolanaNetwork.legacySlug(for: offer.network),
        accepted: nil,
        payload: payload
    )
    return try _encodePaymentEnvelope(envelope)
}

/// Build the payment header for the version the server's challenge declared.
///
/// Dispatches to the legacy `X-PAYMENT` producer when `x402Version == 1`,
/// otherwise to the canonical `PAYMENT-SIGNATURE` producer. The canonical
/// shape stays the default (`nil` / any non-1 version), so adding legacy
/// support does not flip the default emitter. Mirrors the rust client, where
/// the default producer is `build_payment_header` (v2) and `build_payment_
/// header_v1` is emitted only for legacy peers.
///
/// - Returns: the base64 header value and the header name to set it under
///   (`X-PAYMENT` for legacy, `PAYMENT-SIGNATURE` otherwise).
public func buildX402PaymentForChallenge(
    signer: any SolanaSigner,
    rpc: RpcClient,
    offer: X402AcceptsEntry,
    declaredVersion: Int?,
    nonceGenerator: (() -> Data)? = nil
) async throws -> (headerName: String, value: String) {
    if declaredVersion == X402VersionLegacy {
        let value = try await buildX402LegacyPaymentHeader(
            signer: signer, rpc: rpc, offer: offer, nonceGenerator: nonceGenerator
        )
        return (X402LegacyPaymentHeader, value)
    }
    let value = try await buildX402PaymentHeader(
        signer: signer, rpc: rpc, offer: offer, nonceGenerator: nonceGenerator
    )
    return (X402PaymentHeader, value)
}

/// Encode a payment envelope to a standard-base64 header value.
///
/// Sorted keys for deterministic output. Standard base64 (padded), matching
/// the rust producer's `general_purpose::STANDARD` engine — NOT base64url.
private func _encodePaymentEnvelope(_ envelope: X402PaymentSignatureEnvelope) throws -> String {
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

    // Normalize the offer's network (CAIP-2 id or legacy plain slug) to its
    // canonical CAIP-2 form first, so legacy offers carrying `solana-devnet`
    // resolve to the correct cluster mints rather than falling through to
    // mainnet.
    let clusterLabel = SolanaNetwork.clusterLabel(for: SolanaNetwork.caip2(for: offer.network))
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
) -> X402ParsedChallenge? {
    guard let data = Data(base64Encoded: headerValue),
          let envelope = try? JSONDecoder().decode(X402PaymentRequiredEnvelope.self, from: data),
          let offer = _selectRequirement(from: envelope.accepts, selection: selection)
    else { return nil }
    return X402ParsedChallenge(offer: offer, declaredVersion: envelope.x402Version)
}

private func _selectFromBody(
    _ body: String,
    selection: X402ChallengeSelection
) -> X402ParsedChallenge? {
    guard let data = body.data(using: .utf8),
          let envelope = try? JSONDecoder().decode(X402PaymentRequiredEnvelope.self, from: data),
          let offer = _selectRequirement(from: envelope.accepts, selection: selection)
    else { return nil }
    return X402ParsedChallenge(offer: offer, declaredVersion: envelope.x402Version)
}

private func _selectRequirement(
    from accepts: [X402AcceptsEntry],
    selection: X402ChallengeSelection
) -> X402AcceptsEntry? {
    let preferredNetwork = SolanaNetwork.caip2(for: selection.network)
    let clusterLabel = SolanaNetwork.clusterLabel(for: preferredNetwork)

    let solana = accepts.filter { _isSolanaExact($0) }
    // Normalize each offer's network (CAIP-2 id or legacy plain slug) to its
    // CAIP-2 form before comparing against the preferred network, so legacy
    // 402-body offers (`solana-devnet` etc.) match the same way v2 offers do.
    // Mirrors rust `network_matches`, which normalizes the offer's
    // network/cluster through `caip2_network_for_cluster`.
    let onPreferred = solana.filter { SolanaNetwork.caip2(for: $0.network) == preferredNetwork }

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
    // Accept both CAIP-2 ids (v2 challenges) and legacy plain SVM slugs
    // (`solana` / `solana-devnet` / `solana-testnet`, carried by legacy 402
    // bodies). Mirrors the rust selection filter, which keeps any offer
    // whose network normalizes to a known Solana cluster.
    return SolanaNetwork.isSolanaNetwork(offer.network)
}

private func _effectiveAmountOf(_ offer: X402AcceptsEntry) -> UInt64 {
    UInt64(offer.effectiveAmount ?? "") ?? UInt64.max
}

private func _currenciesMatch(offered: String, accepted: String, label: String) -> Bool {
    let offeredMint = Mints.resolveMint(currency: offered, cluster: label) ?? offered
    let acceptedMint = Mints.resolveMint(currency: accepted, cluster: label) ?? accepted
    return offeredMint == acceptedMint
}
