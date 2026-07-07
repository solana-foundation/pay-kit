import Foundation

// MARK: - x402 upto challenge parsing and payment building (payment-channel)

/// Maximum facilitator fee in basis points (100%).
let X402UptoMaxFacilitatorFeeBps = 10_000

// MARK: - Challenge parsing

/// Parse a 402 `upto` challenge from response headers and/or body, returning the
/// first advertised `upto` requirement. Use ``parseUptoAccepts(headers:body:)``
/// to consider every advertised currency.
///
/// Checks (in order): the `PAYMENT-REQUIRED` header (case-insensitive,
/// standard-base64 JSON), then the response body as raw JSON. Returns `nil`
/// when no `upto` offer is present.
public func parseUptoChallenge(
    headers: [(name: String, value: String)],
    body: String?
) -> X402UptoRequirements? {
    parseUptoAccepts(headers: headers, body: body).first
}

/// Parse *all* `upto` requirements advertised on a 402 (every `scheme == "upto"`
/// `accepts` entry), so a balance- and cost-aware selector can choose among the
/// offered currencies. Empty when none are present.
public func parseUptoAccepts(
    headers: [(name: String, value: String)],
    body: String?
) -> [X402UptoRequirements] {
    func header(_ name: String) -> String? {
        headers.first { $0.name.lowercased() == name.lowercased() }?.value
    }

    var envelope: X402UptoRequiredEnvelope?
    if let value = header(X402PaymentRequiredHeaderName),
       let data = Data(base64Encoded: value) {
        envelope = try? JSONDecoder().decode(X402UptoRequiredEnvelope.self, from: data)
    }
    if envelope == nil, let body, let data = body.data(using: .utf8) {
        envelope = try? JSONDecoder().decode(X402UptoRequiredEnvelope.self, from: data)
    }
    guard let envelope else { return [] }
    return envelope.accepts.filter { $0.scheme == X402UptoScheme }
}

// MARK: - Payment building

/// Default channel grace period (seconds) the client requests at open.
let X402UptoDefaultGracePeriodSeconds: UInt32 = PaymentChannels.defaultGracePeriodSeconds

/// Build an `upto` payload for a `payment-channel` requirement.
///
/// The client (`signer`) is the channel payer; the operator
/// (`extra.facilitatorAddress`) is the channel payee, fee payer, rent payer, and
/// authorized signer. The `open` transaction is built with the operator as fee
/// payer and signed only in the client's payer slot; the operator co-signs and
/// broadcasts. `expiresAt` is the authorization deadline (Unix seconds).
///
/// - Parameters:
///   - nonce: Opaque per-authorization identifier. When `nil`, a random 16-byte
///     hex string is generated (independent of the channel salt).
///   - nonceGenerator: Optional 16-byte source backing the default nonce
///     (tests). Ignored when `nonce` is supplied.
///   - salt: Optional fixed channel salt (tests). When `nil`, a random `u64`
///     salt is drawn, independent of `nonce`.
///   - openSlot: Optional override for the channel-PDA slot seed (tests).
///     When `nil`, the challenge's server-prefetched `extra.recentSlot` is
///     used; the build fails when neither is available.
public func buildUptoPayload(
    signer: any SolanaSigner,
    requirements: X402UptoRequirements,
    expiresAt: Int,
    nonce: String? = nil,
    nonceGenerator: (() -> Data)? = nil,
    salt: UInt64? = nil,
    openSlot: UInt64? = nil
) async throws -> X402UptoPayload {
    let extra = requirements.extra
    guard extra.assetTransferMethod == X402UptoAssetTransferMethod else {
        throw PayKitError.invalidTransaction(
            "x402 client: requirement does not use the payment-channel asset transfer method"
        )
    }

    let max = try requirements.maxAmount()
    let mint = try Pubkey(base58: requirements.asset)
    guard !extra.facilitatorAddress.isEmpty else {
        throw PayKitError.missingField("x402 client: requirement missing extra.facilitatorAddress")
    }
    let operator_ = try Pubkey(base58: extra.facilitatorAddress)
    let beneficiary = try Pubkey(base58: requirements.payTo)

    guard extra.facilitatorFee >= 0, extra.facilitatorFee <= X402UptoMaxFacilitatorFeeBps else {
        throw PayKitError.invalidTransaction(
            "x402 client: facilitatorFee must be between 0 and 10000 basis points"
        )
    }
    let recipients: [PaymentChannels.Distribution]
    if beneficiary == operator_ {
        recipients = []
    } else {
        recipients = [PaymentChannels.Distribution(
            recipient: beneficiary,
            bps: UInt16(X402UptoMaxFacilitatorFeeBps - extra.facilitatorFee)
        )]
    }

    let programId: Pubkey
    if let value = extra.channelProgram, !value.isEmpty {
        programId = try Pubkey(base58: value)
    } else {
        programId = PaymentChannels.programId
    }

    let tokenProgram: Pubkey
    if let value = extra.tokenProgram, !value.isEmpty {
        tokenProgram = try Pubkey(base58: value)
    } else {
        tokenProgram = .tokenProgram
    }

    guard let blockhashStr = extra.recentBlockhash, !blockhashStr.isEmpty else {
        throw PayKitError.missingField("x402 client: requirement missing extra.recentBlockhash")
    }
    let blockhash = try Base58.decode(blockhashStr)
    guard blockhash.count == 32 else {
        throw PayKitError.invalidTransaction(
            "x402 client: recentBlockhash decodes to \(blockhash.count) bytes, expected 32"
        )
    }

    // The program's openSlot seeds the channel PDA: an explicit caller
    // override wins over the challenge's server-prefetched extra.recentSlot.
    let resolvedOpenSlot: UInt64
    if let openSlot {
        resolvedOpenSlot = openSlot
    } else if let value = extra.recentSlot, !value.isEmpty {
        guard let parsed = UInt64(value) else {
            throw PayKitError.invalidTransaction("x402 client: invalid extra.recentSlot \(value)")
        }
        resolvedOpenSlot = parsed
    } else {
        throw PayKitError.missingField("x402 client: requirement missing extra.recentSlot")
    }

    // The channel salt is an independent random u64, not the payload nonce.
    let channelSalt = salt ?? PaymentChannels.uniqueSalt()
    let open = try await PaymentChannels.buildOpenTransaction(
        payer: signer,
        payee: operator_,
        mint: mint,
        authorizedSigner: operator_,
        salt: channelSalt,
        deposit: max,
        gracePeriod: X402UptoDefaultGracePeriodSeconds,
        openSlot: resolvedOpenSlot,
        recipients: recipients,
        tokenProgram: tokenProgram,
        programId: programId,
        feePayer: operator_,
        recentBlockhash: blockhash
    )

    let signerPubkey = try Pubkey(bytes: signer.publicKey)
    let resolvedNonce = nonce ?? randomNonceHex(nonceGenerator: nonceGenerator)

    return X402UptoPayload(
        from: signerPubkey.base58,
        maxAmount: String(max),
        expiresAt: expiresAt,
        validAfter: extra.validAfter ?? 0,
        nonce: resolvedNonce,
        channelId: open.channelId.base58,
        deposit: String(max),
        authorizedSigner: operator_.base58,
        openTransaction: open.transaction
    )
}

/// Wrap a payload in a `PAYMENT-SIGNATURE` envelope and standard-base64 encode it.
///
/// The `accepted` field echoes the offered requirement verbatim (so
/// `scheme`/`network` and server extras survive); the output is compact,
/// key-sorted JSON, standard base64 with padding.
public func encodeUptoHeader(
    requirements: X402UptoRequirements,
    payload: X402UptoPayload
) throws -> String {
    let envelope = X402UptoSignatureEnvelope(
        x402Version: X402Version,
        accepted: try requirements.acceptedValue(),
        payload: payload
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let json = try encoder.encode(envelope)
    return json.base64EncodedString()
}

/// Build the full `PAYMENT-SIGNATURE` header value for an `upto` payment.
public func buildUptoHeader(
    signer: any SolanaSigner,
    requirements: X402UptoRequirements,
    expiresAt: Int,
    nonce: String? = nil,
    nonceGenerator: (() -> Data)? = nil,
    salt: UInt64? = nil,
    openSlot: UInt64? = nil
) async throws -> String {
    let payload = try await buildUptoPayload(
        signer: signer,
        requirements: requirements,
        expiresAt: expiresAt,
        nonce: nonce,
        nonceGenerator: nonceGenerator,
        salt: salt,
        openSlot: openSlot
    )
    return try encodeUptoHeader(requirements: requirements, payload: payload)
}

// MARK: - Internal helpers

/// 16 random bytes rendered as 32 lowercase hex chars: the default opaque
/// payload nonce, independent of the channel salt.
private func randomNonceHex(nonceGenerator: (() -> Data)? = nil) -> String {
    let bytes: Data
    if let nonceGenerator {
        bytes = nonceGenerator()
    } else {
        var rng = SystemRandomNumberGenerator()
        var raw = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { raw[i] = rng.next() }
        bytes = Data(raw)
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
}
