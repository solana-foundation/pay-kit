import Foundation

// MARK: - x402 upto challenge parsing and payment building (payment-channel)

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

/// Build an `upto` payload for a `payment-channel` requirement.
///
/// The client (`signer`) is the channel payer. `extra.feePayer` is the
/// transaction fee payer, rent payer, and zero-share channel payee;
/// `extra.receiverAuthorizer` is the voucher signer only. The `open`
/// transaction is signed only in the client's payer slot; the facilitator
/// co-signs and broadcasts. `expiresAt` is the authorization deadline
/// (Unix seconds).
///
/// - Parameters:
///   - nonce: Ignored; the payload nonce is the channel salt decimal string.
///   - nonceGenerator: Optional 16-byte source backing the default nonce
///     (tests). Ignored; kept for source compatibility.
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

    let max = try requirements.maxAmount()
    let mint = try Pubkey(base58: requirements.asset)
    guard !extra.feePayer.isEmpty else {
        throw PayKitError.missingField("x402 client: requirement missing extra.feePayer")
    }
    let feePayer = try Pubkey(base58: extra.feePayer)
    guard !extra.receiverAuthorizer.isEmpty else {
        throw PayKitError.missingField("x402 client: requirement missing extra.receiverAuthorizer")
    }
    let receiverAuthorizer = try Pubkey(base58: extra.receiverAuthorizer)
    guard extra.withdrawDelay > 0 else {
        throw PayKitError.missingField("x402 client: requirement missing extra.withdrawDelay")
    }
    let beneficiary = try Pubkey(base58: requirements.payTo)

    // Always explicit: the payee seat is held by the facilitator (feePayer)
    // with a zero implicit remainder, so 100% of settled funds must be
    // assigned to payTo through the recipients list.
    let recipients = [PaymentChannels.Distribution(
        recipient: beneficiary,
        bps: 10_000
    )]

    let programId = PaymentChannels.programId

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

    // The channel salt is also the payload nonce, encoded as a decimal string.
    let channelSalt = salt ?? PaymentChannels.uniqueSalt()
    let open = try await PaymentChannels.buildOpenTransaction(
        payer: signer,
        payee: feePayer,
        mint: mint,
        authorizedSigner: receiverAuthorizer,
        salt: channelSalt,
        deposit: max,
        gracePeriod: extra.withdrawDelay,
        openSlot: resolvedOpenSlot,
        recipients: recipients,
        tokenProgram: tokenProgram,
        programId: programId,
        feePayer: feePayer,
        recentBlockhash: blockhash
    )

    let signerPubkey = try Pubkey(bytes: signer.publicKey)

    return X402UptoPayload(
        from: signerPubkey.base58,
        maxAmount: String(max),
        expiresAt: expiresAt,
        validAfter: extra.validAfter ?? 0,
        nonce: String(channelSalt),
        channelId: open.channelId.base58,
        deposit: String(max),
        authorizedSigner: receiverAuthorizer.base58,
        openSlot: String(resolvedOpenSlot),
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
