// Command mpp-conformance is the Swift cross-SDK conformance-vector runner.
//
// It honors the same stdin/stdout contract as the TypeScript reference
// runner (harness/src/conformance/ts-runner.ts), the Go runner
// (go/cmd/conformance), and the other SDK runners: read one conformance
// vector as JSON on stdin, drive the real SolanaPayKit client paths for the
// requested intent + mode, and emit one RunnerResult line as JSON on stdout.
//
// Swift is a CLIENT-only SDK. It implements:
//   - charge build-transaction        (Charge.buildChargeTransaction)
//   - x402-exact build-transaction    (X402 v2 PAYMENT-SIGNATURE envelope,
//                                       incl. the v2 extensions echo-and-append)
//   - canonical-bytes                 (JCS / base64url / challenge-id HMAC)
// It does NOT implement the server pre-broadcast verifier, so every
// verify-transaction vector (charge or x402) emits an "unsupported-mode"
// reject the driver SKIPs for this language.
//
// The oracle for charge build vectors is the DECODED SEMANTIC SHAPE of the
// transaction (fee payer, transfer set, compute caps, memos); for x402 build
// vectors it is the DECODED ENVELOPE SHAPE (x402Version, accepted offer
// fields, the v2 extensions object); canonical-bytes pins exact bytes.
//
// The run is deterministic and RPC-free: build vectors pin a recent
// blockhash and resolve the token program ahead of time, and x402 build
// vectors carry a pinned placeholder transaction (the conformance oracle is
// the envelope, not the signed tx), so the SDK build paths are invoked with
// rpc == nil and never contact a live validator.

import CryptoKit
import Foundation
import SolanaPayKit

// MARK: - Program ids (mirror harness/src/conformance/decode.ts)

private let tokenProgramId = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
private let token2022ProgramId = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
private let systemProgramId = "11111111111111111111111111111111"
private let computeBudgetProgramId = "ComputeBudget111111111111111111111111111111"
private let memoProgramId = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
private let defaultNetwork = "mainnet"
private let defaultSPLDecimals = 6
private let x402DefaultPinnedTransaction = "AA=="

// MARK: - Vector decoding (mirror schema.ts ConformanceVector)

private struct Vector: Decodable {
    let id: String
    let intent: String?
    let mode: String
    let input: VectorInput
}

private struct VectorInput: Decodable {
    let request: VectorChargeRequest?
    let transaction: String?
    let signerSecretKey: [UInt8]?
    let rpcFixtures: RPCFixtures?
    // canonical-bytes payloads are decoded lazily from the raw JSON because
    // `value` is an arbitrary JSON document Codable cannot model directly.
    let encodeBase64Url: EncodeBase64URL?
    let challengeId: ChallengeID?
    // x402-exact build inputs.
    let x402Version: Int?
    let x402Offer: JSONValue?
    let x402PinnedTransaction: String?
    let x402AdvertisedExtensions: JSONValue?
    let x402PaymentIdentifierId: String?
}

private struct VectorChargeRequest: Decodable {
    let amount: String
    let currency: String
    let externalId: String?
    let recipient: String?
    let payTo: String?
    let asset: String?
    let methodDetails: MethodDetails?
    let computeUnitLimit: UInt32?
    let computeUnitPrice: String?
}

private struct MethodDetails: Decodable {
    let network: String?
    let decimals: Int?
    let tokenProgram: String?
    let recentBlockhash: String?
    let feePayer: Bool?
    let feePayerKey: String?
    let splits: [Split]?
}

private struct Split: Decodable {
    let recipient: String
    let amount: String
    let ataCreationRequired: Bool?
    let memo: String?
}

private struct RPCFixtures: Decodable {
    let recentBlockhash: String?
    let mintOwners: [String: String]?
}

private struct EncodeBase64URL: Decodable {
    let hexBytes: String?
    let utf8: String?
}

// challenge-id HMAC input (mirror schema.ts / ts-runner challengeId).
private struct ChallengeID: Decodable {
    let secretKey: String
    let realm: String
    let method: String
    let intent: String
    let request: String
    let expires: String?
    let digest: String?
    let opaque: String?
}

// MARK: - Result encoding (mirror schema.ts RunnerResult)

private struct TransferShape: Encodable {
    let kind: String
    let destination: String?
    let mint: String?
    let amount: String
    let decimals: Int?
    let tokenProgram: String?

    enum CodingKeys: String, CodingKey {
        case kind, destination, mint, amount, decimals, tokenProgram
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(kind, forKey: .kind)
        try c.encode(amount, forKey: .amount)
        if let destination { try c.encode(destination, forKey: .destination) }
        if let mint { try c.encode(mint, forKey: .mint) }
        if let decimals { try c.encode(decimals, forKey: .decimals) }
        if let tokenProgram { try c.encode(tokenProgram, forKey: .tokenProgram) }
    }
}

private struct TransactionShape: Encodable {
    var feePayer: String?
    var transfers: [TransferShape]
    var forbiddenPrograms: [String]
    var maxComputeUnitLimit: UInt32?
    var maxComputeUnitPrice: String?
    var memo: [String]

    enum CodingKeys: String, CodingKey {
        case feePayer, transfers, forbiddenPrograms, maxComputeUnitLimit, maxComputeUnitPrice, memo
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        if let feePayer { try c.encode(feePayer, forKey: .feePayer) }
        try c.encode(transfers, forKey: .transfers)
        try c.encode(forbiddenPrograms, forKey: .forbiddenPrograms)
        if let maxComputeUnitLimit { try c.encode(maxComputeUnitLimit, forKey: .maxComputeUnitLimit) }
        if let maxComputeUnitPrice { try c.encode(maxComputeUnitPrice, forKey: .maxComputeUnitPrice) }
        try c.encode(memo, forKey: .memo)
    }
}

private struct ExactBytes: Encodable {
    var canonicalJson: String?
    var base64Url: String?
    var bytes: [Int]?

    enum CodingKeys: String, CodingKey {
        case canonicalJson, base64Url, bytes
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        if let canonicalJson { try c.encode(canonicalJson, forKey: .canonicalJson) }
        if let base64Url { try c.encode(base64Url, forKey: .base64Url) }
        if let bytes { try c.encode(bytes, forKey: .bytes) }
    }
}

// x402 envelope shape oracle (mirror schema.ts X402EnvelopeShape).
private struct X402EnvelopeShape: Encodable {
    var x402Version: Int
    var scheme: String?
    var network: String?
    var hasAccepted: Bool
    var payloadHasTransaction: Bool
    var acceptedScheme: String?
    var acceptedNetwork: String?
    var acceptedAsset: String?
    var acceptedPayTo: String?
    var acceptedAmount: String?
    var hasExtensions: Bool?
    var hasPaymentIdentifier: Bool?
    var paymentIdentifierRequired: Bool?
    var paymentIdentifierId: String?
    var extensionKeys: [String]?

    enum CodingKeys: String, CodingKey {
        case x402Version, scheme, network, hasAccepted, payloadHasTransaction
        case acceptedScheme, acceptedNetwork, acceptedAsset, acceptedPayTo, acceptedAmount
        case hasExtensions, hasPaymentIdentifier, paymentIdentifierRequired
        case paymentIdentifierId, extensionKeys
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(x402Version, forKey: .x402Version)
        try c.encode(hasAccepted, forKey: .hasAccepted)
        try c.encode(payloadHasTransaction, forKey: .payloadHasTransaction)
        if let scheme { try c.encode(scheme, forKey: .scheme) }
        if let network { try c.encode(network, forKey: .network) }
        if let acceptedScheme { try c.encode(acceptedScheme, forKey: .acceptedScheme) }
        if let acceptedNetwork { try c.encode(acceptedNetwork, forKey: .acceptedNetwork) }
        if let acceptedAsset { try c.encode(acceptedAsset, forKey: .acceptedAsset) }
        if let acceptedPayTo { try c.encode(acceptedPayTo, forKey: .acceptedPayTo) }
        if let acceptedAmount { try c.encode(acceptedAmount, forKey: .acceptedAmount) }
        if let hasExtensions { try c.encode(hasExtensions, forKey: .hasExtensions) }
        if let hasPaymentIdentifier { try c.encode(hasPaymentIdentifier, forKey: .hasPaymentIdentifier) }
        if let paymentIdentifierRequired { try c.encode(paymentIdentifierRequired, forKey: .paymentIdentifierRequired) }
        if let paymentIdentifierId { try c.encode(paymentIdentifierId, forKey: .paymentIdentifierId) }
        if let extensionKeys { try c.encode(extensionKeys, forKey: .extensionKeys) }
    }
}

private struct RunnerResult: Encodable {
    let id: String
    let outcome: String
    var transactionShape: TransactionShape?
    var exactBytes: ExactBytes?
    var x402EnvelopeShape: X402EnvelopeShape?
    var error: String?
    var rejectCode: String?

    enum CodingKeys: String, CodingKey {
        case id, outcome, transactionShape, exactBytes, x402EnvelopeShape, error, rejectCode
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(outcome, forKey: .outcome)
        if let transactionShape { try c.encode(transactionShape, forKey: .transactionShape) }
        if let exactBytes { try c.encode(exactBytes, forKey: .exactBytes) }
        if let x402EnvelopeShape { try c.encode(x402EnvelopeShape, forKey: .x402EnvelopeShape) }
        if let error { try c.encode(error, forKey: .error) }
        if let rejectCode { try c.encode(rejectCode, forKey: .rejectCode) }
    }
}

// MARK: - Reject classification
//
// The harness asserts a normalized reject CATEGORY per reject vector. Map the
// Swift SDK's native reject message (the `MppError` payload string) onto the
// shared RejectCode vocabulary so the driver can compare categories across
// SDKs rather than brittle prose. Swift is a CLIENT-only SDK, so the only
// harness reject vector it actually processes is the splits-consume-amount
// build vector; the rest of the vocabulary is mapped for completeness and
// future build-path rejects. Returns nil for messages outside the vocabulary
// (e.g. the unsupported-mode skip), and the runner omits `rejectCode` then.
private func classifyReject(_ message: String) -> String? {
    let m = message.lowercased()

    func has(_ needle: String) -> Bool { m.contains(needle) }

    if has("splits consume the entire amount")
        || (has("primary") && has("positive"))
        || (has("split") && has("exceed")) {
        return "splits-exceed-amount"
    }
    if has("too many splits") {
        return "too-many-splits"
    }
    if has("compute unit price") && has("exceed") && (has("cap") || has("maximum")) {
        return "compute-price-over-cap"
    }
    if has("compute unit limit") && has("exceed") {
        return "compute-limit-over-cap"
    }
    if has("fee payer cannot authorize") {
        return "fee-payer-not-authority"
    }
    if (has("no matching") || has("unexpected")) && has("transfer") {
        return "no-matching-transfer"
    }
    if has("amount") && (has("mismatch") || has("does not match")) {
        return "amount-mismatch"
    }
    if has("payment-identifier") && (has("required") || has("missing")) {
        return "payment-identifier-required"
    }
    if has("invalid") || has("malformed") || has("decode") || has("payload") {
        return "invalid-payload"
    }
    return nil
}

private enum RunnerError: Error, CustomStringConvertible {
    case message(String)
    var description: String {
        switch self {
        case let .message(text): return text
        }
    }
}

// MARK: - Local signer

private struct ConformanceSigner: SolanaSigner {
    let publicKey: Data
    let address: String
    private let handler: @Sendable (Data) async throws -> Data

    init(secretKey: [UInt8]) throws {
        guard secretKey.count == 64 else {
            throw RunnerError.message("signerSecretKey must be 64 bytes, got \(secretKey.count)")
        }
        let inner = try MemorySigner(secretKey: Data(secretKey))
        self.publicKey = inner.publicKey
        self.address = inner.address
        self.handler = { try await inner.sign(message: $0) }
    }

    func sign(message: Data) async throws -> Data {
        try await handler(message)
    }
}

// MARK: - base64url helper (mirror the SDK PayCore/Base64URL transform)

private func base64Url(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

// MARK: - Request flattening (mirror ts-runner / go flattenRequest)

private func resolveTokenProgram(
    currency: String,
    network: String,
    explicit: String?,
    mintOwners: [String: String]?
) -> String? {
    if let explicit { return explicit }
    if currency.lowercased() == "sol" { return nil }
    let resolvedMint = Charge.resolveStablecoinMint(currency: currency, network: network) ?? currency
    if let owner = mintOwners?[resolvedMint] { return owner }
    return Mints.defaultTokenProgram(currency: currency, cluster: network)
}

// Apply the precedence rules a vector can probe: top-level asset / payTo win
// over currency / recipient; methodDetails carry the rest. Resolve the token
// program ahead of time so the SDK build path stays RPC-free, mirroring the
// TS and Go reference runners. The flattened request is decoded through the
// SDK's own `ChargeRequest` Decodable path (the model has no cross-module
// public initializer), so the runner exercises the same decode the SDK
// uses on the wire.
private func flattenRequest(
    _ request: VectorChargeRequest,
    mintOwners: [String: String]?
) throws -> ChargeRequest {
    let currency = request.asset ?? request.currency
    guard let recipient = request.payTo ?? request.recipient else {
        throw RunnerError.message("vector request is missing recipient/payTo")
    }
    let md = request.methodDetails
    let network = md?.network ?? defaultNetwork

    let tokenProgram = resolveTokenProgram(
        currency: currency,
        network: network,
        explicit: md?.tokenProgram,
        mintOwners: mintOwners
    )

    let isSOL = currency.lowercased() == "sol"
    let decimals = md?.decimals ?? (isSOL ? nil : defaultSPLDecimals)

    var methodDetails: [String: Any] = [:]
    methodDetails["network"] = network
    if let decimals { methodDetails["decimals"] = decimals }
    if let tokenProgram { methodDetails["tokenProgram"] = tokenProgram }
    if let bh = md?.recentBlockhash { methodDetails["recentBlockhash"] = bh }
    if let fp = md?.feePayer { methodDetails["feePayer"] = fp }
    if let fpk = md?.feePayerKey { methodDetails["feePayerKey"] = fpk }
    if let splits = md?.splits {
        methodDetails["splits"] = splits.map { split -> [String: Any] in
            var out: [String: Any] = ["recipient": split.recipient, "amount": split.amount]
            if let req = split.ataCreationRequired { out["ataCreationRequired"] = req }
            if let memo = split.memo { out["memo"] = memo }
            return out
        }
    }

    var object: [String: Any] = [
        "amount": request.amount,
        "currency": currency,
        "recipient": recipient,
        "methodDetails": methodDetails,
    ]
    if let externalId = request.externalId { object["externalId"] = externalId }

    let data = try JSONSerialization.data(withJSONObject: object)
    do {
        return try JSONDecoder().decode(ChargeRequest.self, from: data)
    } catch {
        throw RunnerError.message("failed to decode flattened ChargeRequest: \(error)")
    }
}

// MARK: - Charge build path

private func buildChargeTransaction(_ vector: Vector) async throws -> String {
    let input = vector.input
    guard let request = input.request else {
        throw RunnerError.message("build/verify vector is missing input.request")
    }
    guard let secret = input.signerSecretKey else {
        throw RunnerError.message("build/verify vector is missing input.signerSecretKey")
    }
    let signer = try ConformanceSigner(secretKey: secret)
    let charge = try flattenRequest(request, mintOwners: input.rpcFixtures?.mintOwners)

    var options = Charge.Options()
    if let limit = request.computeUnitLimit { options.computeUnitLimit = limit }
    if let priceStr = request.computeUnitPrice {
        guard let price = UInt64(priceStr) else {
            throw RunnerError.message("invalid computeUnitPrice \(priceStr)")
        }
        options.computeUnitPrice = price
    }

    // rpc == nil: recentBlockhash is pinned and the token program is resolved
    // ahead of time, so the SDK never reaches for a live RPC.
    return try await Charge.buildChargeTransaction(
        request: charge,
        signer: signer,
        rpc: nil,
        options: options
    )
}

// MARK: - x402-exact build path
//
// The conformance oracle for x402 build vectors is the decoded ENVELOPE
// shape, not the signed transaction, so the runner wraps the pinned
// placeholder transaction (input.x402PinnedTransaction, default "AA==") into
// a v2 PAYMENT-SIGNATURE envelope using the real SDK types and the
// echo-and-append helper, then decodes the shape. This mirrors the TS
// reference runner (`runX402Vector` build branch) exactly and stays
// RPC-free.

private func buildX402Envelope(_ vector: Vector) throws -> X402EnvelopeShape {
    let input = vector.input
    guard let offerValue = input.x402Offer else {
        throw RunnerError.message("invalid payload: x402 build vector missing input.x402Offer")
    }
    let version = input.x402Version ?? 2
    guard version == 2 else {
        throw RunnerError.message("swift x402 runner only builds v2 envelopes; got \(version)")
    }
    let transaction = input.x402PinnedTransaction ?? x402DefaultPinnedTransaction
    let offer = try offerValue.decode(X402AcceptsEntry.self)

    // Echo-and-append (x402 v2 §5.1.2): echo the server's advertised
    // extensions verbatim, preserving unknown keys, and fill the required
    // client-side payment-identifier.info.id (pinned in the vector for a
    // deterministic byte assertion, else freshly generated). When the server
    // advertised nothing, this returns nil and the envelope omits the
    // `extensions` object entirely.
    let extensions = try buildX402Extensions(
        echoing: input.x402AdvertisedExtensions,
        paymentIdentifierID: input.x402PaymentIdentifierId
    )

    let envelope = X402PaymentSignatureEnvelope(
        x402Version: version,
        accepted: offer,
        payload: X402PaymentPayload(transaction: transaction),
        extensions: extensions
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let header = try encoder.encode(envelope).base64EncodedString()
    return try decodeX402EnvelopeShape(header)
}

// Decode an outbound v2 PAYMENT-SIGNATURE header into the conformance
// envelope-shape oracle (mirror x402.ts decodeEnvelopeShape).
private func decodeX402EnvelopeShape(_ header: String) throws -> X402EnvelopeShape {
    guard let data = Data(base64Encoded: header) else {
        throw RunnerError.message("x402 envelope header is not valid base64")
    }
    guard let top = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw RunnerError.message("x402 envelope is not a JSON object")
    }

    let x402Version = (top["x402Version"] as? Int) ?? 0
    let accepted = top["accepted"] as? [String: Any]
    let payload = top["payload"] as? [String: Any]
    let transaction = payload?["transaction"] as? String

    var shape = X402EnvelopeShape(
        x402Version: x402Version,
        hasAccepted: accepted != nil,
        payloadHasTransaction: (transaction?.isEmpty == false)
    )
    shape.scheme = top["scheme"] as? String
    shape.network = top["network"] as? String
    if let accepted {
        shape.acceptedScheme = accepted["scheme"] as? String
        shape.acceptedNetwork = accepted["network"] as? String
        shape.acceptedAsset = accepted["asset"] as? String
        shape.acceptedPayTo = accepted["payTo"] as? String
        shape.acceptedAmount = accepted["amount"] as? String
    }

    // Surface the v2 extensions object. hasExtensions is false when the key
    // is absent OR present-but-empty (the echo-and-omit rule means a
    // conforming build never emits an empty `extensions: {}`).
    if let extensions = top["extensions"] as? [String: Any] {
        let keys = extensions.keys.sorted()
        shape.hasExtensions = !keys.isEmpty
        shape.extensionKeys = keys
        if let pid = extensions[X402PaymentIdentifierKey] as? [String: Any] {
            shape.hasPaymentIdentifier = true
            if let info = pid["info"] as? [String: Any] {
                if let required = info["required"] as? Bool {
                    shape.paymentIdentifierRequired = required
                }
                if let id = info["id"] as? String {
                    shape.paymentIdentifierId = id
                }
            }
        } else {
            shape.hasPaymentIdentifier = false
        }
    } else {
        shape.hasExtensions = false
        shape.hasPaymentIdentifier = false
        shape.extensionKeys = []
    }

    return shape
}

// MARK: - Wire decode (mirror decode.ts / go shapeFromTransaction)

private struct DecodeCursor {
    let data: [UInt8]
    var offset = 0
    init(_ data: Data) { self.data = [UInt8](data) }

    mutating func shortVecLength() throws -> Int {
        var value = 0
        var shift = 0
        for _ in 0..<3 {
            guard offset < data.count else {
                throw RunnerError.message("short-vec length truncated")
            }
            let byte = data[offset]; offset += 1
            value |= Int(byte & 0x7F) << shift
            if (byte & 0x80) == 0 { return value }
            shift += 7
        }
        throw RunnerError.message("short-vec length exceeds 3 bytes")
    }

    mutating func take(_ count: Int) throws -> [UInt8] {
        guard offset + count <= data.count else {
            throw RunnerError.message("unexpected end of transaction bytes")
        }
        let slice = Array(data[offset..<(offset + count)])
        offset += count
        return slice
    }

    mutating func byte() throws -> UInt8 {
        guard offset < data.count else {
            throw RunnerError.message("unexpected end of transaction bytes")
        }
        let b = data[offset]; offset += 1
        return b
    }
}

private func u32LE(_ d: [UInt8], _ at: Int) -> UInt32 {
    UInt32(d[at]) | (UInt32(d[at + 1]) << 8) | (UInt32(d[at + 2]) << 16) | (UInt32(d[at + 3]) << 24)
}

private func u64LE(_ d: [UInt8], _ at: Int) -> UInt64 {
    var v: UInt64 = 0
    for i in 0..<8 { v |= UInt64(d[at + i]) << (8 * i) }
    return v
}

private func shapeFromTransaction(_ base64: String) throws -> TransactionShape {
    guard let txData = Data(base64Encoded: base64) else {
        throw RunnerError.message("transaction is not valid base64")
    }
    var cur = DecodeCursor(txData)
    let sigCount = try cur.shortVecLength()
    _ = try cur.take(sigCount * 64)
    // Legacy messages carry no version prefix byte (the SDK always emits
    // legacy for charge). Header is 3 bytes.
    let header = try cur.take(3)
    _ = header
    let keyCount = try cur.shortVecLength()
    var keys: [String] = []
    keys.reserveCapacity(keyCount)
    for _ in 0..<keyCount {
        let raw = try cur.take(32)
        keys.append(try Pubkey(bytes: Data(raw)).base58)
    }
    _ = try cur.take(32) // recent blockhash

    func accountAt(_ accounts: [UInt8], _ pos: Int) -> String? {
        guard pos >= 0, pos < accounts.count else { return nil }
        let idx = Int(accounts[pos])
        guard idx >= 0, idx < keys.count else { return nil }
        return keys[idx]
    }

    guard !keys.isEmpty else {
        throw RunnerError.message("transaction has no account keys")
    }

    var shape = TransactionShape(
        feePayer: keys[0],
        transfers: [],
        forbiddenPrograms: [],
        memo: []
    )

    let ixCount = try cur.shortVecLength()
    for _ in 0..<ixCount {
        let programIdx = Int(try cur.byte())
        let acctCount = try cur.shortVecLength()
        let accounts = try cur.take(acctCount)
        let dataLen = try cur.shortVecLength()
        let data = try cur.take(dataLen)

        guard programIdx >= 0, programIdx < keys.count else { continue }
        let program = keys[programIdx]

        switch program {
        case computeBudgetProgramId:
            if data.count == 5, data[0] == 2 {
                shape.maxComputeUnitLimit = u32LE(data, 1)
            } else if data.count == 9, data[0] == 3 {
                shape.maxComputeUnitPrice = String(u64LE(data, 1))
            }
        case memoProgramId:
            shape.memo.append(String(decoding: data, as: UTF8.self))
        case systemProgramId:
            // System transfer: u32 LE discriminator 2 + u64 LE lamports.
            if data.count >= 12, u32LE(data, 0) == 2 {
                guard let dest = accountAt(accounts, 1) else { continue }
                shape.transfers.append(TransferShape(
                    kind: "sol",
                    destination: dest,
                    mint: nil,
                    amount: String(u64LE(data, 4)),
                    decimals: nil,
                    tokenProgram: nil
                ))
            }
        case tokenProgramId, token2022ProgramId:
            // transferChecked: discriminator 12, u64 amount at [1], decimals [9].
            if data.count >= 10, data[0] == 12, accounts.count >= 4 {
                guard let mint = accountAt(accounts, 1),
                      let dest = accountAt(accounts, 2) else { continue }
                shape.transfers.append(TransferShape(
                    kind: "spl",
                    destination: dest,
                    mint: mint,
                    amount: String(u64LE(data, 1)),
                    decimals: Int(data[9]),
                    tokenProgram: program
                ))
            }
        default:
            continue
        }
    }

    return shape
}

// MARK: - canonical-bytes

private func runCanonicalBytes(_ vector: Vector, rawValue: Any?) throws -> ExactBytes {
    var eb = ExactBytes()
    if let value = rawValue {
        // Canonical JSON via Foundation's sorted-key serializer, the same
        // canonicalization the SDK wire path relies on
        // (JSONEncoder.outputFormatting = [.sortedKeys]). RFC 8785 key order
        // for BMP keys agrees with sorted-key order.
        let data = try JSONSerialization.data(
            withJSONObject: value,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        eb.canonicalJson = String(decoding: data, as: UTF8.self)
        eb.base64Url = base64Url(data)
    }
    if let enc = vector.input.encodeBase64Url {
        if let hex = enc.hexBytes {
            let bytes = try hexDecode(hex)
            eb.bytes = bytes.map { Int($0) }
            eb.base64Url = base64Url(Data(bytes))
        } else if let utf8 = enc.utf8 {
            eb.base64Url = base64Url(Data(utf8.utf8))
        }
    }
    if let c = vector.input.challengeId {
        // base64url(HMAC-SHA256(secret, realm|method|intent|request|expires|
        // digest|opaque)); absent optionals join as empty strings. Mirrors
        // rust compute_challenge_id (protocol/core/challenge.rs) and the TS
        // reference runner.
        let hmacInput = [
            c.realm,
            c.method,
            c.intent,
            c.request,
            c.expires ?? "",
            c.digest ?? "",
            c.opaque ?? "",
        ].joined(separator: "|")
        let key = SymmetricKey(data: Data(c.secretKey.utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: Data(hmacInput.utf8), using: key)
        eb.base64Url = base64Url(Data(mac))
    }
    return eb
}

private func hexDecode(_ hex: String) throws -> [UInt8] {
    let chars = Array(hex)
    guard chars.count % 2 == 0 else {
        throw RunnerError.message("hex string has odd length")
    }
    var out: [UInt8] = []
    out.reserveCapacity(chars.count / 2)
    var i = 0
    while i < chars.count {
        guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else {
            throw RunnerError.message("invalid hex digit")
        }
        out.append(UInt8(hi << 4 | lo))
        i += 2
    }
    return out
}

// MARK: - Dispatch

private func runVector(_ vector: Vector, rawValue: Any?) async -> RunnerResult {
    do {
        // x402-exact: the oracle is the decoded envelope shape. Swift builds
        // the v2 PAYMENT-SIGNATURE envelope (incl. extensions echo-and-append)
        // but has no server verifier, so verify vectors are unsupported.
        if vector.intent == "x402-exact" {
            switch vector.mode {
            case "build-transaction":
                let shape = try buildX402Envelope(vector)
                return RunnerResult(id: vector.id, outcome: "accept", x402EnvelopeShape: shape)
            case "verify-transaction":
                return RunnerResult(
                    id: vector.id,
                    outcome: "reject",
                    error: "unsupported-mode: swift is a client-only SDK and does not implement x402 verify-transaction"
                )
            default:
                return RunnerResult(
                    id: vector.id,
                    outcome: "reject",
                    error: "unsupported mode \(vector.mode) for x402-exact"
                )
            }
        }

        switch vector.mode {
        case "canonical-bytes":
            let eb = try runCanonicalBytes(vector, rawValue: rawValue)
            return RunnerResult(id: vector.id, outcome: "accept", exactBytes: eb)
        case "build-transaction":
            let tx = try await buildChargeTransaction(vector)
            let shape = try shapeFromTransaction(tx)
            return RunnerResult(id: vector.id, outcome: "accept", transactionShape: shape)
        case "verify-transaction":
            // Swift is a client-only SDK: it has no server pre-broadcast
            // verifier. Emit a clear unsupported-mode result the driver
            // SKIPs for this language rather than a false accept/reject.
            return RunnerResult(
                id: vector.id,
                outcome: "reject",
                error: "unsupported-mode: swift is a client-only SDK and does not implement verify-transaction"
            )
        default:
            return RunnerResult(
                id: vector.id,
                outcome: "reject",
                error: "unsupported mode \(vector.mode)"
            )
        }
    } catch {
        let message = String(describing: error)
        return RunnerResult(
            id: vector.id,
            outcome: "reject",
            error: message,
            rejectCode: classifyReject(message)
        )
    }
}

// MARK: - Entry point

func main() async {
    let raw = FileHandle.standardInput.readDataToEndOfFile()
    guard !raw.isEmpty else {
        FileHandle.standardError.write(Data("swift conformance runner received empty stdin".utf8))
        exit(1)
    }

    let vector: Vector
    let rawValue: Any?
    do {
        vector = try JSONDecoder().decode(Vector.self, from: raw)
        // `value` is an arbitrary JSON document; pull it from the parsed
        // object tree rather than Codable so canonical-bytes vectors can
        // canonicalize any shape.
        if let top = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
           let input = top["input"] as? [String: Any] {
            rawValue = input["value"]
        } else {
            rawValue = nil
        }
    } catch {
        FileHandle.standardError.write(Data("failed to parse vector: \(error)".utf8))
        exit(1)
    }

    let result = await runVector(vector, rawValue: rawValue)
    do {
        let encoder = JSONEncoder()
        let data = try encoder.encode(result)
        var line = data
        line.append(0x0A)
        FileHandle.standardOutput.write(line)
    } catch {
        FileHandle.standardError.write(Data("failed to encode result: \(error)".utf8))
        exit(1)
    }
}

await main()
