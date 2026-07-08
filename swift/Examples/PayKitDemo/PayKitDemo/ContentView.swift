import SwiftUI
import SolanaPayKit

struct ContentView: View {
    // Hardcoded for the demo. The playground API (`examples/playground-api`,
    // `pnpm dev`) serves its priced routes + `/openapi.json` discovery on
    // :3000 and routes settlement through the hosted Surfpool sandbox at
    // `402.surfnet.dev:8899`. The iOS simulator shares the host network, so
    // `127.0.0.1` reaches the local playground.
    private let rpcURL = URL(string: "https://402.surfnet.dev:8899")!
    private let playgroundURL = URL(string: "http://127.0.0.1:3000")!

    @State private var signer: MemorySigner?
    @State private var usdcBalance: Decimal?
    @State private var log: [LogEntry] = []
    @State private var busy: BusyKind?
    @State private var endpoints: [Endpoint] = []
    @State private var endpointsError: String?
    /// Per-endpoint protocol the user picked to settle over (endpoint id -> method).
    @State private var protocolChoice: [String: String] = [:]

    var body: some View {
        NavigationStack {
            Form {
                accountSection
                endpointsSection
                logSection
            }
            .navigationTitle("PayKit Demo")
            .toolbar {
                ToolbarItem(placement: .bottomBar) {
                    if signer != nil {
                        Button(role: .destructive) { reset() } label: {
                            Label("Reset Account", systemImage: "trash")
                        }
                        .disabled(busy != nil)
                    }
                }
            }
        }
        .task {
            do {
                if let loaded = try DemoSigner.loadSigner() {
                    signer = loaded
                    await refreshBalance()
                }
            } catch {
                append(.system("Failed to load signer: \(error.localizedDescription)", success: false))
            }
            await loadEndpoints()
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private var accountSection: some View {
        Section("Account") {
            if let signer {
                LabeledContent {
                    Text(Self.shortAddress(signer.address))
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                } label: {
                    Text("Address")
                }

                if let balance = usdcBalance {
                    LabeledContent {
                        HStack(spacing: 6) {
                            Image(systemName: "dollarsign.circle.fill")
                                .foregroundStyle(.green)
                            Text(Self.formatUSDC(balance))
                                .font(.body.monospacedDigit())
                        }
                    } label: {
                        Text("Balance")
                    }
                } else {
                    Button {
                        Task { await topup() }
                    } label: {
                        busyRow(
                            title: "Topup 1000 USDC + 100 SOL",
                            icon: "arrow.down.circle.fill",
                            active: busy == .topup
                        )
                    }
                    .disabled(busy != nil)
                }
            } else {
                Button {
                    setupAccount()
                } label: {
                    busyRow(
                        title: "Setup Account",
                        icon: "key.fill",
                        active: false
                    )
                }
            }
        }
    }

    @ViewBuilder
    private var endpointsSection: some View {
        Section("Endpoints (\(endpoints.count) from OpenAPI)") {
            if let endpointsError {
                Label(endpointsError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            } else if endpoints.isEmpty {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Loading \(playgroundURL.absoluteString)/openapi.json…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 12) {
                        ForEach(endpoints) { endpoint in
                            EndpointCard(
                                endpoint: endpoint,
                                busy: busy == .pay(endpoint.id),
                                selected: protocolChoice[endpoint.id] ?? endpoint.selectedProtocol,
                                onTap: { Task { await pay(endpoint) } },
                                onSelect: { method in protocolChoice[endpoint.id] = method }
                            )
                            .disabled(busy != nil || signer == nil)
                        }
                    }
                    .padding(.vertical, 4)
                }
                .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
            }

            if signer == nil && !endpoints.isEmpty {
                Text("Tap **Setup Account** to enable these.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var logSection: some View {
        Section {
            if log.isEmpty {
                Text("Tap an endpoint above to send a charge.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(log) { entry in
                    LogRow(entry: entry)
                }
            }
        } header: {
            HStack {
                Text("Log")
                Spacer()
                if !log.isEmpty {
                    Button("Clear") { log.removeAll() }
                        .font(.caption)
                        .textCase(.none)
                }
            }
        }
    }

    // MARK: - Actions

    private func setupAccount() {
        do {
            let new = try DemoSigner.setupSigner()
            signer = new
            usdcBalance = nil
            append(.system("New account: \(new.address)", success: true))
        } catch {
            append(.system("Setup failed: \(error.localizedDescription)", success: false))
        }
    }

    private func reset() {
        do {
            try DemoSigner.resetSigner()
            signer = nil
            usdcBalance = nil
            append(.system("Account reset.", success: true))
        } catch {
            append(.system("Reset failed: \(error.localizedDescription)", success: false))
        }
    }

    private func topup() async {
        guard let signer else { return }
        busy = .topup
        defer { busy = nil }
        do {
            try await DemoSigner.topup(rpc: rpcURL, pubkey: signer.address)
            append(.system("Topup ok: 1000 USDC + 100 SOL on \(rpcURL.host ?? rpcURL.absoluteString)", success: true))
            await refreshBalance()
        } catch {
            append(.system("Topup failed: \(error.localizedDescription)", success: false))
        }
    }

    private func refreshBalance() async {
        guard let signer else { return }
        do {
            usdcBalance = try await DemoSigner.usdcBalance(rpc: rpcURL, pubkey: signer.address)
        } catch {
            // Surface but don't disrupt the UI; the topup row stays
            // visible as the fallback path.
            append(.system("Balance check failed: \(error.localizedDescription)", success: false))
        }
    }

    /// Fetch `/openapi.json` from the playground and build the priced-endpoint
    /// collection. Surfaces a fetch/decode failure in `endpointsError` so the
    /// section shows it instead of an empty spinner.
    private func loadEndpoints() async {
        endpointsError = nil
        let url = playgroundURL.appendingPathComponent("openapi.json")
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                throw OpenAPIError.httpStatus(http.statusCode)
            }
            let loaded = try OpenAPI.endpoints(from: data)
            endpoints = loaded
            if loaded.isEmpty {
                endpointsError = "No priced endpoints in the OpenAPI spec."
            }
        } catch {
            endpointsError = "Could not load \(url.absoluteString): \(error.localizedDescription)"
        }
    }

    private func pay(_ endpoint: Endpoint) async {
        guard let signer else { return }

        // Session endpoints run the real payment-channel flow (open -> stream
        // SSE deliveries -> sign + commit a voucher -> settle), not the one-shot
        // 402 -> charge -> retry loop.
        if endpoint.intent == .session {
            busy = .pay(endpoint.id)
            defer { busy = nil }
            do {
                let result = try await SessionStream.consume(
                    streamURL: playgroundURL.appendingPathComponent(endpoint.path),
                    payer: signer
                )
                append(.success(
                    endpoint: endpoint,
                    signature: result.settleSignature,
                    body: result.steps.joined(separator: "\n")
                ))
                await refreshBalance()
            } catch {
                append(.failure(endpoint: endpoint, message: String(describing: error)))
            }
            return
        }

        // x402 `upto` (usage): authorize a ceiling by opening a payment channel,
        // then the server meters actual usage and settles `actual <= max`,
        // refunding the rest. One tap drives the whole flow through the upto
        // client; the response body reports the metered amount billed.
        if endpoint.scheme == .upto {
            busy = .pay(endpoint.id)
            defer { busy = nil }
            let client = PayKit.HttpClient.x402Upto(
                signer: signer,
                settlementHeader: "x-payment-response"
            )
            let url = playgroundURL.appendingPathComponent(endpoint.path)
            do {
                let response = try await client
                    .request(
                        url,
                        method: .post,
                        headers: ["Accept": "application/json", "Content-Type": "text/plain"],
                        body: Data("Solana is a fast, low-cost blockchain for payments and apps.".utf8)
                    )
                    .response()
                let bodyString = String(data: response.body, encoding: .utf8) ?? ""
                if (200..<300).contains(response.status) {
                    append(.success(
                        endpoint: endpoint,
                        signature: response.settlementSignature,
                        body: bodyString
                    ))
                    await refreshBalance()
                } else {
                    append(.failure(endpoint: endpoint, message: "HTTP \(response.status)\n\(bodyString)"))
                }
            } catch {
                append(.failure(endpoint: endpoint, message: String(describing: error)))
            }
            return
        }

        // Other non-charge intents (subscription) are multi-step flows with
        // dedicated pay-kit APIs the tap demo doesn't drive.
        guard endpoint.intent == .charge else {
            append(.failure(
                endpoint: endpoint,
                message: "\(endpoint.label) is an mpp/\(endpoint.intent.label) flow this demo doesn't drive; use the matching pay-kit API."
            ))
            return
        }

        let url = playgroundURL.appendingPathComponent(endpoint.path)

        busy = .pay(endpoint.id)
        defer { busy = nil }

        // Settle over the protocol the user picked (default: the advertised mpp).
        let selected = protocolChoice[endpoint.id] ?? endpoint.selectedProtocol
        let client: PayKit.HttpClient
        if selected == "x402" {
            client = PayKit.HttpClient.x402(
                signer: signer,
                rpc: RpcClient(endpoint: rpcURL),
                selection: X402ChallengeSelection(),
                // x402 settles in the `Payment-Response` header (a base64
                // envelope whose `transaction` field is the on-chain
                // signature), not the MPP `Payment-Receipt` header. Read
                // that so the signature surfaces instead of "no receipt".
                settlementHeader: "payment-response"
            )
        } else {
            client = PayKit.HttpClient.mpp(
                signer: signer,
                rpc: RpcClient(endpoint: rpcURL),
                settlementHeader: "payment-receipt"
            )
        }
        var headers: [String: String] = ["Accept": "application/json"]
        var body: Data? = nil
        if endpoint.method == .post {
            headers["Content-Type"] = "application/json"
            body = Data("{}".utf8)
        }

        do {
            let response = try await client
                .request(url, method: endpoint.method, headers: headers, body: body)
                .response()
            let bodyString = String(data: response.body, encoding: .utf8) ?? ""
            if (200..<300).contains(response.status) {
                // `response.settlementSignature` is the raw `Payment-Receipt`
                // header — a base64url-no-pad JSON envelope produced by
                // the gateway's `format_receipt`. The bare on-chain
                // signature lives in the envelope's `reference` field;
                // that's what the pay.sh receipt page expects in its
                // `/receipt/<sig>` path.
                // MPP wraps the signature in a base64url Payment-Receipt envelope
                // (`reference` field); x402 returns the bare settlement signature.
                // Decode the envelope when present, else use the raw value.
                let signature = response.settlementSignature.flatMap(Self.signatureFromReceiptHeader)
                    ?? response.settlementSignature
                append(.success(
                    endpoint: endpoint,
                    signature: signature,
                    body: bodyString
                ))
                await refreshBalance()
            } else {
                append(.failure(
                    endpoint: endpoint,
                    message: "HTTP \(response.status)\n\(bodyString)"
                ))
            }
        } catch {
            append(.failure(endpoint: endpoint, message: String(describing: error)))
        }
    }

    // MARK: - Helpers

    private func append(_ entry: LogEntry) {
        log.insert(entry, at: 0)
    }

    /// Truncate a base58 pubkey to `first6…last6`. The full address is
    /// in the Log when the account is created, and the field is
    /// `.textSelection(.enabled)` so users can long-press the
    /// truncated form to copy if they need the full value.
    static func shortAddress(_ address: String) -> String {
        guard address.count > 14 else { return address }
        return "\(address.prefix(6))…\(address.suffix(6))"
    }

    private static let usdcFormatter: NumberFormatter = {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 6
        return f
    }()

    static func formatUSDC(_ amount: Decimal) -> String {
        let formatted = usdcFormatter.string(from: amount as NSDecimalNumber) ?? "\(amount)"
        return "\(formatted) USDC"
    }

    /// Format USDC base units (6 decimals) as a dollar string for the log.
    static func formatBaseUnitsUSD(_ baseUnits: UInt64) -> String {
        let dollars = Decimal(baseUnits) / 1_000_000
        let formatted = usdcFormatter.string(from: dollars as NSDecimalNumber) ?? "\(dollars)"
        return "$\(formatted)"
    }

    /// Decode a settlement header (base64url-no-pad JSON envelope) and return
    /// the on-chain signature. MPP's `Payment-Receipt` carries it in
    /// `reference`; x402's `X-PAYMENT-RESPONSE` carries it in `transaction`.
    static func signatureFromReceiptHeader(_ header: String) -> String? {
        // Re-pad and translate URL-safe alphabet to standard base64 so
        // Foundation's decoder accepts it.
        var s = header
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - s.count % 4) % 4
        s.append(String(repeating: "=", count: pad))
        guard let data = Data(base64Encoded: s),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        let signature = (json["reference"] as? String) ?? (json["transaction"] as? String)
        return (signature?.isEmpty == false) ? signature : nil
    }

    @ViewBuilder
    private func busyRow(title: String, icon: String, active: Bool) -> some View {
        HStack {
            Label(title, systemImage: icon)
            Spacer()
            if active {
                ProgressView()
            }
        }
    }
}

// MARK: - Endpoint

/// Discovery intent of an offer. `.other` preserves any value the demo does not
/// special-case so an unknown gateway intent still renders.
enum EndpointIntent: Hashable {
    case charge
    case session
    case subscription
    case other(String)

    /// Map a wire intent (defaulting an absent value to `charge`, as the demo
    /// did before).
    init(_ raw: String?) {
        switch raw?.lowercased() {
        case "session": self = .session
        case "subscription": self = .subscription
        case let value? where !value.isEmpty && value != "charge": self = .other(value)
        default: self = .charge
        }
    }

    /// Wire label for display.
    var label: String {
        switch self {
        case .charge: return "charge"
        case .session: return "session"
        case .subscription: return "subscription"
        case let .other(value): return value
        }
    }
}

/// Payment scheme of an offer. `.other` preserves unknown schemes.
enum EndpointScheme: Hashable {
    case exact
    case upto
    case other(String)

    /// Map a wire scheme, or `nil` when the offer carries none.
    init?(_ raw: String?) {
        guard let raw = raw?.lowercased(), !raw.isEmpty else { return nil }
        switch raw {
        case "exact": self = .exact
        case "upto": self = .upto
        default: self = .other(raw)
        }
    }
}

/// A priced operation discovered from the playground's `/openapi.json`,
/// rendered as a tappable card in the endpoints collection.
struct Endpoint: Identifiable, Hashable {
    let id: String
    let label: String
    let method: PayKit.HTTPMethod
    let path: String
    let priceUSD: String
    let systemImage: String
    let tint: Color
    /// Discovery intent of the first offer; the demo only settles `charge` over
    /// MPP and explains the rest.
    let intent: EndpointIntent
    /// Scheme of the first offer when present. A metered `upto` route advertises
    /// the generic `charge` intent, so the demo routes by this scheme to reach
    /// the usage flow.
    let scheme: EndpointScheme?
    /// Accepted protocols in offer order, e.g. `["x402", "mpp"]`.
    let methods: [String]
    /// The protocol this demo actually settles over (`mpp` for charge endpoints
    /// that advertise it); `nil` for flows the demo doesn't consume. Rendered
    /// emphasized on the card so it's clear which offer is used.
    let selectedProtocol: String?
}

// MARK: - Endpoint card

private struct EndpointCard: View {
    let endpoint: Endpoint
    let busy: Bool
    /// The protocol currently selected to settle over (the user's tap choice, or
    /// the default). Rendered emphasized.
    let selected: String?
    let onTap: () -> Void
    let onSelect: (String) -> Void

    /// Charge endpoints that advertise more than one protocol let the user pick
    /// which to settle over by tapping a method chip.
    private var selectable: Bool { endpoint.intent == .charge && endpoint.methods.count > 1 }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: endpoint.systemImage)
                    .font(.title2)
                Spacer()
                if busy {
                    ProgressView()
                        .tint(.white)
                } else {
                    Text(endpoint.method.rawValue)
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.white.opacity(0.25))
                        .clipShape(Capsule())
                }
            }
            Spacer(minLength: 0)
            Text(endpoint.label)
                .font(.subheadline.weight(.semibold))
                .multilineTextAlignment(.leading)
                .lineLimit(2)
            Text(endpoint.priceUSD)
                .font(.caption.monospacedDigit())
                .opacity(0.9)
            HStack(spacing: 3) {
                ForEach(Array(endpoint.methods.enumerated()), id: \.offset) { index, method in
                    if index > 0 { Text("·").opacity(0.45) }
                    let isSelected = method == selected
                    Text(method)
                        .fontWeight(isSelected ? .bold : .regular)
                        .opacity(isSelected ? 1.0 : 0.55)
                        .underline(isSelected && selectable)
                        .contentShape(Rectangle())
                        .onTapGesture { if selectable { onSelect(method) } }
                }
                if endpoint.intent != .charge {
                    Text("·").opacity(0.45)
                    Text(endpoint.intent.label).opacity(0.55)
                }
            }
            .font(.caption2)
            .lineLimit(1)
        }
        .padding(12)
        .frame(width: 150, height: 130, alignment: .topLeading)
        .background(endpoint.tint.gradient)
        .foregroundStyle(.white)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .contentShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .onTapGesture { onTap() }
    }
}

// MARK: - Log

struct LogEntry: Identifiable {
    enum Kind {
        case success(endpoint: Endpoint, signature: String?, body: String)
        case failure(endpoint: Endpoint?, message: String)
        case system(message: String, success: Bool)
    }

    let id = UUID()
    let timestamp: Date
    let kind: Kind

    static func success(endpoint: Endpoint, signature: String?, body: String) -> LogEntry {
        LogEntry(timestamp: Date(), kind: .success(endpoint: endpoint, signature: signature, body: body))
    }
    static func failure(endpoint: Endpoint? = nil, message: String) -> LogEntry {
        LogEntry(timestamp: Date(), kind: .failure(endpoint: endpoint, message: message))
    }
    static func system(_ message: String, success: Bool) -> LogEntry {
        LogEntry(timestamp: Date(), kind: .system(message: message, success: success))
    }
}

private struct LogRow: View {
    let entry: LogEntry

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                icon
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text(Self.timeFormatter.string(from: entry.timestamp))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            detail
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder
    private var icon: some View {
        switch entry.kind {
        case .success: Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
        case .failure: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
        case .system(_, let ok): Image(systemName: ok ? "info.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(ok ? .blue : .orange)
        }
    }

    private var title: String {
        switch entry.kind {
        case .success(let endpoint, _, _): return "\(endpoint.label) — 200 OK"
        case .failure(let endpoint, _):    return endpoint.map { "\($0.label) — failed" } ?? "Error"
        case .system:                       return "System"
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch entry.kind {
        case .success(_, let signature, let body):
            if let signature {
                Text(signature)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(2)
                if let url = receiptURL(signature: signature) {
                    Link("View receipt on pay.sh", destination: url)
                        .font(.footnote)
                }
            } else {
                Text("Settled. No settlement signature in response.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if !body.isEmpty {
                Text(body)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(4)
            }
        case .failure(_, let message):
            Text(message)
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .lineLimit(6)
        case .system(let message, _):
            Text(message)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }

    private func receiptURL(signature: String) -> URL? {
        // pay.sh route is singular `/receipt/<signature>` and expects
        // the bare base58 signature (not the receipt envelope).
        // `network=sandbox` covers Surfpool / localnet RPCs; mainnet
        // is the default when the param is omitted.
        var components = URLComponents(string: "https://pay.sh/receipt/\(signature)")
        components?.queryItems = [URLQueryItem(name: "network", value: "sandbox")]
        return components?.url
    }
}

// MARK: - Busy state

private enum BusyKind: Equatable {
    case topup
    case pay(String)
}

#Preview {
    ContentView()
}
