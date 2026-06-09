import SwiftUI
import SolanaPayKit

struct ContentView: View {
    // Hardcoded for the demo. `pay server demo` binds the gateway to
    // `0.0.0.0:1402` and routes settlement through the hosted Surfpool
    // sandbox at `402.surfnet.dev:8899`. To target a local Surfpool
    // instead (`pay server demo --local`), edit these two constants.
    private let rpcURL = URL(string: "https://402.surfnet.dev:8899")!
    private let gatewayURL = URL(string: "http://127.0.0.1:1402")!

    @State private var signer: MemorySigner?
    @State private var usdcBalance: Decimal?
    @State private var log: [LogEntry] = []
    @State private var busy: BusyKind?

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
        Section("Endpoints (\(gatewayURL.absoluteString))") {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 12) {
                    ForEach(EndpointCatalog.all) { endpoint in
                        EndpointCard(endpoint: endpoint, busy: busy == .pay(endpoint.id)) {
                            Task { await pay(endpoint) }
                        }
                        .disabled(busy != nil || signer == nil)
                    }
                }
                .padding(.vertical, 4)
            }
            .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))

            if signer == nil {
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

    private func pay(_ endpoint: Endpoint) async {
        guard let signer else { return }
        let url = gatewayURL.appendingPathComponent(endpoint.path)

        busy = .pay(endpoint.id)
        defer { busy = nil }

        let client = PayKit.HttpClient.mpp(
            signer: signer,
            rpc: RpcClient(endpoint: rpcURL),
            settlementHeader: "payment-receipt"
        )
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
                let signature = response.settlementSignature.flatMap(Self.signatureFromReceiptHeader)
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

    /// Decode a `Payment-Receipt` header (base64url-no-pad JSON envelope
    /// produced by the gateway's `format_receipt`) and return the
    /// `reference` field — the on-chain signature.
    static func signatureFromReceiptHeader(_ header: String) -> String? {
        // Re-pad and translate URL-safe alphabet to standard base64 so
        // Foundation's decoder accepts it.
        var s = header
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - s.count % 4) % 4
        s.append(String(repeating: "=", count: pad))
        guard let data = Data(base64Encoded: s),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let reference = json["reference"] as? String,
              !reference.isEmpty
        else { return nil }
        return reference
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

// MARK: - Endpoint catalog

struct Endpoint: Identifiable, Hashable {
    let id: String
    let label: String
    let method: PayKit.HTTPMethod
    let path: String
    let priceUSD: String
    let systemImage: String
    let tint: Color
}

enum EndpointCatalog {
    static let all: [Endpoint] = [
        Endpoint(
            id: "reports-usage",
            label: "Usage Report",
            method: .get,
            path: "api/v1/reports/usage",
            priceUSD: "$0.01",
            systemImage: "chart.bar.fill",
            tint: .blue
        ),
        Endpoint(
            id: "compute-run",
            label: "Compute Job",
            method: .post,
            path: "api/v1/compute/run",
            priceUSD: "$0.10",
            systemImage: "cpu",
            tint: .indigo
        ),
        Endpoint(
            id: "subscriptions-charge",
            label: "Subscription",
            method: .post,
            path: "api/v1/subscriptions/charge",
            priceUSD: "$49.99",
            systemImage: "repeat.circle.fill",
            tint: .purple
        ),
        Endpoint(
            id: "invoices-pay",
            label: "Pay Invoice",
            method: .post,
            path: "api/v1/invoices/pay",
            priceUSD: "$100",
            systemImage: "doc.text.fill",
            tint: .pink
        ),
        Endpoint(
            id: "referrals-purchase",
            label: "Referral Purchase",
            method: .post,
            path: "api/v1/referrals/purchase",
            priceUSD: "$199",
            systemImage: "person.2.fill",
            tint: .orange
        ),
        Endpoint(
            id: "orders-checkout",
            label: "Checkout",
            method: .post,
            path: "api/v1/orders/checkout",
            priceUSD: "$250",
            systemImage: "cart.fill",
            tint: .green
        ),
        Endpoint(
            id: "settlements-disburse",
            label: "Disbursement",
            method: .post,
            path: "api/v1/settlements/disburse",
            priceUSD: "$1000",
            systemImage: "banknote.fill",
            tint: .red
        ),
    ]
}

// MARK: - Endpoint card

private struct EndpointCard: View {
    let endpoint: Endpoint
    let busy: Bool
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
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
            }
            .padding(12)
            .frame(width: 150, height: 130, alignment: .topLeading)
            .background(endpoint.tint.gradient)
            .foregroundStyle(.white)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        }
        .buttonStyle(.plain)
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
                Text("No `Payment-Receipt` header in response.")
                    .font(.footnote)
                    .foregroundStyle(.orange)
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
