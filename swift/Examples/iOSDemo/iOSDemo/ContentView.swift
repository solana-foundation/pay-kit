import SwiftUI
import SolanaMpp

struct ContentView: View {
    // Defaults match the local Surfpool + MerchantServer setup. Edit in
    // the UI to point at a different stack (e.g. `https://402.surfnet.dev:8899`
    // for the hosted Surfpool RPC, or a deployed merchant).
    @State private var rpcURLString: String = "http://127.0.0.1:8899"
    @State private var merchantURLString: String = "http://127.0.0.1:3004/fortune"

    @State private var status: ChargeStatus = .idle
    @State private var isCharging: Bool = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Signer") {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Address")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(DemoSigner.shared.address)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    Text("Demo seeded keypair. Replace with Mobile Wallet Adapter or Seeker Seed Vault for production (issue #113).")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }

                Section("Endpoints") {
                    TextField("Solana RPC URL", text: $rpcURLString)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    TextField("Merchant URL", text: $merchantURLString)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                }

                Section {
                    Button {
                        Task { await pay() }
                    } label: {
                        HStack {
                            Spacer()
                            if isCharging {
                                ProgressView().padding(.trailing, 8)
                            }
                            Text(isCharging ? "Paying…" : "Pay")
                                .font(.headline)
                            Spacer()
                        }
                    }
                    .disabled(isCharging)
                }

                Section("Result") {
                    resultView
                }
            }
            .navigationTitle("MPP iOS Demo")
        }
        .task {
            // Headless screenshot hook for CI / PR evidence: when launched
            // with `MPP_AUTO_PAY=1`, fire the pay flow once on appear so a
            // screencap captures the success state without UI interaction.
            // No-op for normal users.
            if ProcessInfo.processInfo.environment["MPP_AUTO_PAY"] == "1" {
                await pay()
            }
        }
    }

    @ViewBuilder
    private var resultView: some View {
        switch status {
        case .idle:
            Text("Tap Pay to send a charge credential to the merchant.")
                .foregroundStyle(.secondary)
        case .success(let outcome):
            VStack(alignment: .leading, spacing: 8) {
                Label("Charge succeeded (HTTP 200)", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                if let signature = outcome.signature {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("On-chain signature")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(signature)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                        if let explorer = explorerURL(signature: signature, rpc: rpcURLString) {
                            Link("View on Solana Explorer", destination: explorer)
                                .font(.footnote)
                        }
                    }
                } else {
                    Text("No `Payment-Receipt` header in response.")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
                if !outcome.body.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Response body")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(outcome.body)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }
        case .failure(let message):
            VStack(alignment: .leading, spacing: 8) {
                Label("Charge failed", systemImage: "xmark.octagon.fill")
                    .foregroundStyle(.red)
                Text(message)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
    }

    private func pay() async {
        isCharging = true
        defer { isCharging = false }
        status = .idle

        guard let merchantURL = URL(string: merchantURLString) else {
            status = .failure("Merchant URL is not a valid URL")
            return
        }
        guard let rpcURL = URL(string: rpcURLString) else {
            status = .failure("RPC URL is not a valid URL")
            return
        }

        let client = MppHTTPClient(
            signer: DemoSigner.shared,
            rpc: RpcClient(endpoint: rpcURL)
        )
        do {
            // The Python `payment_link_server.py` example surfaces the
            // settlement signature in the `Payment-Receipt` header.
            let response = try await client.fetch(
                url: merchantURL,
                method: "GET",
                additionalHeaders: ["Accept": "application/json"],
                body: nil,
                settlementHeader: "payment-receipt"
            )
            if (200..<300).contains(response.status) {
                let body = String(data: response.body, encoding: .utf8) ?? ""
                status = .success(ChargeOutcome(
                    signature: response.settlementSignature,
                    body: body
                ))
            } else {
                let body = String(data: response.body, encoding: .utf8) ?? ""
                status = .failure("HTTP \(response.status)\n\(body)")
            }
        } catch {
            status = .failure(String(describing: error))
        }
    }

    private func explorerURL(signature: String, rpc: String) -> URL? {
        // Surfpool localnet and the hosted `402.surfnet.dev` RPC are not
        // crawled by the public Solana Explorer, so the link uses the
        // custom-cluster form pointing at the configured RPC. On
        // mainnet, switch this to the default cluster.
        var components = URLComponents(string: "https://explorer.solana.com/tx/\(signature)")
        components?.queryItems = [
            URLQueryItem(name: "cluster", value: "custom"),
            URLQueryItem(name: "customUrl", value: rpc),
        ]
        return components?.url
    }
}

private enum ChargeStatus {
    case idle
    case success(ChargeOutcome)
    case failure(String)
}

private struct ChargeOutcome {
    let signature: String?
    let body: String
}

#Preview {
    ContentView()
}
