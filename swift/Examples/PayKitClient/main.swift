// Headless `SolanaPayKit` CLI driver. Probes a 402-gated resource and
// settles the payment through either the MPP charge intent or the x402
// exact intent, depending on the first positional argument.
//
// Run via:
//   swift run -c release PayKitClient mpp  https://target.example.com/paid
//   swift run -c release PayKitClient x402 https://target.example.com/paid
//
// Wire it into Package.swift as an executable target locally when you
// want to iterate; kept source-only here so the default `swift build`
// stays library-only.
//
// Env:
//   PAYKIT_CLIENT_SECRET_KEY_HEX  - 32-byte Ed25519 seed (hex)
//   PAYKIT_RPC_URL                - Solana RPC URL
//                                   (default https://402.surfnet.dev:8899)
//   PAYKIT_NETWORK                - x402 only: CAIP-2 id or cluster slug
//                                   (default devnet)
//   PAYKIT_PREFER_CURRENCIES      - x402 only: comma-separated preference list

import Foundation
import SolanaPayKit

@main
struct PayKitClient {
    static func main() async throws {
        let args = CommandLine.arguments
        guard args.count >= 3,
              let proto = Protocol_(rawValue: args[1].lowercased()),
              let target = URL(string: args[2])
        else {
            FileHandle.standardError.write(Data(
                "usage: PayKitClient <mpp|x402> <url>\n".utf8
            ))
            return
        }

        let env = ProcessInfo.processInfo.environment

        guard let keyHex = env["PAYKIT_CLIENT_SECRET_KEY_HEX"],
              let secretKey = Data(hexString: keyHex)
        else {
            FileHandle.standardError.write(Data(
                "set PAYKIT_CLIENT_SECRET_KEY_HEX\n".utf8
            ))
            return
        }

        let rpcURL = URL(string: env["PAYKIT_RPC_URL"] ?? "https://402.surfnet.dev:8899")!
        let signer = try MemorySigner(secretKey: secretKey)
        let rpc = RpcClient(endpoint: rpcURL)

        let client: PayKit.HttpClient
        switch proto {
        case .mpp:
            client = PayKit.HttpClient.mpp(signer: signer, rpc: rpc)
        case .x402:
            let network = env["PAYKIT_NETWORK"] ?? SolanaNetwork.devnet
            let currencies = env["PAYKIT_PREFER_CURRENCIES"]
                .map { $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } }
                .map { $0.filter { !$0.isEmpty } }
                .flatMap { $0.isEmpty ? nil : $0 }
            let selection = X402ChallengeSelection(network: network, currencies: currencies)
            client = PayKit.HttpClient.x402(signer: signer, rpc: rpc, selection: selection)
        }

        let response = try await client.request(target).response()
        print("protocol:   \(proto.rawValue)")
        print("status:     \(response.status)")
        if let sig = response.settlementSignature {
            print("settlement: \(sig)")
        }
        if response.paymentSent != nil {
            print("paid:       yes")
        }
    }
}

// Underscore suffix avoids shadowing the Swift `Protocol` keyword.
private enum Protocol_: String {
    case mpp
    case x402
}

private extension Data {
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let byte = UInt8(String(chars[i...i + 1]), radix: 16) else { return nil }
            bytes.append(byte)
        }
        self.init(bytes)
    }
}
