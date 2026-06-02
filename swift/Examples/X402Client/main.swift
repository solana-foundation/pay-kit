// Minimal x402 exact client example. Run via:
//   swift run -c release X402Client https://target.example.com/paid
//
// Mirrors the ChargeClient example: a headless x402 client that probes a
// gated resource, builds the Payment-Signature header through a signer, and
// replays the request once. Wire it into Package.swift as an executable
// target locally when you want to iterate; kept source-only here so the
// default `swift build` stays library-only.
//
// Env:
//   MPP_CLIENT_SECRET_KEY_HEX  - 32-byte Ed25519 seed (hex)
//   X402_RPC_URL               - Solana RPC for the blockhash fallback
//                                (default https://api.devnet.solana.com)
//   X402_NETWORK               - CAIP-2 id or cluster slug (default devnet)
//   X402_PREFER_CURRENCIES     - optional comma-separated preference list

import Foundation
import SolanaPayKit

@main
struct X402Client {
    static func main() async throws {
        guard CommandLine.arguments.count >= 2,
              let target = URL(string: CommandLine.arguments[1])
        else {
            FileHandle.standardError.write(Data("usage: X402Client <url>\n".utf8))
            return
        }

        let env = ProcessInfo.processInfo.environment

        guard let keyHex = env["MPP_CLIENT_SECRET_KEY_HEX"],
              let secretKey = Data(hexString: keyHex)
        else {
            FileHandle.standardError.write(Data("set MPP_CLIENT_SECRET_KEY_HEX\n".utf8))
            return
        }

        let rpcURL = URL(string: env["X402_RPC_URL"] ?? "https://api.devnet.solana.com")!
        let network = env["X402_NETWORK"] ?? SolanaNetwork.devnet
        let currencies = env["X402_PREFER_CURRENCIES"]
            .map { $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } }
            .map { $0.filter { !$0.isEmpty } }
            .flatMap { $0.isEmpty ? nil : $0 }

        let signer = try MemorySigner(secretKey: secretKey)
        let rpc = RpcClient(endpoint: rpcURL)
        let selection = X402ChallengeSelection(network: network, currencies: currencies)
        let client = PayKit.HttpClient.x402(signer: signer, rpc: rpc, selection: selection)

        let response = try await client.request(target).response()
        print("status:      \(response.status)")
        if let sig = response.settlementSignature {
            print("settlement:  \(sig)")
        }
        if response.paymentSent != nil {
            print("paid:        yes (Payment-Signature sent)")
        }
    }
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
