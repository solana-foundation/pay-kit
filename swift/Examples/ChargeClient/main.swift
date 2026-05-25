// Minimal charge-client example. Run via:
//   swift run -c release ChargeClient https://target.example.com/paid
//
// Wire it into Package.swift as an executable target locally when you
// want to iterate; kept source-only here so the default `swift build`
// stays library-only.

import Foundation
import SolanaMpp

@main
struct ChargeClient {
    static func main() async throws {
        guard CommandLine.arguments.count >= 2,
              let target = URL(string: CommandLine.arguments[1])
        else {
            FileHandle.standardError.write(Data("usage: ChargeClient <url>\n".utf8))
            return
        }

        guard let keyHex = ProcessInfo.processInfo.environment["MPP_CLIENT_SECRET_KEY_HEX"],
              let secretKey = Data(hexString: keyHex)
        else {
            FileHandle.standardError.write(Data("set MPP_CLIENT_SECRET_KEY_HEX\n".utf8))
            return
        }

        let signer = try MemorySigner(secretKey: secretKey)
        let rpc = RpcClient(endpoint: URL(string: "https://402.surfnet.dev")!)
        let client = MppHTTPClient(signer: signer, rpc: rpc)

        let response = try await client.fetch(url: target)
        print("status:    \(response.status)")
        if let sig = response.settlementSignature {
            print("signature: \(sig)")
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
