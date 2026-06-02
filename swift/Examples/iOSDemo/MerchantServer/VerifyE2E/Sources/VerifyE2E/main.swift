// Standalone Swift driver that exercises the same code path as the
// iOSDemo app (PayKit.HttpClient.mpp + MemorySigner with the demo seed) against
// a running Surfpool + MerchantServer stack. Useful for verifying the
// stack outside the Simulator and for the PR's evidence trail.
//
// Run from this directory:
//
//     swift run
//
// Requires:
//   - Surfpool: http://127.0.0.1:8899
//   - Merchant: http://127.0.0.1:3004/fortune
import Foundation
import SolanaPayKit

let seed = Data([
    0x69, 0x4f, 0x53, 0x2d, 0x44, 0x45, 0x4d, 0x4f,
    0x2d, 0x53, 0x45, 0x45, 0x44, 0x2d, 0x44, 0x4f,
    0x2d, 0x4e, 0x4f, 0x54, 0x2d, 0x55, 0x53, 0x45,
    0x2d, 0x49, 0x4e, 0x2d, 0x50, 0x52, 0x4f, 0x44,
])

let merchantURL = URL(string: ProcessInfo.processInfo.environment["MERCHANT_URL"]
    ?? "http://127.0.0.1:3004/fortune")!
let rpcURL = URL(string: ProcessInfo.processInfo.environment["RPC_URL"]
    ?? "http://127.0.0.1:8899")!

let exitCode = await { () -> Int32 in
    do {
        let signer = try MemorySigner(secretKey: seed)
        print("[verify] signer address: \(signer.address)")
        let client = PayKit.HttpClient.mpp(
            signer: signer,
            rpc: RpcClient(endpoint: rpcURL),
            settlementHeader: "payment-receipt"
        )
        let response = try await client
            .request(merchantURL, headers: ["Accept": "application/json"])
            .response()
        let body = String(data: response.body, encoding: .utf8) ?? ""
        print("[verify] HTTP \(response.status)")
        print("[verify] settlement signature: \(response.settlementSignature ?? "(none)")")
        print("[verify] body: \(body)")
        return (200..<300).contains(response.status) ? 0 : 1
    } catch {
        print("[verify] error: \(error)")
        return 2
    }
}()
exit(exitCode)
