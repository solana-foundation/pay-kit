import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct JsonRpcBlockhashProvider: RecentBlockhashProvider {
    private let rpcURL: URL

    public init(rpcURL: URL) {
        self.rpcURL = rpcURL
    }

    public func getLatestBlockhash() async throws -> String {
        var request = URLRequest(url: rpcURL)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "content-type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [["commitment": "confirmed"]],
        ])
        let (data, _) = try await URLSession.shared.data(for: request)
        let response = try JSONDecoder().decode(BlockhashResponse.self, from: data)
        guard let blockhash = response.result?.value.blockhash else {
            throw X402Error.rpc(String(data: data, encoding: .utf8) ?? "missing blockhash")
        }
        return blockhash
    }
}

private struct BlockhashResponse: Decodable {
    struct Result: Decodable {
        struct Value: Decodable {
            let blockhash: String
        }
        let value: Value
    }
    let result: Result?
}
