import Foundation

public protocol SolanaSigner: Sendable {
    var publicKey: Data { get }
    var address: String { get }

    func sign(message: Data) async throws -> Data
}

public struct MemorySigner: SolanaSigner, Sendable {
    public let publicKey: Data
    public let address: String

    private let signHandler: @Sendable (Data) async throws -> Data

    public init(
        publicKey: Data,
        address: String,
        sign: @escaping @Sendable (Data) async throws -> Data
    ) {
        self.publicKey = publicKey
        self.address = address
        self.signHandler = sign
    }

    public init(publicKey: Data, address: String, signature: Data) {
        self.init(publicKey: publicKey, address: address) { _ in signature }
    }

    public func sign(message: Data) async throws -> Data {
        try await signHandler(message)
    }
}
