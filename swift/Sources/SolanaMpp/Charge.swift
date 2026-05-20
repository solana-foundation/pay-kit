import Foundation

public protocol ChargeTransactionProviding: Sendable {
    func buildTransaction(for request: ChargeRequest) async throws -> String
}

public struct StaticChargeTransactionProvider: ChargeTransactionProviding, Sendable {
    private let transaction: String

    public init(transaction: String) {
        self.transaction = transaction
    }

    public func buildTransaction(for request: ChargeRequest) async throws -> String {
        transaction
    }
}

public struct ChargeCredentialBuilder: Sendable {
    private let transactionProvider: any ChargeTransactionProviding

    public init(transactionProvider: any ChargeTransactionProviding) {
        self.transactionProvider = transactionProvider
    }

    public func authorizationHeader(for challenge: PaymentChallenge) async throws -> String {
        try challenge.requireSolanaCharge()

        let transaction = try await transactionProvider.buildTransaction(for: challenge.chargeRequest)
        let credential = PaymentCredential(
            challenge: challenge.echo(),
            payload: .transaction(transaction)
        )
        return try MppHeaders.formatAuthorization(credential)
    }
}
