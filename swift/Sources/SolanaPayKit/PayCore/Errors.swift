import Foundation

/// Shared payment-core error. Lives in `PayCore` (not the MPP package) so both
/// the MPP and x402 protocol layers can throw it without depending on each other.
public enum PayKitError: Error, Equatable {
    case invalidBase64URL
    case invalidBase58
    case invalidHeader
    case invalidJSON(String)
    case invalidPaymentScheme
    case invalidPubkey(String)
    case invalidTransaction(String)
    case missingField(String)
    case rpcFailure(String)
    case signingFailure(String)
    case unsupportedChallenge(method: String, intent: String)
}
