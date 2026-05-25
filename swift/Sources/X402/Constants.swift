import Foundation

public enum X402 {
    public static let paymentSignatureHeader = "PAYMENT-SIGNATURE"
    public static let paymentRequiredHeader = "PAYMENT-REQUIRED"
    public static let xPaymentRequiredHeader = "X-PAYMENT-REQUIRED"
    public static let x402Version = 2
    public static let exactScheme = "exact"
    public static let solanaDevnet = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    public static let solanaMainnet = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    public static let solanaTestnet = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
    public static let tokenProgram = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    public static let token2022Program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
    public static let associatedTokenProgram = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
    public static let computeBudgetProgram = "ComputeBudget111111111111111111111111111111"
    public static let memoProgram = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
    public static let maxMemoBytes = 256
}

public enum X402Error: Error, Equatable, CustomStringConvertible {
    case invalidBase58(String)
    case invalidSecretKeyLength(Int)
    case invalidSecretKeyByte(Int)
    case invalidSignatureLength(Int)
    case invalidAmount(String)
    case unsupportedScheme(String)
    case unsupportedNetwork(String)
    case unsupportedX402Version(Int)
    case missingFeePayer
    case missingBlockhash
    case missingChallenge
    case memoTooLarge(Int)
    case invalidDecimals(Double)
    case publicKeyMismatch(expected: String, derived: String)
    case unsupportedTokenProgram(String)
    case rpc(String)

    public var description: String {
        switch self {
        case .invalidBase58(let value): return "invalid base58 value: \(value)"
        case .invalidSecretKeyLength(let count): return "expected a 64-byte Solana secret key, got \(count)"
        case .invalidSecretKeyByte(let value): return "secret-key element is out of UInt8 range: \(value)"
        case .invalidSignatureLength(let count): return "expected a 64-byte signature, got \(count)"
        case .invalidAmount(let value): return "invalid exact amount: \(value)"
        case .unsupportedScheme(let value): return "unsupported x402 scheme: \(value)"
        case .unsupportedNetwork(let value): return "unsupported x402 network: \(value)"
        case .unsupportedX402Version(let value): return "unsupported x402Version: \(value) (expected \(X402.x402Version))"
        case .missingFeePayer: return "payment requirement is missing extra.feePayer"
        case .missingBlockhash: return "payment requirement is missing a recent blockhash and no RPC client was provided"
        case .missingChallenge: return "server did not return a supported SVM x402 challenge"
        case .memoTooLarge(let count): return "extra.memo exceeds \(X402.maxMemoBytes) bytes: \(count)"
        case .invalidDecimals(let value): return "invalid extra.decimals value: \(value) (must be an integer in 0...255)"
        case .publicKeyMismatch(let expected, let derived): return "secret key public component \(derived) does not match supplied address \(expected)"
        case .unsupportedTokenProgram(let value): return "unsupported extra.tokenProgram: \(value) (allowed: \(X402.tokenProgram), \(X402.token2022Program))"
        case .rpc(let value): return value
        }
    }
}
