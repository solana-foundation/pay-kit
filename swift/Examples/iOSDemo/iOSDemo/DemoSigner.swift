import Foundation
import SolanaPayKit

// ⚠️⚠️⚠️ DO NOT USE IN PRODUCTION ⚠️⚠️⚠️
//
// This file ships a hard-coded 32-byte Ed25519 seed inside the app binary
// so the demo is reproducible on Surfpool: the derived public key is
// always `B8pEG2UVbzLLSaZnN15UHVza7Ugk3HtfDaxUB4FbZ2xm`, which the
// `MerchantServer/serve.py` script pre-funds with SOL and USDC on
// startup. The corresponding private key is therefore PUBLIC; anyone
// reading this repo can sign as that account.
//
// For real applications, swap `DemoSigner.shared` for a `SolanaSigner`
// implementation that delegates signing to either:
//
//   - Solana Mobile Wallet Adapter (the canonical path for production
//     Solana iOS / Android apps), or
//   - Solana Seeker Seed Vault (hardware-backed signer on Seeker
//     devices). This is the deferred follow-up tracked in issue #113
//     acceptance criteria item 6.
//
// The `SolanaSigner` protocol in `Sources/SolanaPayKit/SolanaSigner.swift`
// is the single integration point; nothing else in the demo needs to
// change to switch signers.
enum DemoSigner {
    /// Reproducible 32-byte seed. Matches the address funded by the
    /// `MerchantServer/serve.py` helper script.
    static let seed: Data = Data([
        0x69, 0x4f, 0x53, 0x2d, 0x44, 0x45, 0x4d, 0x4f,
        0x2d, 0x53, 0x45, 0x45, 0x44, 0x2d, 0x44, 0x4f,
        0x2d, 0x4e, 0x4f, 0x54, 0x2d, 0x55, 0x53, 0x45,
        0x2d, 0x49, 0x4e, 0x2d, 0x50, 0x52, 0x4f, 0x44,
    ])

    /// Cached signer instance.
    static let shared: MemorySigner = {
        do {
            return try MemorySigner(secretKey: seed)
        } catch {
            // Seed is a static 32-byte constant; this initializer cannot
            // fail in practice. Crash loudly if it ever does so a
            // future bad edit is caught at first launch.
            fatalError("DemoSigner seed is invalid: \(error)")
        }
    }()
}
