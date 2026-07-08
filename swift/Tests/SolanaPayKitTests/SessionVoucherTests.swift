import Foundation
import Testing
@testable import SolanaPayKit

/// Byte-exact golden vectors for the payment-channel voucher preimage and the
/// channel PDA, mirroring the Rust spine tests
/// (`voucher_message_is_program_borsh_layout`, `channel_pda_is_stable`).
@Suite("Session voucher preimage + PDA")
struct SessionVoucherTests {
    @Test
    func voucherPreimageIsBorshLayout() throws {
        let channel = try Pubkey(bytes: Data(repeating: 9, count: 32))
        let bytes = PaymentChannels.voucherMessageBytes(channelId: channel, cumulative: 42, expiresAt: 1234)

        #expect(bytes.count == 48)
        #expect(Array(bytes[0..<32]) == Array(repeating: 9, count: 32))
        // 42 little-endian u64.
        #expect(Array(bytes[32..<40]) == [42, 0, 0, 0, 0, 0, 0, 0])
        // 1234 = 0x04D2 little-endian i64.
        #expect(Array(bytes[40..<48]) == [0xD2, 0x04, 0, 0, 0, 0, 0, 0])
    }

    @Test
    func voucherPreimageEncodesNegativeExpiryAsTwosComplement() throws {
        let channel = try Pubkey(bytes: Data(repeating: 1, count: 32))
        // i64 -1 → all 0xFF.
        let bytes = PaymentChannels.voucherMessageBytes(channelId: channel, cumulative: 0, expiresAt: -1)
        #expect(Array(bytes[40..<48]) == Array(repeating: 0xFF, count: 8))
    }

    @Test
    func channelPdaIsDeterministicAndSaltSensitive() throws {
        let payer = try Pubkey(bytes: Data(repeating: 1, count: 32))
        let payee = try Pubkey(bytes: Data(repeating: 2, count: 32))
        let mint = try Pubkey(bytes: Data(repeating: 3, count: 32))
        let signer = try Pubkey(bytes: Data(repeating: 4, count: 32))

        let a = try PaymentChannels.findChannelPda(
            payer: payer, payee: payee, mint: mint, authorizedSigner: signer, salt: 99, programId: PaymentChannels.programId
        )
        let b = try PaymentChannels.findChannelPda(
            payer: payer, payee: payee, mint: mint, authorizedSigner: signer, salt: 99, programId: PaymentChannels.programId
        )
        let other = try PaymentChannels.findChannelPda(
            payer: payer, payee: payee, mint: mint, authorizedSigner: signer, salt: 100, programId: PaymentChannels.programId
        )

        #expect(a == b)
        #expect(a != other)
    }

    @Test
    func voucherSignatureVerifiesAgainstAuthorizedSigner() async throws {
        let signer = try MemorySigner(secretKey: Data(repeating: 42, count: 32))
        let channel = try Pubkey(bytes: Data(repeating: 7, count: 32))
        let session = ActiveSession(channelId: channel, signer: signer)

        let voucher = try await session.signIncrement(100)
        let message = try voucher.data.messageBytes()
        let signature = try Base58.decode(voucher.signature)

        #expect(try Ed25519.verify(signature: signature, message: message, publicKey: signer.publicKey))
        #expect(voucher.data.channelId == channel.base58)
        #expect(voucher.data.cumulative == "100")
    }
}
