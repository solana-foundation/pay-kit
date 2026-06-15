import Foundation
import Testing
@testable import SolanaPayKit

@Suite("Pubkey")
struct PubkeyTests {
    @Test
    func systemProgramIsAllZero() {
        #expect(Pubkey.systemProgram.bytes == Data(repeating: 0, count: 32))
        #expect(Pubkey.systemProgram.base58 == "11111111111111111111111111111111")
    }

    @Test
    func tokenProgramRoundTrip() throws {
        let key = Pubkey.tokenProgram
        let again = try Pubkey(base58: key.base58)
        #expect(again == key)
        #expect(key.base58 == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    }

    @Test
    func rejectsWrongLengthBytes() {
        #expect(throws: MppError.invalidPubkey("expected 32 bytes, got 31")) {
            _ = try Pubkey(bytes: Data(repeating: 1, count: 31))
        }
    }

    @Test
    func rejectsBase58WithWrongDecodedLength() {
        // "abc" decodes to 2 bytes, not 32.
        #expect(throws: MppError.self) {
            _ = try Pubkey(base58: "abc")
        }
    }

    @Test
    func hashableUsableInSet() throws {
        let a = try Pubkey(base58: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        let b = try Pubkey(base58: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        let c = Pubkey.systemProgram
        let set: Set<Pubkey> = [a, b, c]
        #expect(set.count == 2)
    }
}
