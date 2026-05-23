import Foundation
import Testing
@testable import SolanaMpp

@Suite("Curve25519 field arithmetic and on-curve check")
struct Curve25519FieldTests {
    /// Captured from `solana-curve25519::edwards::validate_edwards`
    /// (the same path Solana uses for PDA on-curve checks). The hex
    /// pair are the candidate hashes at bumps 255 and 254 from the
    /// `usdc_alice` ATA fixture in AtaTests.
    @Test
    func recognizesKnownOnCurvePoint() throws {
        let onCurveHex = "09ad9b4b044f46ef9a393166b562a727528dff968f3e2c628265856554767daf"
        let data = try TestHex.decode(onCurveHex)
        #expect(Curve25519OnCurve.isOnCurve(data), "expected on-curve")
    }

    @Test
    func recognizesKnownOffCurvePoint() throws {
        let offCurveHex = "4aa094c208240efddcb7f7180bccf8db85ad86a24823a0a4cb8475898f122b12"
        let data = try TestHex.decode(offCurveHex)
        #expect(!Curve25519OnCurve.isOnCurve(data), "expected off-curve")
    }

    @Test
    func generatorPointIsOnCurve() throws {
        // Standard Ed25519 base-point compressed y (little-endian).
        // y = 4/5 mod p. Bytes 0x58, 0x66, 0x66, 0x66, ..., 0x66.
        let baseHex = "5866666666666666666666666666666666666666666666666666666666666666"
        let data = try TestHex.decode(baseHex)
        #expect(Curve25519OnCurve.isOnCurve(data))
    }
}
