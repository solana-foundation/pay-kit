import Foundation

/// Pure-Swift field arithmetic over GF(p) where p = 2^255 - 19, enough
/// to decide whether a candidate 32-byte value lies on the Ed25519
/// curve. The implementation uses 256-bit unsigned integers built from
/// four `UInt64` limbs (little-endian limb order, big-endian within a
/// limb). Multiplication uses Swift's `multipliedFullWidth(by:)` for
/// 128-bit products, then reduces via the `2^255 = 19 (mod p)`
/// identity. The code stays on macOS 13 / iOS 16 (no `UInt128`
/// dependency).
///
/// This mirrors the Solana spine's `solana-curve25519` PDA check, which
/// itself calls `curve25519-dalek`'s `CompressedEdwardsY::decompress`.
enum Curve25519Field {
    /// 256-bit unsigned integer as 4 little-endian limbs (limb 0 holds
    /// the low 64 bits). All algorithms work over reduced residues in
    /// `[0, p)` unless documented otherwise.
    struct U256: Equatable {
        var limbs: [UInt64] // count == 4

        static let zero = U256(limbs: [0, 0, 0, 0])
        static let one = U256(limbs: [1, 0, 0, 0])

        init(limbs: [UInt64]) {
            precondition(limbs.count == 4)
            self.limbs = limbs
        }

        /// Parse a 32-byte little-endian field element. The top bit of
        /// byte 31 (the compressed sign bit) is masked off.
        static func fromLE(_ bytes: Data) -> U256 {
            precondition(bytes.count == 32)
            var b = [UInt8](repeating: 0, count: 32)
            bytes.copyBytes(to: &b, count: 32)
            b[31] &= 0x7F
            var l = [UInt64](repeating: 0, count: 4)
            for i in 0..<4 {
                var v: UInt64 = 0
                for j in 0..<8 {
                    v |= UInt64(b[i * 8 + j]) << (8 * j)
                }
                l[i] = v
            }
            return U256(limbs: l)
        }
    }

    /// p = 2^255 - 19.
    static let p = U256(limbs: [
        0xFFFFFFFFFFFFFFED,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
    ])

    /// Compares a < b. Both inputs must be canonical residues.
    static func less(_ a: U256, _ b: U256) -> Bool {
        for i in stride(from: 3, through: 0, by: -1) {
            if a.limbs[i] != b.limbs[i] {
                return a.limbs[i] < b.limbs[i]
            }
        }
        return false
    }

    /// Adds two field elements, returning a result in `[0, 2p)`.
    static func addWithCarry(_ a: U256, _ b: U256) -> (sum: U256, carry: UInt64) {
        var out = [UInt64](repeating: 0, count: 4)
        var carry: UInt64 = 0
        for i in 0..<4 {
            let (s1, c1) = a.limbs[i].addingReportingOverflow(b.limbs[i])
            let (s2, c2) = s1.addingReportingOverflow(carry)
            out[i] = s2
            carry = (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
        }
        return (U256(limbs: out), carry)
    }

    /// Subtract b from a, returning (a - b) and the final borrow.
    static func subWithBorrow(_ a: U256, _ b: U256) -> (diff: U256, borrow: UInt64) {
        var out = [UInt64](repeating: 0, count: 4)
        var borrow: UInt64 = 0
        for i in 0..<4 {
            let (d1, b1) = a.limbs[i].subtractingReportingOverflow(b.limbs[i])
            let (d2, b2) = d1.subtractingReportingOverflow(borrow)
            out[i] = d2
            borrow = (b1 ? 1 : 0) &+ (b2 ? 1 : 0)
        }
        return (U256(limbs: out), borrow)
    }

    /// Reduce a 256-bit value mod p: subtract p once if x >= p.
    static func reduce(_ a: U256) -> U256 {
        if !less(a, p) {
            return subWithBorrow(a, p).diff
        }
        return a
    }

    /// Modular add.
    static func addMod(_ a: U256, _ b: U256) -> U256 {
        let (s, carry) = addWithCarry(a, b)
        // If carry from limb 3 set OR s >= p, subtract p.
        var result = s
        if carry == 1 || !less(s, p) {
            result = subWithBorrow(result, p).diff
        }
        return result
    }

    /// Modular subtract.
    static func subMod(_ a: U256, _ b: U256) -> U256 {
        let (d, borrow) = subWithBorrow(a, b)
        if borrow == 1 {
            // Add p to wrap back into [0, p).
            let (r, _) = addWithCarry(d, p)
            return r
        }
        return d
    }

    /// Multiply two field elements. Schoolbook 4-by-4 producing 8
    /// 64-bit limbs, then folds the high half using the 2^256 = 38
    /// (mod p) identity twice.
    static func mulMod(_ a: U256, _ b: U256) -> U256 {
        var t = [UInt64](repeating: 0, count: 8)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let (hi, lo) = a.limbs[i].multipliedFullWidth(by: b.limbs[j])
                let (sum1, c1) = t[i + j].addingReportingOverflow(lo)
                let (sum2, c2) = sum1.addingReportingOverflow(carry)
                t[i + j] = sum2
                carry = UInt64(hi) &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
            }
            t[i + 4] = carry
        }

        // Fold high 4 limbs into low 4 with multiplier 38 = 2 * 19,
        // because 2^256 mod (2^255 - 19) = 2 * 19 = 38.
        // result_lo = t[0..4] + 38 * t[4..8]
        let high = [UInt64](t[4..<8])
        let low = [UInt64](t[0..<4])
        var folded = [UInt64](repeating: 0, count: 5) // 4 limbs + possible overflow
        var carry: UInt64 = 0
        for i in 0..<4 {
            let (hi, lo) = high[i].multipliedFullWidth(by: 38)
            let (sum1, c1) = low[i].addingReportingOverflow(lo)
            let (sum2, c2) = sum1.addingReportingOverflow(carry)
            folded[i] = sum2
            carry = UInt64(hi) &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
        }
        folded[4] = carry

        // folded is up to 5 limbs; fold the high limb again with 38.
        let (hi2, lo2) = folded[4].multipliedFullWidth(by: 38)
        // hi2 should be zero since folded[4] is at most ~38 from the
        // previous step.
        precondition(hi2 == 0, "unexpected overflow in second fold")
        var result = U256(limbs: [folded[0], folded[1], folded[2], folded[3]])
        let (s, c) = addWithCarry(result, U256(limbs: [lo2, 0, 0, 0]))
        result = s
        if c == 1 {
            // 2^256 from this carry folds back as +38.
            let (s2, _) = addWithCarry(result, U256(limbs: [38, 0, 0, 0]))
            result = s2
        }
        return reduce(reduce(result))
    }

    static func square(_ a: U256) -> U256 { mulMod(a, a) }

    /// Modular exponentiation by a 256-bit constant. The exponent is
    /// represented as 4 little-endian limbs.
    static func powMod(_ base: U256, exponent: [UInt64]) -> U256 {
        precondition(exponent.count == 4)
        var result = U256.one
        var current = base
        for limb in exponent {
            var bits = limb
            for _ in 0..<64 {
                if bits & 1 == 1 {
                    result = mulMod(result, current)
                }
                current = square(current)
                bits >>= 1
            }
        }
        return result
    }

    /// d = -121665 / 121666 (mod p), 4 limbs LE.
    static let d = U256(limbs: [
        0x75EB4DCA135978A3,
        0x00700A4D4141D8AB,
        0x8CC740797779E898,
        0x52036CEE2B6FFE73,
    ])

    /// sqrt(-1) mod p = 2^((p-1)/4), 4 limbs LE.
    static let sqrtM1 = U256(limbs: [
        0xC4EE1B274A0EA0B0,
        0x2F431806AD2FE478,
        0x2B4D00993DFBD7A7,
        0x2B8324804FC1DF0B,
    ])

    /// (p - 5) / 8, used as exponent for the (u/v)-square-root trick.
    /// = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
    static let pSubFiveDivEight: [UInt64] = [
        0xFFFFFFFFFFFFFFFD,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x0FFFFFFFFFFFFFFF,
    ]
}

/// On-curve check used by `ProgramDerivedAddress.find`. Returns true if
/// the 32-byte input decodes to a valid Ed25519 curve point. Matches
/// the behavior of `curve25519-dalek::edwards::CompressedEdwardsY::decompress`,
/// which Solana's PDA verifier calls.
enum Curve25519OnCurve {
    static func isOnCurve(_ bytes: Data) -> Bool {
        guard bytes.count == 32 else { return false }

        let y = Curve25519Field.U256.fromLE(bytes)
        // Reject if y >= p.
        if !Curve25519Field.less(y, Curve25519Field.p) { return false }

        let y2 = Curve25519Field.square(y)
        let u = Curve25519Field.subMod(y2, .one)            // y^2 - 1
        let dy2 = Curve25519Field.mulMod(Curve25519Field.d, y2)
        let v = Curve25519Field.addMod(dy2, .one)           // d*y^2 + 1

        // x = (u * v^3) * (u * v^7)^((p - 5) / 8)
        let v2 = Curve25519Field.square(v)
        let v3 = Curve25519Field.mulMod(v2, v)
        let v7 = Curve25519Field.mulMod(Curve25519Field.square(v3), v)
        let uv7 = Curve25519Field.mulMod(u, v7)
        let exp = Curve25519Field.powMod(uv7, exponent: Curve25519Field.pSubFiveDivEight)
        var x = Curve25519Field.mulMod(u, v3)
        x = Curve25519Field.mulMod(x, exp)

        // Check whether v*x^2 == ±u; if v*x^2 == -u, fix x by multiplying by sqrt(-1).
        let vx2 = Curve25519Field.mulMod(v, Curve25519Field.square(x))
        if vx2 == u { return true }
        let negU = Curve25519Field.subMod(.zero, u)
        if vx2 == negU { return true }
        return false
    }
}
