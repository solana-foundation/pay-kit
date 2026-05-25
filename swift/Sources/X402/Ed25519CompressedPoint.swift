import Foundation

enum Ed25519CompressedPoint {
    static func isOnCurve(_ bytes: Data) -> Bool {
        guard let y = FieldElement(canonicalCompressedY: bytes) else {
            return false
        }

        let ySquared = y.squared()
        let u = ySquared.subtracting(.one)
        let v = ySquared.multiplied(by: .edwardsD).adding(.one)

        let vSquared = v.squared()
        let vCubed = vSquared.multiplied(by: v)
        let vSeventh = vCubed.multiplied(by: vSquared.squared())
        let exponentInput = u.multiplied(by: vSeventh)
        var x = u
            .multiplied(by: vCubed)
            .multiplied(by: exponentInput.pow2523())

        var check = v.multiplied(by: x.squared())
        if check.isEqual(to: u) {
            return true
        }

        if check.isEqual(to: u.negated()) {
            x = x.multiplied(by: .sqrtMinusOne)
            check = v.multiplied(by: x.squared())
            return check.isEqual(to: u)
        }

        return false
    }
}

private struct FieldElement {
    private var limbs: [Int64]

    static let zero = FieldElement(Array(repeating: 0, count: 16))
    static let one = FieldElement([1] + Array(repeating: 0, count: 15))

    // -121665 / 121666 mod 2^255 - 19, little-endian 16-bit limbs.
    static let edwardsD = FieldElement([
        0x78a3, 0x1359, 0x4dca, 0x75eb,
        0xd8ab, 0x4141, 0x0a4d, 0x0070,
        0xe898, 0x7779, 0x4079, 0x8cc7,
        0xfe73, 0x2b6f, 0x6cee, 0x5203,
    ])

    // sqrt(-1) mod 2^255 - 19, little-endian 16-bit limbs.
    static let sqrtMinusOne = FieldElement([
        0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
        0xe478, 0xad2f, 0x1806, 0x2f43,
        0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
        0xdf0b, 0x4fc1, 0x2480, 0x2b83,
    ])

    init(_ limbs: [Int64]) {
        precondition(limbs.count == 16)
        self.limbs = limbs
    }

    init?(canonicalCompressedY bytes: Data) {
        guard bytes.count == 32 else {
            return nil
        }

        var yBytes = [UInt8](bytes)
        yBytes[31] &= 0x7f

        var limbs = [Int64](repeating: 0, count: 16)
        for index in 0..<16 {
            limbs[index] = Int64(yBytes[index * 2]) | (Int64(yBytes[index * 2 + 1]) << 8)
        }
        limbs[15] &= 0x7fff

        let element = FieldElement(limbs)
        guard element.bytes() == yBytes else {
            return nil
        }
        self = element
    }

    func adding(_ other: FieldElement) -> FieldElement {
        FieldElement(zip(limbs, other.limbs).map(+))
    }

    func subtracting(_ other: FieldElement) -> FieldElement {
        FieldElement(zip(limbs, other.limbs).map(-))
    }

    func negated() -> FieldElement {
        FieldElement.zero.subtracting(self)
    }

    func squared() -> FieldElement {
        multiplied(by: self)
    }

    func multiplied(by other: FieldElement) -> FieldElement {
        var product = [Int64](repeating: 0, count: 31)
        for lhs in 0..<16 {
            for rhs in 0..<16 {
                product[lhs + rhs] += limbs[lhs] * other.limbs[rhs]
            }
        }

        for index in stride(from: 30, through: 16, by: -1) {
            product[index - 16] += 38 * product[index]
        }

        var reduced = Array(product[0..<16])
        FieldElement.carryReduce(&reduced)
        FieldElement.carryReduce(&reduced)
        FieldElement.carryReduce(&reduced)
        return FieldElement(reduced)
    }

    func pow2523() -> FieldElement {
        var result = self
        for bit in stride(from: 250, through: 0, by: -1) {
            result = result.squared()
            if bit != 1 {
                result = result.multiplied(by: self)
            }
        }
        return result
    }

    func isEqual(to other: FieldElement) -> Bool {
        bytes() == other.bytes()
    }

    private func bytes() -> [UInt8] {
        var normalized = limbs
        FieldElement.carryReduce(&normalized)
        FieldElement.carryReduce(&normalized)
        FieldElement.carryReduce(&normalized)

        for _ in 0..<2 {
            var candidate = [Int64](repeating: 0, count: 16)
            candidate[0] = normalized[0] - 0xffed
            for index in 1..<15 {
                candidate[index] = normalized[index] - 0xffff - ((candidate[index - 1] >> 16) & 1)
                candidate[index - 1] &= 0xffff
            }
            candidate[15] = normalized[15] - 0x7fff - ((candidate[14] >> 16) & 1)
            let borrow = (candidate[15] >> 16) & 1
            candidate[14] &= 0xffff
            if 1 - borrow == 1 {
                normalized = candidate
            }
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        for index in 0..<16 {
            bytes[index * 2] = UInt8(normalized[index] & 0xff)
            bytes[index * 2 + 1] = UInt8((normalized[index] >> 8) & 0xff)
        }
        return bytes
    }

    private static func carryReduce(_ limbs: inout [Int64]) {
        for index in 0..<16 {
            limbs[index] += 1 << 16
            let carry = limbs[index] >> 16
            if index < 15 {
                limbs[index + 1] += carry - 1
            } else {
                limbs[0] += 38 * (carry - 1)
            }
            limbs[index] -= carry << 16
        }
    }
}
