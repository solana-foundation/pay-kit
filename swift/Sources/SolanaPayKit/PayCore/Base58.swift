import Foundation

/// Base58 (Bitcoin / Solana) encoder and decoder.
///
/// Uses the alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
/// and preserves leading-zero bytes as leading `1` characters, matching
/// the Rust `bs58` crate at version 0.5 (the same crate the spine pins
/// in `rust/Cargo.toml`). Parity tests in `Base58Tests` lock the
/// byte-for-byte agreement with that crate.
public enum Base58 {
    public static let alphabet: [UInt8] = Array(
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8
    )

    private static let decodeTable: [Int8] = {
        var table = [Int8](repeating: -1, count: 128)
        for (index, byte) in alphabet.enumerated() {
            table[Int(byte)] = Int8(index)
        }
        return table
    }()

    public static func encode(_ data: Data) -> String {
        if data.isEmpty { return "" }

        // Count leading zero bytes.
        var leadingZeros = 0
        for byte in data {
            if byte == 0 { leadingZeros += 1 } else { break }
        }

        // Base-256 -> base-58 by repeated division.
        var digits = [UInt8]()
        digits.reserveCapacity(data.count * 138 / 100 + 1)

        var input = Array(data)
        var start = leadingZeros
        while start < input.count {
            var carry = 0
            var i = start
            while i < input.count {
                let value = carry * 256 + Int(input[i])
                input[i] = UInt8(value / 58)
                carry = value % 58
                i += 1
            }
            digits.append(UInt8(carry))
            // Advance start past any new leading zero in the base-256 buffer.
            while start < input.count, input[start] == 0 {
                start += 1
            }
        }

        var output = [UInt8]()
        output.reserveCapacity(leadingZeros + digits.count)
        for _ in 0..<leadingZeros { output.append(alphabet[0]) }
        for digit in digits.reversed() { output.append(alphabet[Int(digit)]) }
        return String(decoding: output, as: UTF8.self)
    }

    public static func decode(_ string: String) throws -> Data {
        if string.isEmpty { return Data() }

        let scalars = Array(string.utf8)

        // Count leading '1' (zero-value) characters.
        var leadingOnes = 0
        for byte in scalars {
            if byte == alphabet[0] { leadingOnes += 1 } else { break }
        }

        var b256 = [UInt8](repeating: 0, count: scalars.count * 733 / 1000 + 1)
        var length = 0
        for byte in scalars {
            guard Int(byte) < 128 else { throw MppError.invalidBase58 }
            let digit = decodeTable[Int(byte)]
            guard digit >= 0 else { throw MppError.invalidBase58 }

            var carry = Int(digit)
            var i = 0
            // Iterate from the rightmost active slot back to index 0; allow
            // the loop to grow `length` when `carry` outlives the active
            // range so high-order bytes can carry into a new slot.
            while carry != 0 || i < length {
                if i >= b256.count {
                    b256.append(0)
                }
                let slot = b256.count - 1 - i
                let value = Int(b256[slot]) * 58 + carry
                b256[slot] = UInt8(value & 0xff)
                carry = value >> 8
                i += 1
            }
            length = i
        }

        // Strip leading zero bytes that came from the buffer pre-allocation.
        var bufferZeros = b256.count - length
        // Skip any extra zero-valued bytes inside the active range that
        // correspond to the leading '1' characters, but keep exactly
        // `leadingOnes` zero bytes at the front of the final output.
        while bufferZeros < b256.count, b256[bufferZeros] == 0 {
            bufferZeros += 1
        }

        var output = Data()
        output.reserveCapacity(leadingOnes + (b256.count - bufferZeros))
        for _ in 0..<leadingOnes { output.append(0) }
        output.append(contentsOf: b256[bufferZeros..<b256.count])
        return output
    }
}
