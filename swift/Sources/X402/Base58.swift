import Foundation

enum Base58 {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    private static let index: [UInt8: Int] = {
        var table: [UInt8: Int] = [:]
        for (offset, byte) in alphabet.enumerated() {
            table[byte] = offset
        }
        return table
    }()

    static func encode(_ data: Data) -> String {
        if data.isEmpty { return "" }
        var digits = [UInt8](repeating: 0, count: data.count * 138 / 100 + 1)
        var length = 0
        for byte in data {
            var carry = Int(byte)
            var index = 0
            for digitIndex in stride(from: digits.count - 1, through: digits.count - length, by: -1) {
                carry += Int(digits[digitIndex]) << 8
                digits[digitIndex] = UInt8(carry % 58)
                carry /= 58
                index += 1
            }
            while carry > 0 {
                digits[digits.count - 1 - index] = UInt8(carry % 58)
                carry /= 58
                index += 1
            }
            length = index
        }
        var result = String(repeating: "1", count: data.prefix(while: { $0 == 0 }).count)
        for digit in digits.suffix(length) {
            result.append(Character(UnicodeScalar(alphabet[Int(digit)])))
        }
        return result
    }

    static func decode(_ string: String) throws -> Data {
        if string.isEmpty { return Data() }
        let bytes = Array(string.utf8)
        var decoded = [UInt8](repeating: 0, count: bytes.count * 733 / 1000 + 1)
        var length = 0
        for byte in bytes {
            guard let value = index[byte] else {
                throw X402Error.invalidBase58(string)
            }
            var carry = value
            var index = 0
            for decodedIndex in stride(from: decoded.count - 1, through: decoded.count - length, by: -1) {
                carry += Int(decoded[decodedIndex]) * 58
                decoded[decodedIndex] = UInt8(carry & 0xff)
                carry >>= 8
                index += 1
            }
            while carry > 0 {
                decoded[decoded.count - 1 - index] = UInt8(carry & 0xff)
                carry >>= 8
                index += 1
            }
            length = index
        }
        let leadingZeros = bytes.prefix(while: { $0 == Character("1").asciiValue }).count
        return Data([UInt8](repeating: 0, count: leadingZeros) + decoded.suffix(length))
    }
}

public struct SolanaPublicKey: Equatable, Hashable, Codable {
    public let bytes: Data

    public init(_ base58: String) throws {
        let decoded = try Base58.decode(base58)
        guard decoded.count == 32 else {
            throw X402Error.invalidBase58(base58)
        }
        self.bytes = decoded
    }

    public init(bytes: Data) throws {
        guard bytes.count == 32 else {
            throw X402Error.invalidBase58(Base58.encode(bytes))
        }
        self.bytes = bytes
    }

    public var base58: String {
        Base58.encode(bytes)
    }
}
