import Foundation
import Testing
@testable import SolanaPayKit

/// The 39 date-time vectors where the old parser diverged from the Rust reference; the anchor predates every vector, so a row tests parsing, not time.
@Suite("MPP expires RFC 3339 conformance")
struct ExpiresRFC3339Tests {
    private static let anchor = Date(timeIntervalSince1970: -100_000_000_000)  // ~1199 BCE

    private static let vectors: [(name: String, expires: String, accept: Bool)] = [
        ("jsts_date_time_010", "1990-02-31T15:59:59.123-08:00", false),
        ("jsts_date_time_011", "1990-12-31T15:59:59-24:00", false),
        ("jsts_date_time_012", "1963-06-19T08:30:06.28123+01:00Z", false),
        ("jsts_date_time_013", "1990-12-31T24:00:00Z", false),
        ("jsts_date_time_015", "1990-12-31T10:00:00+10:60", false),
        ("jsts_date_time_019", "1963-6-19T08:30:06.283185Z", false),
        ("jsts_date_time_020", "1963-06-1T08:30:06.283185Z", false),
        ("jsts_date_time_021", "1963-06-1৪T00:00:00Z", false),
        ("jsts_date_time_022", "1963-06-11T0৪:00:00Z", false),
        ("jsts_date_time_024", "1985-04-12T23:20:50+01", false),
        ("jsts_date_time_027", "1985-04-12T23:20:50Z\n", false),
        ("go_parseerror_2006_01_02t15_04_05z07_00", "2006-01-02T15:04:05Z07:00", false),
        ("go_parseerror_2006_01_02t15_04_05z_abc", "2006-01-02T15:04:05Z_abc", false),
        ("go_parseerror_0000_01_01t00_00_00_00_0", "0000-01-01T00:00:00+00:+0", false),
        ("offset_hour_out_of_range", "2026-01-29T12:00:00+24:00", false),
        ("offset_minute_out_of_range", "2026-01-29T12:00:00+00:60", false),
        ("offset_missing_colon", "2026-01-29T12:00:00+0000", false),
        ("offset_hour_only", "2026-01-29T12:00:00-08", false),
        ("year_10000", "10000-01-01T00:00:00Z", false),
        ("year_two_digit", "26-01-29T12:00:00Z", false),
        ("feb_30", "2026-02-30T00:00:00Z", false),
        ("sep_31", "2026-09-31T00:00:00Z", false),
        ("non_leap_year_1900_feb_29", "1900-02-29T00:00:00Z", false),
        ("non_leap_year_2026_feb_29", "2026-02-29T00:00:00Z", false),
        ("apr_31", "2026-04-31T00:00:00Z", false),
        ("hour_24", "2026-01-29T24:00:00Z", false),
        ("trailing_garbage_after_offset", "2026-01-29T12:00:00Z_abc", false),
        ("trailing_newline_after_offset", "2026-01-29T12:00:00Z\n", false),
        ("trailing_duplicate_z", "2026-01-29T12:00:00ZZ", false),
        ("offset_signed_minute", "2026-01-29T12:00:00+00:+0", false),
        ("jsts_date_time_005", "1998-12-31T23:59:60Z", true),
        ("jsts_date_time_006", "1998-12-31T15:59:60.123-08:00", true),
        ("jsts_date_time_017", "1963-06-19t08:30:06.283185z", true),
        ("leap_second_offset_rolls_local_date_forward", "1999-01-01T00:59:60+01:00", true),
        ("rfc_5_8_example_leap_second_z", "1990-12-31T23:59:60Z", true),
        ("rfc_5_8_example_leap_second_offset", "1990-12-31T15:59:60-08:00", true),
        ("leap_second_june_month_end", "1972-06-30T23:59:60Z", true),
        ("lowercase_t_separator", "1985-04-12t23:20:50.52Z", true),
        ("lowercase_t_and_z", "1985-04-12t23:20:50.52z", true),
    ]

    private func challenge(_ expires: String) throws -> PaymentChallenge {
        try PaymentChallenge(id: "ch", realm: "MPP Payment", method: "solana", intent: "charge",
                             request: Base64URL.encode(Data("{}".utf8)), expires: expires)
    }

    @Test
    func matchesTheRustReferenceOnEveryDivergentVector() throws {
        #expect(Self.vectors.count == 39)
        for v in Self.vectors {
            let expired = try challenge(v.expires).isExpired(now: Self.anchor)
            #expect(expired == !v.accept, "\(v.name) \(v.expires.debugDescription)")
        }
    }

    @Test
    func leapSecondClampsIntoFiftyNineAndNeverReachesTheNextMinute() throws {
        let challenge = try challenge("1990-12-31T23:59:60Z")
        #expect(!challenge.isExpired(now: Date(timeIntervalSince1970: 662_687_999)))  // :59Z
        #expect(challenge.isExpired(now: Date(timeIntervalSince1970: 662_688_000)))  // next day 00:00Z
        for s in ["1998-12-30T23:59:60Z", "1998-12-31T23:58:60Z"] { #expect(try self.challenge(s).isExpired(now: Self.anchor), "\(s)") }
    }
}
