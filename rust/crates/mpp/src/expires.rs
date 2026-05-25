//! Expiration time helpers.
//!
//! Convenience functions for generating ISO 8601 expiration timestamps.

use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

pub fn seconds(n: u64) -> String {
    offset(Duration::seconds(n as i64))
}

pub fn minutes(n: u64) -> String {
    offset(Duration::minutes(n as i64))
}

pub fn hours(n: u64) -> String {
    offset(Duration::hours(n as i64))
}

pub fn days(n: u64) -> String {
    offset(Duration::days(n as i64))
}

pub fn weeks(n: u64) -> String {
    offset(Duration::weeks(n as i64))
}

fn offset(duration: Duration) -> String {
    let dt = OffsetDateTime::now_utc() + duration;
    dt.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minutes_format() {
        let result = minutes(5);
        assert!(result.contains('T'));
    }

    #[test]
    fn hours_later_than_minutes() {
        let m = minutes(1);
        let h = hours(1);
        assert!(h > m);
    }

    // ── All duration functions produce valid RFC3339 ──

    fn is_valid_rfc3339(s: &str) -> bool {
        OffsetDateTime::parse(s, &Rfc3339).is_ok()
    }

    #[test]
    fn seconds_produces_valid_rfc3339() {
        assert!(is_valid_rfc3339(&seconds(30)));
    }

    #[test]
    fn minutes_produces_valid_rfc3339() {
        assert!(is_valid_rfc3339(&minutes(5)));
    }

    #[test]
    fn hours_produces_valid_rfc3339() {
        assert!(is_valid_rfc3339(&hours(2)));
    }

    #[test]
    fn days_produces_valid_rfc3339() {
        assert!(is_valid_rfc3339(&days(7)));
    }

    #[test]
    fn weeks_produces_valid_rfc3339() {
        assert!(is_valid_rfc3339(&weeks(1)));
    }

    // ── Ordering: each longer duration produces a later time ──

    #[test]
    fn seconds_is_in_the_future() {
        let now = OffsetDateTime::now_utc();
        let ts = seconds(60);
        let parsed = OffsetDateTime::parse(&ts, &Rfc3339).unwrap();
        assert!(parsed > now);
    }

    #[test]
    fn days_later_than_hours() {
        let h = hours(1);
        let d = days(1);
        let h_dt = OffsetDateTime::parse(&h, &Rfc3339).unwrap();
        let d_dt = OffsetDateTime::parse(&d, &Rfc3339).unwrap();
        assert!(d_dt > h_dt);
    }

    #[test]
    fn weeks_later_than_days() {
        let d = days(1);
        let w = weeks(1);
        let d_dt = OffsetDateTime::parse(&d, &Rfc3339).unwrap();
        let w_dt = OffsetDateTime::parse(&w, &Rfc3339).unwrap();
        assert!(w_dt > d_dt);
    }

    #[test]
    fn zero_seconds_is_approximately_now() {
        let now = OffsetDateTime::now_utc();
        let ts = seconds(0);
        let parsed = OffsetDateTime::parse(&ts, &Rfc3339).unwrap();
        // Should be within 2 seconds of now
        let diff = (parsed - now).whole_seconds().unsigned_abs();
        assert!(diff <= 2);
    }

    #[test]
    fn zero_minutes_is_approximately_now() {
        let now = OffsetDateTime::now_utc();
        let ts = minutes(0);
        let parsed = OffsetDateTime::parse(&ts, &Rfc3339).unwrap();
        let diff = (parsed - now).whole_seconds().unsigned_abs();
        assert!(diff <= 2);
    }

    // ── The string contains Z (UTC) ──

    #[test]
    fn timestamps_are_utc() {
        assert!(seconds(10).ends_with('Z'));
        assert!(minutes(10).ends_with('Z'));
        assert!(hours(1).ends_with('Z'));
        assert!(days(1).ends_with('Z'));
        assert!(weeks(1).ends_with('Z'));
    }
}
