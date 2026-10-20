//! On-chain integration tests for solana-pay-kit. The test bodies live in
//! `tests/`; this lib only holds the shared skip policy.

/// Environment variable that turns an unavailable validator from a skip into
/// a failure. CI sets it whenever the datasource secret is available, so a
/// test that cannot reach its validator there fails instead of reporting
/// `ok` (cargo captures the stderr of passing tests, so a silent `return`
/// is indistinguishable from a real pass).
pub const HARNESS_REQUIRE_ENV: &str = "HARNESS_REQUIRE";

/// Whether skipping is forbidden for this run.
pub fn skipping_forbidden() -> bool {
    std::env::var(HARNESS_REQUIRE_ENV).is_ok_and(|v| v == "1")
}

/// Record that a test cannot run. Panics under `HARNESS_REQUIRE=1`;
/// otherwise prints the reason so local runs without a validator stay green.
/// Callers `return` right after.
#[track_caller]
pub fn skip_or_fail(reason: &str) {
    if skipping_forbidden() {
        panic!(
            "integration test cannot run and {HARNESS_REQUIRE_ENV}=1 forbids skipping: {reason}"
        );
    }
    eprintln!("skipping: {reason}");
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test touching the env var avoids races with parallel tests.
    #[test]
    fn skip_policy_follows_harness_require() {
        std::env::remove_var(HARNESS_REQUIRE_ENV);
        assert!(!skipping_forbidden());
        skip_or_fail("positive control: local runs may skip");

        std::env::set_var(HARNESS_REQUIRE_ENV, "0");
        assert!(!skipping_forbidden());

        std::env::set_var(HARNESS_REQUIRE_ENV, "1");
        assert!(skipping_forbidden());
        let panicked = std::panic::catch_unwind(|| skip_or_fail("no validator")).is_err();
        std::env::remove_var(HARNESS_REQUIRE_ENV);
        assert!(
            panicked,
            "HARNESS_REQUIRE=1 must turn a skip into a failure"
        );
    }
}
