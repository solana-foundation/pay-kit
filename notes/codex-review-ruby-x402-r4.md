# Codex Review — Ruby x402 (Round 4)

Source: solana-foundation/x402-sdk PR #20 — tip `45e618f`.

## Confidence

- Round 4 verdict: **0 real P1**, **Confidence 4/5**.
- Cross-language interop matrix: **90/90** pass.
- MPP §19.6 (cross-server portability + idempotent resubmit): clean.

## Regression / hardening surface carried into this port

- Fee-payer attack regression suite (verifier rejects a fee-payer attempting
  to drain user funds or substitute pay_to).
- Sign-then-verify ordering: server validates the client signature **before**
  the facilitator co-signs, so an invalid client signature can never become
  a settled transaction.
- Resource binding: the signed payment is bound to the challenged resource
  path; a payment authored against `/A` cannot be replayed against `/B`.
- `Base64.strict_decode64` for all header decoding (no whitespace-bypass).
- short_vec UTF-8 encoding bug fix: `[byte].pack("C")` on an ASCII-8BIT
  buffer instead of string concat (which silently re-encodes high bytes).
- Memo byte comparison stays in ASCII-8BIT (no implicit UTF-8 promotion
  of non-ASCII payloads).
- Cross-server credential canonical-reject token: divergent canonicalization
  forces a deterministic reject rather than silent acceptance.
- Ensure-block double-close guard on TCP listener / connection.

## Verification in this PR

- `ruby -c` clean across all three lib files, both bin entries, both tests.
- `ruby -Ilib:test test/x402_interop_client_test.rb` → 26 runs, 54
  assertions, 0 failures.
- `ruby -Ilib:test test/x402_interop_server_test.rb` → 42 runs, 135
  assertions, 0 failures.
- `tests/interop/src/implementations.ts` compiles standalone under `tsc`
  (pre-existing `@solana/mpp/*` resolution errors in unrelated harness
  files are not introduced by this PR).

## Namespace mapping

| Source (x402-sdk #20)              | mpp-sdk port                |
| ---------------------------------- | --------------------------- |
| `X402SDK::Interop::Client`         | `X402::Interop::Client`     |
| `X402SDK::Interop::Server`         | `X402::Interop::Server`     |
| `X402SDK::Interop::Exact`          | `X402::Interop::Exact`      |
| `lib/x402_sdk/interop/*.rb`        | `ruby/lib/x402/*.rb`        |
| `bin/interop-{client,server}`      | `ruby/bin/x402-interop-*`   |

Only the top-level constant changes (`X402SDK` → `X402`); the
`Interop::*` submodule layout is preserved so review against the source
diff stays one-to-one.
