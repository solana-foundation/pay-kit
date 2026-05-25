# Codex Review — PHP x402 exact server (Round 4)

**Target:** solana-foundation/mpp-sdk `php/src/x402/`
**Scope:** Server-only adapter port (no client this round)

## Verdict

- **Real P1 findings:** 0
- **Confidence:** 4 / 5
- **Cross-language matrix:** 90 / 90
- **MPP §19.6:** cross-server portability + idempotent-resubmit clean

## Carried-over hardening from PR #19

The PHP InteropServer ships the following regressions baked in from upstream
rounds 1–4. Each is exercised by `tests/x402_interop_server_test.php`:

1. **Fee-payer attack regression suite** — 4 malicious shapes plus a positive
   control proving signer-account ordering is enforced before signature
   verification.
2. **u64 overflow fix in compute-price cap** — GMP-based comparison replaces
   PHP's native integer math so micro-lamports can be capped at full u64
   range without silent wraparound.
3. **Broadcast → confirm → mark settlement ordering** — settlement is only
   marked after RPC confirmation polling succeeds. If RPC errors after
   broadcast, the in-flight claim is released so retries are observable to
   the client rather than silently double-charged.
4. **Lighthouse instruction passthrough** — spine parity with the Rust
   reference; Lighthouse assertion instructions are allowed through the
   optional-instruction allowlist unchanged.
5. **`extra.tokenProgram` mint allowlist** — only the canonical SPL Token
   programs (Tokenkeg + Token2022) are accepted; arbitrary program IDs
   smuggled via `extra.tokenProgram` are rejected before transaction
   inspection.
6. **base58 sentinel zero-byte fix** — System Program ID
   (`11111111111111111111111111111111`) round-trips correctly through the
   decoder; the leading-zero sentinel path no longer drops bytes.
7. **Cross-server credential canonical reject token** — payments whose
   `accepted` block does not structurally match the requirement set are
   rejected with the canonical token expected by the cross-language matrix.
8. **ATA-create instruction rejected from optional-instruction loop** —
   spine parity fix: AssociatedTokenAccount `create` instructions are not
   silently absorbed into the optional-instruction allowlist; they must be
   handled by the explicit split-ATA scenario only.

## Verification commands

```bash
cd php && composer test
find php -name '*.php' -exec php -l {} \;
pnpm --filter @mpp/interop typecheck
```

## Files touched in this port

- `php/src/x402/InteropServer.php`        (~1 050 lines, procedural functions)
- `php/bin/x402-interop-server.php`        harness binary
- `php/tests/x402_interop_server_test.php` full regression suite
- `php/composer.json`                       autoload entry + `test:x402` script
- `harness/src/implementations.ts`          `php-x402-server` wiring (no client)

Namespace rewritten from upstream `X402Sdk\Interop` → `SolanaMpp\X402\Interop`
to match the mpp-sdk PHP package convention (`SolanaMpp\…`). All require
paths re-rooted at `src/x402/InteropServer.php`. Coverage report file label
updated to the new path so the coverage gate continues to map correctly.
