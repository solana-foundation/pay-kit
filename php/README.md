# PHP MPP SDK

PHP is a server-side implementation for the Solana payment method in the
Machine Payments Protocol.

This package is intentionally server-first. Lua and PHP do not need client-side
payment construction in the current MPP roadmap; they should be able to issue
charge challenges, verify credentials, and return payment receipts from server
frameworks.

The current implementation provides:

- charge intent request validation
- `Payment` challenge and credential header helpers
- server-side charge verification helpers
- PHPUnit coverage for core protocol behavior

Session, subscription, and framework middleware helpers should land as separate
reviewable commits.

## Compatibility

| Cell | Client | Server |
|---|:---:|:---:|
| `x402/exact` | — | — |
| `x402/upto` | — | — |
| `x402/batch-settlement` | — | — |
| `mpp/charge/pull` | — | supported |
| `mpp/charge/push` | — | — |
| `mpp/session` | — | — |
| `mpp/subscription` | — | — |

PHP currently verifies server-side MPP charge credentials and participates in
the TypeScript interop harness as a server adapter. It does not provide a PHP
client, transaction builder, or wallet integration.

## Layout

```text
php/
├── src/       SDK source
├── tests/     PHPUnit suite
└── README.md
```

## Local Payment Check

Start a PHP-backed protected endpoint through the interop harness or an
application embedding `SolanaMpp\Server\ChargeServer`.

Use `curl` to confirm the server returns a payment challenge, then use the
`pay` CLI to complete the 402 challenge/credential flow.

```bash
brew install pay

# payment required
curl http://localhost:4567/paid

# payment successful
pay curl http://localhost:4567/paid
```

## Running Tests

```bash
cd php
composer install
composer test
```

CI also runs `composer run test:coverage` with a coverage driver and uploads
`php/build/coverage/clover.xml`. The coverage command enforces a 90% line
coverage gate.
