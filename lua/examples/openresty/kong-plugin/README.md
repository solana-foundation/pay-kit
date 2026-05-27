# Kong plugin: `pay-kit`

A Kong custom plugin that gates upstream API routes behind a PayKit
charge. Runs in the `access` phase, issues an HTTP 402 with the
right `WWW-Authenticate` + `PAYMENT-REQUIRED` headers on first
contact, and verifies / settles the credential on the paid retry.
Backs both x402 (`exact` scheme on Solana) and MPP from the same
adapter binary; client picks per-request via header detection.

The plugin source lives in `lua/kong/plugins/pay-kit/`:

```
kong/plugins/pay-kit/
├── handler.lua       # access / header_filter / log phase methods
├── schema.lua        # Kong typedefs schema (gate-name OR inline)
└── bootstrap.lua     # KONG_NGINX_HTTP_INIT_BY_LUA_BLOCK entry point
```

## Install

LuaRocks (recommended):

```bash
luarocks install kong-plugin-pay-kit
```

Or, in dev: copy the `kong/plugins/pay-kit/` directory into Kong's
plugin path (`/usr/local/share/lua/5.1/kong/plugins/`).

Activate via `kong.conf` or env:

```bash
KONG_PLUGINS=bundled,pay-kit
KONG_NGINX_HTTP_INIT_BY_LUA_BLOCK="require('kong.plugins.pay-kit.init').setup()"
```

## Configure (env vars)

The plugin reads its global config (operator, signer, RPC URL, MPP
secret) from PAY_KIT_* env vars at master init:

```bash
PAY_KIT_NETWORK="solana_devnet"
PAY_KIT_RPC_URL="https://api.devnet.solana.com"
PAY_KIT_OPERATOR_RECIPIENT="<base58 Solana address>"
PAY_KIT_OPERATOR_KEY="<JSON array | base58 | hex 64-byte secret>"
PAY_KIT_MPP_CHALLENGE_BINDING_SECRET="<HMAC secret>"
```

Per-route config goes on the plugin instance (Admin API):

```bash
# Inline gate
curl -X POST http://localhost:8001/services/<svc>/plugins \
  -d "name=pay-kit" \
  -d "config.amount=0.10" \
  -d "config.stablecoins=USDC"

# Or reference a gate registered via bootstrap.lua + pay_kit.gate()
curl -X POST http://localhost:8001/services/<svc>/plugins \
  -d "name=pay-kit" \
  -d "config.gate=report"
```

## How it works

1. **Master init.** `bootstrap.lua` reads env vars and calls
   `pay_kit.configure()` once. State survives all workers via Lua
   module caching.
2. **Access phase.** `handler.lua:access(conf)` builds a gate arg
   (named or inline) and calls `pay_kit.try_payment()`. Unpaid
   requests get `kong.response.exit(402, body, headers)`. Paid
   requests stash the payment on `kong.ctx.shared.pay_kit_payment`
   for downstream plugins.
3. **Header filter.** Settlement headers
   (`x-payment-settlement-signature`, `payment-response`, ...) are
   stamped onto the upstream 200 response so clients can verify
   on-chain proofs.

## Priority

`PRIORITY = 1010` sits between basic-auth (1001) and OIDC (1050).
Payment runs **before** rate-limiting (910) so unpaid traffic never
burns the rate-limit bucket. Combine with identity-auth plugins by
keeping pay-kit at 1010 and the auth plugin at its default; paid
+ authenticated requests flow through both.

## Plugin config schema

| Field          | Type     | Required                          | Notes                                                            |
|----------------|----------|-----------------------------------|------------------------------------------------------------------|
| `gate`         | string   | One of `{gate, amount}` required  | Name registered via bootstrap-time `pay_kit.gate(name, opts)`.   |
| `amount`       | string   | One of `{gate, amount}` required  | Inline form: `"0.10"` (parsed by `pay_kit.usd`).                 |
| `stablecoins`  | string[] | Required when `amount` is set     | Ordered preference list, e.g. `["USDC", "USDT"]`.                |
| `accept`       | string[] | Optional                          | Subset of `{"x402", "mpp"}`. Defaults to config-level accept.    |
| `pay_to`       | string   | Optional                          | Per-gate override (marketplace pattern). Defaults to operator.   |
| `description`  | string   | Optional                          | Human label echoed in the challenge.                             |
