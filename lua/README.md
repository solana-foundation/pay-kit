<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="PayKit" width="100%" />
</p>

# solana-pay-kit (Lua / OpenResty)

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in
Lua. Runs on LuaJIT 2.1 (the OpenResty / Kong / APISIX production
runtime). One library, two protocols underneath:
[x402](https://x402.org) and the
[Machine Payments Protocol](https://mpp.dev). Server-side only;
clients live in the TypeScript, Rust, Go, Python, Ruby, Kotlin, and
Swift packages.

This package supersedes the previous MPP-only `mpp` LuaRocks package.
`require('mpp')` still works (deprecation shim) and points at the
new `require('resty.pay_kit')` umbrella.

[![LuaJIT](https://img.shields.io/badge/luajit-2.1-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)]()

## Quick start

```nginx
http {
  lua_shared_dict pay_kit_replay 10m;

  init_by_lua_block {
    local pay_kit = require('resty.pay_kit')
    local signer  = require('resty.pay_kit.signer')

    assert(pay_kit.configure({
      network = 'solana_devnet',
      operator = {
        recipient = os.getenv('PAY_KIT_OPERATOR_RECIPIENT'),
        signer    = signer.from_env('PAY_KIT_OPERATOR_KEY'),
      },
      mpp = { challenge_binding_secret = os.getenv('PAY_KIT_MPP_SECRET') },
    }))

    pay_kit.gate('report', { amount = pay_kit.usd('0.10') })
  }

  server {
    location = /report {
      access_by_lua_block { require('resty.pay_kit').require_payment('report') }
      proxy_pass http://backend;
    }
  }
}
```

That's the whole demo. The library:

- Emits an HTTP 402 with `WWW-Authenticate: Payment` (MPP) and
  `PAYMENT-REQUIRED` (x402) headers when no credential is present.
- Verifies the credential, broadcasts on-chain (self-hosted x402),
  and consumes the signature in the cross-worker
  `ngx.shared.pay_kit_replay` dict. Delegated x402 mode
  (`x402.facilitator_url`) is reserved in the config but not
  wired yet; the dispatcher raises `not implemented` if the flag
  is set.
- Echoes settlement headers (`x-payment-settlement-signature`,
  `payment-response`) onto the upstream 200 so clients verify.

`signer.from_env('PAY_KIT_OPERATOR_KEY')` returns `nil` for unset
env vars - the operator table picks up the default in-process demo
signer in that case. Production refuses to start with the demo
signer on `solana_mainnet`.

## Three primitives

Mirrors `lua-resty-openidc`'s shape and the cross-SDK trio:

| Function                                    | Returns                | On unpaid                          |
|---------------------------------------------|------------------------|------------------------------------|
| `pay_kit.require_payment(name_or_opts)`     | `payment` table        | halts via `ngx.exit(402)`          |
| `pay_kit.try_payment(name_or_opts)`         | `(payment, err, resp)` | never halts (you render the 402)   |
| `pay_kit.payment()`                         | `payment | nil`        | -                                  |
| `pay_kit.paid()` / `paid_for(name)`         | `bool`                 | -                                  |

`require_payment` is the bang form Kong / APISIX plugins use; the
`try_*` form gives callers control of the 402 response when needed.

## Gates

```lua
-- Simple
pay_kit.gate('report', { amount = pay_kit.usd('0.10') })

-- x402-only
pay_kit.gate('api_call', {
  amount = pay_kit.usd('0.001', 'USDC'),
  accept = { 'x402' },
})

-- Multi-recipient (MPP only; x402 auto-disabled)
pay_kit.gate('marketplace_sale', {
  amount     = pay_kit.usd('10.00'),
  pay_to     = SELLER,
  fee_within = { [PLATFORM] = pay_kit.usd('0.30') },
})

-- Dynamic
pay_kit.gate('tiered', function(req)
  local tier = req.query.tier
  return { amount = pay_kit.usd(tier == 'premium' and '5.00' or '0.10') }
end)
```

`pay_kit.usd('0.10')` returns a Price with the integer micro-units
amount (`100000`) and an ordered settlement preference list. Floats
are rejected at the call site - pass a string literal.

Six rules, validated at registration time:

1. Fixed amounts only.
2. `pay_to` optional; defaults to `operator.recipient`.
3. All amounts share one denomination.
4. `sum(fee_within) <= amount`.
5. x402 auto-disabled when fees present.
6. Stablecoin preference lives on the gate or config, not per-fee.

## Operator

One value bundling the merchant identity:

```lua
operator = {
  recipient = 'Cs2zd...',                                -- where settled funds land
  signer    = signer.file('/etc/paykit/operator.json'),  -- Ed25519 keypair
  fee_payer = true,                                      -- pays SOL fees
}
```

Eight signer factories live in `resty.pay_kit.signer`:

- `signer.demo()`          - hard-coded demo keypair (warns at boot, refused on mainnet)
- `signer.bytes(table_64)` - 64-byte Solana CLI keypair as table of ints
- `signer.json(str)`       - Solana CLI JSON-array format
- `signer.base58(str)`     - Phantom / Solflare export
- `signer.hex(str)`        - 128-char hex
- `signer.file(path)`      - read JSON-array file
- `signer.from_env(name)`  - read env var; auto-detects format; `nil` for unset
- `signer.generate()`      - fresh keypair (test-only)

Remote enclave signers (`resty.pay_kit.kms.{gcp,aws,vault}`) are
reserved namespaces; v1 returns `not implemented yet`. The duck type
(`:pubkey`, `:sign`, `:fee_payer`, `:demo`) is locked so the
post-v1 swap does not change call sites.

## Chain access

`rpc_url` is the Solana RPC endpoint (any RPC; defaults to the public
network endpoint when omitted; production should use a private RPC).
`x402.facilitator_url` is reserved for delegated mode (POST verify +
settle to a facilitator; the lib never touches the chain in that
shape). The flag is recognized by the config schema but not wired:
the dispatcher raises `not implemented` if you set it. Self-hosted
is the only x402 path that ships in v1.

```lua
{
  rpc_url = 'https://helius.example.com',         -- private mainnet RPC
  x402 = { facilitator_url = nil },               -- self-hosted (only v1 path)
}
```

## Replay protection

Auto-detects `ngx.shared.pay_kit_replay`. Declare it once in nginx.conf:

```nginx
http { lua_shared_dict pay_kit_replay 10m; }
```

Falls back to a per-worker in-memory LRU when the dict is missing
(useful for single-worker dev; logs a WARN). Pure-Lua (no OpenResty)
callers can pass `opts.replay_store` to `configure()`.

## Crypto

Ed25519 backend resolves at module load:

1. **lua-resty-openssl** (preferred). Bundled with Kong 3.x; one
   `luarocks install lua-resty-openssl` on APISIX. No system libsodium
   required.
2. **luasodium** (fallback). Plain LuaJIT dev environments without
   OpenResty / OpenSSL still get a working signer.

`resty.pay_kit.util.ed25519.backend()` returns `"openssl"` /
`"luasodium"` / `"none"` so operators can log which path is hot.

## Kong + APISIX

Two gateway plugins ship in the same monorepo:

- **`kong-plugin-pay-kit`** -
  `kong/plugins/pay-kit/{handler,schema,bootstrap}.lua`. Wires via
  `KONG_PLUGINS=bundled,pay-kit` + a one-line
  `KONG_NGINX_HTTP_INIT_BY_LUA_BLOCK` that reads PAY_KIT_* env vars.
  See [`examples/openresty/kong-plugin/`](examples/openresty/kong-plugin/).
- **`apisix-plugin-pay-kit`** -
  `apisix/plugins/pay-kit.lua`. Sibling to the Kong plugin with
  APISIX's two-arg phase methods + json-schema config.

Both are thin shims (~100 lines each); the heavy lifting lives in
`resty.pay_kit` so adding a third gateway is a one-file copy.

## Examples

Three runnable examples ship with this package:

- [`examples/simple-server.lua`](examples/simple-server.lua) - bare
  LuaJIT TCP accept loop, MPP only (predates the PayKit umbrella;
  drives the legacy mpp.server).
- [`examples/openresty/`](examples/openresty/) - OpenResty / nginx
  config with the PayKit umbrella in `init_by_lua_block` and a
  one-line `access_by_lua_file`.
- [`examples/openresty/kong-plugin/`](examples/openresty/kong-plugin/) -
  Kong custom plugin walkthrough.

### Run the OpenResty example

```bash
cd lua/examples/openresty
openresty -p . -c nginx.conf

curl  http://127.0.0.1:4570/report          # 402 + WWW-Authenticate + PAYMENT-REQUIRED
pay curl http://127.0.0.1:4570/report       # pays and succeeds (with `brew install pay`)
```

## Coverage

```bash
cd lua
just test-cover
```

Local target: line coverage ≥ 90% under luacov. Heavy ATA derivation
spec runs once without luacov (JIT trace requirement).

## Layers

```
resty.pay_kit                       umbrella (configure, gate, usd,
                                    require_payment, try_payment, payment,
                                    paid, paid_for, errors)
resty.pay_kit.signer                Local signer factories
resty.pay_kit.signer.demo           Published demo keypair + warn-once
resty.pay_kit.kms                   Remote enclave signers (post-v1 reserved)
resty.pay_kit.operator              Merchant identity value object
resty.pay_kit.config                Boot-time configure() resolver
resty.pay_kit.gate / fee / registry Gate registry + Fee value object
resty.pay_kit.price                 usd() integer-micro-units helper
resty.pay_kit.schemes.{mpp,x402}    Protocol adapters
resty.pay_kit.dispatcher            Per-worker dispatcher
resty.pay_kit.store                 Replay store (shared_dict + memory)
resty.pay_kit.util.ed25519          Crypto backend abstraction
resty.pay_kit.errors                Canonical error-string constants

kong/plugins/pay-kit/                Kong custom plugin
apisix/plugins/pay-kit.lua           APISIX custom plugin
mpp/                                 Legacy MPP-only surface (deprecated shim)
```
