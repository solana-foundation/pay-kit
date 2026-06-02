# PayKit nginx example

Gates `/report` behind a stablecoin charge using the `pay_kit` umbrella in
an OpenResty / nginx access phase. `/health` stays free.

The whole gate is one line in [`access.lua`](access.lua):

```lua
require('pay_kit').require_payment('report')
```

Boot wiring (`configure` + `gate`) lives in the `init_by_lua_block` of
[`nginx.conf`](nginx.conf) and runs once at master init. With no
environment set it uses sensible defaults: `solana_localnet` resolves to
the hosted Surfpool RPC at `https://402.surfnet.dev:8899`, and the
published demo signer acts as both operator and recipient.

## Run

Requires OpenResty 1.21+ with `lua-resty-openssl`.

```sh
cd lua/examples/nginx
openresty -p . -c nginx.conf
```

Then, in another terminal:

```sh
curl -i http://127.0.0.1:4570/health     # 200 (unprotected)
curl -i http://127.0.0.1:4570/report     # 402 with PAYMENT-REQUIRED + WWW-Authenticate
pay curl http://127.0.0.1:4570/report    # 200 with the protected payload
```

## Production

Override the demo defaults through the umbrella config:

- set `network = 'solana_mainnet'` (or `solana_devnet`)
- pass a real `operator.signer` and `operator.recipient`
- set a strong `mpp.challenge_binding_secret`
- point `rpc_url` at a dedicated RPC endpoint

The demo signer is published in the source and is refused on
`solana_mainnet`.
