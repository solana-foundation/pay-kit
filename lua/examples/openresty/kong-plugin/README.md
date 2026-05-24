# Kong custom plugin: `mpp-charge`

A Kong custom plugin that gates upstream API routes behind an MPP
`charge` challenge. The plugin runs in the `access` phase, issues a
402 with a signed `WWW-Authenticate` header on first contact, and
runs the full Solana settlement lifecycle (decode the wire
transaction, cosign with the configured fee payer, simulate,
broadcast, consume, await) on the credentialed retry.

## Layout

```
kong-plugin/
├── README.md
└── kong/plugins/mpp-charge/
    ├── handler.lua
    └── schema.lua
```

Kong's plugin loader expects the `kong/plugins/<name>/handler.lua`
and `kong/plugins/<name>/schema.lua` paths exactly; do not flatten
them.

## Install

Copy the `kong/plugins/mpp-charge` directory into the location where
Kong loads custom plugins (typically `/usr/local/share/lua/5.1/kong/plugins/`
on Linux distributions, or your local-build override directory). Add
`mpp-charge` to the `plugins` directive in `kong.conf`:

```
plugins = bundled,mpp-charge
```

You also need the Lua MPP SDK installed into Kong's rocks tree:

```
sudo luarocks --lua-version=5.1 install <path-to-mpp-dev-1.rockspec>
sudo luarocks --lua-version=5.1 install luasocket
sudo luarocks --lua-version=5.1 install luasodium
sudo luarocks --lua-version=5.1 install luasec
sudo luarocks --lua-version=5.1 install lua-resty-http
```

The `luasodium` rock requires `libsodium` at the system level
(`apt-get install libsodium-dev` on Debian / Ubuntu,
`brew install libsodium` on macOS).

`lua-resty-http` ships bundled with OpenResty distributions; install
the rock explicitly on bare nginx-with-Lua builds. The plugin uses
it for non-blocking, cosocket-based Solana RPC calls. The blocking
`socket.http` / `ssl.https` transport from `mpp.solana.rpc_transport`
would block the entire nginx worker for the full RPC round trip and
starve every other concurrent request on that worker; never wire
that transport into the access phase. The `luasocket` and `luasec`
rocks are still required because `mpp.solana.rpc_transport` is loaded
by the standalone luajit server example and indirectly via the
rockspec dependency list.

## Shared replay store (cross-worker safety)

Kong's default `worker_processes auto` spawns one Lua state per CPU
core. An in-memory replay store is per-Lua-state, so a credential
consumed by Worker A is invisible to Workers B, C, etc., and an
attacker who receives a valid Payment-Receipt can replay the same
`Authorization: Payment` header against a different worker and obtain
another 200 OK with a fresh on-chain settlement.

The plugin routes replay through `ngx.shared.DICT`, which lives in
nginx-managed shared memory and is atomic across workers. The shared
dict must be declared at the http block level. Add this to Kong's
`nginx_http_*` template directives or to the nginx.conf snippet Kong
loads:

```
lua_shared_dict mpp_replay 10m;
```

Size the dict by expected QPS times challenge lifetime. 10 MB is
enough for ~50,000 consumed-signature entries (each entry is ~200
bytes including key + JSON payload). The `:add` primitive used for
`put_if_absent` is atomic across workers, so duplicate detection is
correct regardless of how many workers Kong starts.

The dict name is configurable via the plugin's `shared_dict_name`
field (default `mpp_replay`). If the dict is not declared at boot,
the plugin raises a clear error pointing back to this README.

## Configure

Per-service via the Kong admin API:

```
curl -i -X POST http://localhost:8001/services/protected-api/plugins \
  -d "name=mpp-charge" \
  -d "config.recipient=<base58 pubkey>" \
  -d "config.currency=USDC" \
  -d "config.network=mainnet-beta" \
  -d "config.secret_key=<hmac secret>" \
  -d "config.amount=1.50" \
  -d "config.rpc_url=https://api.mainnet-beta.solana.com" \
  -d "config.fee_payer_secret_key=[148,222,...]"
```

The `fee_payer_secret_key` is optional. When provided, the plugin
cosigns the client's wire transaction with the configured Solana
keypair before broadcasting. When omitted, the client must
pre-cosign and the plugin only verifies / consumes / awaits.

## Behavior

- `GET /protected` without `Authorization: Payment ...` returns 402
  with a signed `WWW-Authenticate` challenge.
- The same request with `Authorization: Payment ...` triggers the
  full settlement; on success, the request continues upstream and
  the response carries a `Payment-Receipt` header with the on-chain
  signature.
- A failed settlement (transaction decode error, amount mismatch,
  network mismatch, replay) returns a fresh 402.

The plugin caches one `mpp.server` instance per unique `conf` value
to avoid rebuilding the verifier / RPC / signer on every request.
The cache key is the configuration table identity; Kong replaces it
when the operator PATCHes the plugin config.
