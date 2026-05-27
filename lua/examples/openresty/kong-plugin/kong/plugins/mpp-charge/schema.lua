--[[
Kong plugin schema for `mpp-charge`.

Declares the per-service configuration fields the handler reads. The
schema uses Kong's `typedefs` for url fields and the standard
`name`/`fields` shape that Kong's `Schema` engine validates at startup
and on every PATCH /plugins call.
]]

local typedefs = require('kong.db.schema.typedefs')

return {
  name = 'mpp-charge',
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = 'record',
        fields = {
          { recipient  = { type = 'string', required = true } },
          { currency   = { type = 'string', required = true, default = 'USDC' } },
          { decimals   = { type = 'integer', required = false, default = 6 } },
          { network    = { type = 'string', required = false, default = 'mainnet-beta' } },
          -- referenceable + encrypted on every secret field. Kong vault
          -- references like {vault://env/MPP_SECRET_KEY} only resolve
          -- when the schema marks the field referenceable; encrypted
          -- forces Kong to encrypt at rest in the Postgres/Cassandra
          -- backing store instead of writing the raw key as plaintext.
          -- Operators who use Kong Enterprise vaults or KMS-backed
          -- workflows need both flags to keep the Ed25519 + HMAC
          -- material out of plain DB rows.
          { secret_key = { type = 'string', required = true, referenceable = true, encrypted = true } },
          { realm      = { type = 'string', required = false, default = 'MPP' } },
          { amount     = { type = 'string', required = true } },
          { rpc_url    = { type = 'string', required = true } },
          { fee_payer_secret_key = { type = 'string', required = false, referenceable = true, encrypted = true } },
          -- Shared dict name backing the cross-worker replay store.
          -- Must match a `lua_shared_dict <name> <size>` directive in
          -- the http block. Default `mpp_replay` matches the example
          -- nginx.conf shipped under the kong-plugin README.
          { shared_dict_name = { type = 'string', required = false, default = 'mpp_replay' } },
          -- Timeout in seconds applied to connect/send/read on the
          -- non-blocking cosocket RPC transport. The default (30s)
          -- matches `pay_kit.solana.rpc_transport`.
          { rpc_timeout = { type = 'number', required = false, default = 30 } },
          -- Whether the cosocket transport verifies the TLS chain on
          -- HTTPS RPC URLs. Defaults to true; toggle off only for
          -- self-signed test endpoints.
          { rpc_ssl_verify = { type = 'boolean', required = false, default = true } },
          -- TTL applied to the cross-worker replay marker stored in
          -- ngx.shared.DICT. Without a TTL the dict relies on LRU
          -- eviction when memory pressure hits, which can release a
          -- consumed signature back into the replay surface while the
          -- credential is still within its challenge validity window.
          -- Default 86400 seconds (24h) is well beyond any plausible
          -- challenge expires lifetime; tune higher only if you sign
          -- long-lived credentials.
          { replay_ttl_seconds = { type = 'number', required = false, default = 86400 } },
        },
      },
    },
  },
}
