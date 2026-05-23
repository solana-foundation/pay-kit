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
          { secret_key = { type = 'string', required = true } },
          { realm      = { type = 'string', required = false, default = 'MPP' } },
          { amount     = { type = 'string', required = true } },
          { rpc_url    = { type = 'string', required = true } },
          { fee_payer_secret_key = { type = 'string', required = false } },
          -- Shared dict name backing the cross-worker replay store.
          -- Must match a `lua_shared_dict <name> <size>` directive in
          -- the http block. Default `mpp_replay` matches the example
          -- nginx.conf shipped under the kong-plugin README.
          { shared_dict_name = { type = 'string', required = false, default = 'mpp_replay' } },
        },
      },
    },
  },
}
