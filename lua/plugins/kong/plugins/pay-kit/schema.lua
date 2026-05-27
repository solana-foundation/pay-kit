--[[
Kong plugin schema for PayKit.

Per-route config carries either a gate name (registered globally via
bootstrap.lua during init) OR inline gate fields. The global concerns
(operator identity, signer, RPC URL, MPP secret) come from env vars
read at init time - they do not vary per route.
]]

local typedefs = require('kong.db.schema.typedefs')

return {
  name = 'pay-kit',
  fields = {
    {protocols = typedefs.protocols_http},
    {consumer = typedefs.no_consumer},
    {config = {
      type = 'record',
      fields = {
        -- Either reference a registered gate by name...
        {gate = {type = 'string'}},
        -- ...or specify an inline gate's fields:
        {amount      = {type = 'string'}},
        {stablecoins = {type = 'array', elements = {type = 'string'}}},
        {accept = {
          type = 'array',
          elements = {type = 'string', one_of = {'x402', 'mpp'}},
        }},
        {pay_to      = {type = 'string'}},
        {description = {type = 'string'}},
      },
      entity_checks = {
        {at_least_one_of = {'gate', 'amount'}},
        {conditional = {
          if_field = 'amount',
          if_match = {ne = ''},
          then_field = 'stablecoins',
          then_match = {required = true},
        }},
      },
    }},
  },
}
