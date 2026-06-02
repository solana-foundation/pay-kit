--[[
Apache APISIX plugin for PayKit.

Sibling to `kong/plugins/pay-kit/handler.lua` - same `pay_kit`
library, different gateway envelope. APISIX plugins are single-file
modules, take `function _M.access(conf, ctx)`, and short-circuit by
returning `(status, body, headers)` from the access phase.

The global concerns (operator, signer, RPC URL, MPP secret) live in
env vars consumed by `kong/plugins/pay-kit/init.lua`-style code
that APISIX operators wire via `apisix.init_worker_hook` or an
`access_by_lua_file` near the top of `conf/config.yaml`'s
`apisix.lua_module_hook`. See examples/nginx/README.md.

Priority 2520 sits just above APISIX's jwt-auth (2510) so payment
acts as a paid-tier gate on top of identity auth.
]]

local pay_kit = require('pay_kit')
local core    = require('apisix.core')

local plugin_name = 'pay-kit'

local schema = {
  type = 'object',
  properties = {
    gate        = {type = 'string'},
    amount      = {type = 'string'},
    stablecoins = {type = 'array', items = {type = 'string'}, minItems = 1},
    accept      = {type = 'array', items = {type = 'string', enum = {'x402', 'mpp'}}},
    pay_to      = {type = 'string'},
    description = {type = 'string'},
  },
  anyOf = {
    {required = {'gate'}},
    {required = {'amount'}},
  },
}

local _M = {
  version  = 0.1,
  priority = 2520,
  name     = plugin_name,
  schema   = schema,
}

function _M.check_schema(conf)
  return core.schema.check(schema, conf)
end

local function gate_arg_for(conf)
  if conf.gate and conf.gate ~= '' then return conf.gate end
  local stablecoins = conf.stablecoins or {'USDC'}
  local price, perr = pay_kit.usd(conf.amount, unpack(stablecoins))
  if not price then return nil, perr end
  return {
    amount      = price,
    pay_to      = conf.pay_to,
    accept      = conf.accept,
    description = conf.description,
  }
end

local function request_table(ctx)
  return {
    headers = core.request.headers(ctx) or {},
    path    = (ctx and ctx.var and ctx.var.uri) or '/',
    query   = core.request.get_uri_args(ctx) or {},
  }
end

function _M.access(conf, ctx)
  local arg, err = gate_arg_for(conf)
  if not arg then
    core.log.error('pay-kit: invalid plugin config: ', err)
    return 500, {error = err}
  end

  local request = request_table(ctx)
  local payment, perr, response = pay_kit.try_payment(arg, request)
  if payment then
    ctx.pay_kit_payment = payment
    -- Stamp settlement headers onto the upstream response so the
    -- client sees the on-chain signature.
    if payment.settlement_headers then
      ctx.pay_kit_settlement_headers = payment.settlement_headers
    end
    return
  end

  if response then
    return 402, response.body, response.headers or {}
  end
  return 402, {error = perr or 'payment_required'}
end

function _M.header_filter(_conf, ctx)
  local headers = ctx and ctx.pay_kit_settlement_headers
  if not headers then return end
  for k, v in pairs(headers) do
    core.response.set_header(k, v)
  end
end

return _M
