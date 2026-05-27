-- luacheck: globals kong
--[[
Kong plugin handler for PayKit.

Thin shim over `pay_kit`. Phase methods follow Kong 3.x
conventions (PRIORITY constant, `:access(conf)` no-ctx, header_filter
+ log for receipt stamping). The library does the work; this file
turns plugin config into a Gate and calls require_payment.

Mount via:
  KONG_PLUGINS=bundled,pay-kit
  KONG_NGINX_HTTP_INIT_BY_LUA_BLOCK="require('plugins.kong.plugins.pay-kit.init').setup()"
plus the per-route plugin config (`gate` name or inline amount/mint
fields - see schema.lua).

PRIORITY = 1010 sits between Kong's basic-auth (1001) and OpenID
Connect (1050), and well above rate-limiting (910) so unpaid traffic
never burns the rate-limit bucket.
]]

local pay_kit = require('pay_kit')

local PayKit = {
  PRIORITY = 1010,
  VERSION  = '0.1.0',
}

-- Resolve the gate for this request. Plugin config carries either a
-- registry `gate` name OR inline gate fields (amount, mint, pay_to,
-- accept, description). Inline form is convenient for one-off routes;
-- the registered form lets one Pricing block declare the catalogue.
local function gate_arg_for(conf)
  if conf.gate and conf.gate ~= '' then return conf.gate end
  local stablecoins = conf.stablecoins or {'USDC'}
  local price, perr = pay_kit.usd(conf.amount, unpack(stablecoins))
  if not price then return nil, perr end
  local opts = {
    amount      = price,
    pay_to      = conf.pay_to,
    accept      = conf.accept,
    description = conf.description,
  }
  return opts
end

local function request_table()
  local headers = (kong and kong.request and kong.request.get_headers and kong.request.get_headers()) or {}
  local path    = (kong and kong.request and kong.request.get_path and kong.request.get_path()) or '/'
  local query   = (kong and kong.request and kong.request.get_query and kong.request.get_query()) or {}
  return {headers = headers, path = path, query = query}
end

function PayKit:init_worker()
  -- Per-worker hook. configure() lives in bootstrap.lua so master init
  -- can read env vars before fork; per-worker work happens lazily in
  -- :access() through the dispatcher cache.
end

function PayKit:access(conf)
  local arg, err = gate_arg_for(conf)
  if not arg then
    kong.log.err('pay-kit: invalid plugin config: ', err)
    return kong.response.exit(500, {error = err})
  end

  local request = request_table()
  local payment, perr, response = pay_kit.try_payment(arg, request)
  if payment then
    kong.ctx.shared.pay_kit_payment = payment
    return
  end

  -- Emit 402 with the dispatcher's response envelope so downstream
  -- adapters (logging, observability) can read the shape.
  local body, headers
  if response then
    body = response.body
    headers = response.headers or {}
  else
    body = {error = perr or 'payment_required'}
    headers = {}
  end
  return kong.response.exit(402, body, headers)
end

function PayKit:header_filter(_conf)
  -- Stamp settlement headers onto a successful response. The
  -- dispatcher already set them on `payment.settlement_headers`; the
  -- response handler echoes them so the client can verify.
  local payment = kong.ctx.shared.pay_kit_payment
  if not payment or not payment.settlement_headers then return end
  for k, v in pairs(payment.settlement_headers) do
    if kong.response.get_header(k) == nil then
      kong.response.set_header(k, v)
    end
  end
end

function PayKit:log(_conf)
  -- Optional structured-log emission. Apps wanting a metric can read
  -- kong.ctx.shared.pay_kit_payment in their own log plugin.
end

return PayKit
