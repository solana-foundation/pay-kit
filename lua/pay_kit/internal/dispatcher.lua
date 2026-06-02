--[[
Per-worker dispatcher.

Holds the long-lived adapter instances + replay store. The four
public entry points (require_payment / try_payment / payment / paid /
paid_for) live on the umbrella module and delegate here.

Lifecycle:
- One dispatcher per worker (cached after first configure()).
- Holds the per-gate MPP server cache and x402 adapter inside the
  scheme adapters so warm requests do not rebuild challenge stores.
- Reads the active config via `config.current()` so post-configure
  state stays consistent across calls.

Pure-Lua / no-ngx mode:
- `require_payment` returns (payment, err) instead of calling
  ngx.exit. Caller writes the 402 itself.
- The thread-local payment slot is a module-level local table since
  Lua coroutines and ngx.ctx are not available.
]]

local config_mod  = require('pay_kit.internal.config')
local registry    = require('pay_kit.internal.registry')
local store_mod   = require('pay_kit.store')
local errors      = require('pay_kit.errors')
local x402_mod    = require('pay_kit.protocols.x402')
local mpp_mod     = require('pay_kit.protocols.mpp')

local M = {}

local dispatcher          -- module-level singleton (resolved lazily)
local payment_no_ngx      -- pure-Lua thread-local substitute for ngx.ctx

local function get_ngx() return rawget(_G, 'ngx') end

local function config_resolver() return config_mod.current() end

local function init_dispatcher()
  local cfg = config_mod.current()
  if not cfg then return nil, 'pay_kit: configure() must be called before any payment helper' end
  local store, _backend = store_mod.detect()
  local x402 = assert(x402_mod.new({config_resolver = config_resolver, store = store}))
  local mpp  = assert(mpp_mod.new({config_resolver = config_resolver, store = store}))
  return {
    config = cfg,
    store  = store,
    x402   = x402,
    mpp    = mpp,
  }
end

local function ensure_dispatcher()
  if dispatcher then return dispatcher end
  local d, err = init_dispatcher()
  if not d then return nil, err end
  dispatcher = d
  return d
end

local function request_from_ngx_or_table(req)
  if type(req) == 'table' then return req end
  local ngx_ref = get_ngx()
  if not ngx_ref then return {headers = {}, path = '/', query = {}} end
  return {
    headers = ngx_ref.req and ngx_ref.req.get_headers and ngx_ref.req.get_headers() or {},
    path    = (ngx_ref.var and ngx_ref.var.uri) or '/',
    query   = ngx_ref.req and ngx_ref.req.get_uri_args and ngx_ref.req.get_uri_args() or {},
  }
end

-- Resolve a name or inline-opts table to a static Gate. Dynamic gates
-- materialise against the request here.
local function resolve_gate(arg, request)
  if type(arg) == 'string' then
    return registry.materialize(arg, request)
  end
  if type(arg) == 'table' then
    return registry.build_inline(arg)
  end
  return nil, 'pay_kit: require_payment expects a gate name or option table'
end

-- Issue an unpaid request's 402 response. The dispatcher decides
-- which adapter wrote the response; for a multi-scheme gate, accepts[]
-- carries one entry per accepted scheme.
local function build_402(d, gate, request)
  local accepts = {}
  -- A 402 carries a fresh, single-use signed challenge (per-request
  -- nonce / blockhash / expiry). It must never be cached or reused by an
  -- intermediary, so pin `Cache-Control: no-store`. Mirrors PHP
  -- ChargeServer::paymentRequiredResponse and the Ruby/x402 402 helpers.
  local headers = { ['cache-control'] = 'no-store' }
  if gate:x402_accepted() then
    accepts[#accepts + 1] = d.x402:accepts_entry(gate, request)
    local h = d.x402:challenge_headers(gate, request) or {}
    for k, v in pairs(h) do headers[k] = v end
  end
  if gate:mpp_accepted() then
    accepts[#accepts + 1] = d.mpp:accepts_entry(gate, request)
    local h = d.mpp:challenge_headers(gate, request) or {}
    for k, v in pairs(h) do headers[k] = v end
  end
  return {
    body = {error = 'payment_required', resource = request.path, accepts = accepts},
    headers = headers,
  }
end

-- Pick the right adapter for this request based on detected headers.
-- Returns (adapter, scheme_name) or nil.
local function pick_adapter(d, gate, request)
  if gate:x402_accepted() and d.x402.detect and d.x402:detect(request.headers or {}) then
    return d.x402, 'x402'
  end
  if gate:mpp_accepted() and d.mpp.detect and d.mpp:detect(request.headers or {}) then
    return d.mpp, 'mpp'
  end
  return nil
end

local function set_payment(payment)
  local ngx_ref = get_ngx()
  if ngx_ref and ngx_ref.ctx then ngx_ref.ctx.pay_kit_payment = payment end
  payment_no_ngx = payment
end

local function get_payment()
  local ngx_ref = get_ngx()
  if ngx_ref and ngx_ref.ctx then return ngx_ref.ctx.pay_kit_payment end
  return payment_no_ngx
end

-- --- public API -----------------------------------------------------

function M.try_payment(arg, request_override)
  local d, err = ensure_dispatcher()
  if not d then return nil, err end
  local request = request_from_ngx_or_table(request_override)
  local gate, gerr = resolve_gate(arg, request)
  if not gate then return nil, gerr end

  local adapter = pick_adapter(d, gate, request)
  if not adapter then
    -- Nothing to verify. Return a 402 response payload so the caller
    -- can emit it themselves (try_payment never halts).
    return nil, errors.PAYMENT_REQUIRED, build_402(d, gate, request)
  end
  local payment, verr = adapter:verify_and_settle(gate, request)
  if not payment then return nil, verr end
  set_payment(payment)
  return payment
end

-- Halts via ngx.exit when a 402 is needed. Returns the verified
-- payment otherwise. Mirrors `lua-resty-openidc.authenticate`.
function M.require_payment(arg, request_override)
  local payment, err, response = M.try_payment(arg, request_override)
  if payment then return payment end

  local ngx_ref = get_ngx()
  if not ngx_ref or not ngx_ref.exit then
    -- Pure-Lua mode: hand back the same shape try_payment would.
    return nil, err, response
  end

  -- Emit the 402 to the OpenResty / Kong access phase and halt.
  if response then
    local cjson_safe = require('cjson.safe')
    ngx_ref.status = ngx_ref.HTTP_PAYMENT_REQUIRED or 402
    if response.headers then
      for k, v in pairs(response.headers) do
        ngx_ref.header[k] = v
      end
    end
    ngx_ref.header['content-type'] = 'application/json'
    ngx_ref.say(cjson_safe.encode(response.body))
  else
    ngx_ref.status = 402
    ngx_ref.say(err or errors.INVALID_PROOF)
  end
  return ngx_ref.exit(ngx_ref.HTTP_PAYMENT_REQUIRED or 402)
end

function M.payment()
  return get_payment()
end

function M.paid()
  return get_payment() ~= nil
end

-- True iff `payment()` exists AND the most-recent verify was for
-- the same gate name. Useful for opportunistic gating from a free
-- route ("show premium content if the client already paid for the
-- premium tier").
function M.paid_for(name)
  local p = get_payment()
  if not p then return false end
  return p.gate_name == name or p._gate_name == name
end

-- Test-only: clear cached dispatcher + payment.
function M._reset_for_tests()
  dispatcher = nil
  payment_no_ngx = nil
end

return M
