--[[
solana-pay-kit — Lua / OpenResty SDK umbrella.

Single module surface (mirrors `lua-resty-openidc`):

  local pay_kit = require('pay_kit')

  pay_kit.configure({ ... })                  -- boot-time configuration
  pay_kit.gate(name, opts)                    -- register a gate
  pay_kit.usd("0.10", "USDC")                 -- price helper
  pay_kit.require_payment(name)               -- access-phase gate (halts via ngx.exit)
  pay_kit.try_payment(name)                   -- (payment, err) form for custom 402
  pay_kit.payment()                           -- current ngx.ctx payment or nil
  pay_kit.paid()                              -- bool
  pay_kit.paid_for(name)                      -- bool

Umbrella re-exports (indexable off the returned table):

  pay_kit.signer                        -- Local signer factories
  pay_kit.kms                           -- Remote-enclave signer factories (reserved)
  pay_kit.errors                        -- Canonical error-string constants
  pay_kit.operator                      -- Operator construction helpers

Protocol adapters and the JSON-RPC client are not re-exported off the
umbrella; `require` them directly:

  require('pay_kit.protocols.mpp')      -- MPP adapter
  require('pay_kit.protocols.x402')     -- x402 adapter
  require('pay_kit.solana.rpc')         -- Cosocket-aware JSON-RPC client

This file is intentionally thin: it pulls the umbrella surface from
the dedicated sub-modules so the layout stays readable. Each sub-
module is independently `require`able for callers that want only one
piece (the Kong plugin only needs `signer` + the protocol adapters,
for example).
]]

local M = {}

M._VERSION = '0.1.0'

-- Internal modules backing the top-level surface below.
local config_mod     = require('pay_kit.internal.config')
local price_mod      = require('pay_kit.internal.price')
local registry_mod   = require('pay_kit.internal.registry')
local dispatcher_mod = require('pay_kit.internal.dispatcher')

M.signer   = require('pay_kit.signer')
M.kms      = require('pay_kit.kms')
M.errors   = require('pay_kit.errors')
M.operator = require('pay_kit.internal.operator')

-- Top-level surface.
function M.configure(opts) return config_mod.configure(opts) end
function M.config() return config_mod.current() end
function M.usd(amount, ...) return price_mod.usd(amount, ...) end
function M.gate(name, opts_or_fn) return registry_mod.register(name, opts_or_fn) end
function M.require_payment(arg, req) return dispatcher_mod.require_payment(arg, req) end
function M.try_payment(arg, req) return dispatcher_mod.try_payment(arg, req) end
function M.payment() return dispatcher_mod.payment() end
function M.paid() return dispatcher_mod.paid() end
function M.paid_for(name) return dispatcher_mod.paid_for(name) end

-- Test-only escape hatch; production callers never use this.
function M._reset_for_tests()
  config_mod._reset_for_tests()
  registry_mod._unfreeze_for_tests()
  dispatcher_mod._reset_for_tests()
  require('pay_kit.signer.demo').reset_for_tests()
end

return M
