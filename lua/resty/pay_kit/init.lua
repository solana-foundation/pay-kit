--[[
solana-pay-kit — Lua / OpenResty SDK umbrella.

Single module surface (mirrors `lua-resty-openidc`):

  local pay_kit = require('resty.pay_kit')

  pay_kit.configure({ ... })                  -- boot-time configuration
  pay_kit.gate(name, opts)                    -- register a gate
  pay_kit.usd("0.10", "USDC")                 -- price helper
  pay_kit.require_payment(name)               -- access-phase gate (halts via ngx.exit)
  pay_kit.try_payment(name)                   -- (payment, err) form for custom 402
  pay_kit.payment()                           -- current ngx.ctx payment or nil
  pay_kit.paid()                              -- bool
  pay_kit.paid_for(name)                      -- bool

Sub-modules:

  resty.pay_kit.signer                        -- Local signer factories
  resty.pay_kit.kms                           -- Remote-enclave signer factories (reserved, v1.5+)
  resty.pay_kit.errors                        -- Canonical error-string constants
  resty.pay_kit.schemes.{mpp, x402}           -- Protocol adapters
  resty.pay_kit.solana.rpc                    -- Cosocket-aware JSON-RPC client

This file is intentionally thin: it pulls the umbrella surface from
the dedicated sub-modules so the layout stays readable. Each sub-
module is independently `require`able for callers that want only one
piece (the Kong plugin only needs `signer` + `schemes.*`, for example).

The phase-by-phase implementation lands across P1-P12; this entry
point exposes whatever subset is ready as the work progresses, so
that any consumer who pins to `resty.pay_kit` gets the canonical path
from the first commit even if a function inside still raises
`pay_kit: not implemented`.
]]

local M = {}

M._VERSION = '0.1.0'

-- Sub-module re-exports. `signer` and `kms` ship in P1; the rest
-- arrive in P2-P6 and the existing `require` calls in this file
-- update as each phase lands.
local config_mod     = require('resty.pay_kit.config')
local price_mod      = require('resty.pay_kit.price')
local registry_mod   = require('resty.pay_kit.registry')
local dispatcher_mod = require('resty.pay_kit.dispatcher')

M.signer   = require('resty.pay_kit.signer')
M.kms      = require('resty.pay_kit.kms')
M.errors   = require('resty.pay_kit.errors')
M.operator = require('resty.pay_kit.operator')

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
  require('resty.pay_kit.signer.demo').reset_for_tests()
end

return M
