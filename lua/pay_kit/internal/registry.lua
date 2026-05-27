--[[
Gate registry.

Module-level singleton holding the registered gates by name. Static
gates are stored as built `Gate` objects; dynamic gates are stored as
functions called at access time with the parsed request.

Frozen after `pay_kit.configure()` returns - subsequent `pay_kit.gate()`
calls return `(nil, gate_registration_frozen)`. This matches the
design's "Immutable after configure" rule and prevents inconsistent
behaviour from late registrations against a partially-warmed worker.

Test suites unfreeze via `_unfreeze_for_tests()`.
]]

local gate_mod = require('pay_kit.internal.gate')
local errors   = require('pay_kit.errors')

local M = {}

local static_gates = {}
local dynamic_gates = {}
local frozen = false

-- Defaults for gate.build come from the active config. Lazy-resolved
-- to avoid cyclic require with `pay_kit.config`.
local function build_defaults()
  local config_mod = require('pay_kit.internal.config')
  local cfg = config_mod.current()
  if not cfg then return {} end
  return {
    pay_to = cfg:effective_recipient(),
    accept = cfg.accept,
  }
end

-- Register a gate. `opts` is either a table (static gate) OR a function
-- (dynamic gate) called with the per-request context. Returns
-- (true, nil) on success.
function M.register(name, opts_or_fn)
  if frozen then return nil, errors.GATE_REGISTRATION_FROZEN end
  if type(name) ~= 'string' or name == '' then
    return nil, 'pay_kit: gate name must be a non-empty string'
  end
  if static_gates[name] or dynamic_gates[name] then
    return nil, 'pay_kit: duplicate gate ' .. name
  end

  if type(opts_or_fn) == 'function' then
    -- Dynamic gate: store the builder closure. Resolution happens
    -- at request time via `materialize(name, request)`.
    dynamic_gates[name] = opts_or_fn
    return true
  end

  if type(opts_or_fn) ~= 'table' then
    return nil, 'pay_kit: gate ' .. name ..
      ': opts must be a table or a function'
  end

  local opts = {}
  for k, v in pairs(opts_or_fn) do opts[k] = v end
  opts.name = name
  local gate, err = gate_mod.build(opts, build_defaults())
  if not gate then return nil, err end
  static_gates[name] = gate
  return true
end

-- Resolve a registered gate to a static Gate, materialising the
-- dynamic builder against `request` when needed. Returns
-- (gate, nil) or (nil, err).
function M.materialize(name, request)
  if static_gates[name] then return static_gates[name] end
  local builder = dynamic_gates[name]
  if not builder then return nil, errors.GATE_NOT_FOUND end
  local ok, opts_or_err = pcall(builder, request)
  if not ok then
    return nil, 'pay_kit: dynamic gate ' .. name .. ' raised: ' ..
      tostring(opts_or_err)
  end
  if type(opts_or_err) ~= 'table' then
    return nil, 'pay_kit: dynamic gate ' .. name ..
      ' must return a table'
  end
  local opts = {}
  for k, v in pairs(opts_or_err) do opts[k] = v end
  opts.name = name
  return gate_mod.build(opts, build_defaults())
end

-- Build an inline gate from a fresh option table. Used by
-- `require_payment(table)` when the caller bypasses the registry.
function M.build_inline(opts)
  if type(opts) ~= 'table' then
    return nil, 'pay_kit: inline gate must be a table'
  end
  local clone = {}
  for k, v in pairs(opts) do clone[k] = v end
  clone.name = clone.name or '_inline'
  return gate_mod.build(clone, build_defaults())
end

function M.has(name)
  return static_gates[name] ~= nil or dynamic_gates[name] ~= nil
end

function M.freeze() frozen = true end

function M._unfreeze_for_tests()
  frozen = false
  static_gates = {}
  dynamic_gates = {}
end

return M
