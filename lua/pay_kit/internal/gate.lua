--[[
Gate value object + builder.

A gate is the unit. Each gate carries:
- name (symbol), amount (Price), pay_to (string),
- fees ({Fee,...}), accept ({"x402","mpp"}), description (string).

Rules (validated at `Gate.build`, return `(nil, err)` on violation):
1. Fixed amounts only.
2. `pay_to` is optional and defaults to `operator.recipient`.
3. All amounts share one denomination.
4. `sum(fee_within values) <= amount`.
5. x402 is automatically disabled when fees are present (the resolver
   strips "x402" from `accept` silently; explicit `accept = {"x402"}`
   on a gate with fees returns the canonical error string).
6. Stablecoin preference is gate- or config-level, not per-fee.

Mirrors the Ruby gem's `PayKit::Gate` (ruby/lib/pay_kit/gate.rb).
]]

local fee_mod = require('pay_kit.internal.fee')
local errors  = require('pay_kit.errors')

local M = {}
local Gate = {}
Gate.__index = Gate

local function is_price(p)
  if type(p) ~= 'table' then return false end
  return type(p.units) == 'function' and type(p.denomination) == 'function'
end

-- Resolve which schemes the gate accepts.
local function resolve_accept(name, requested_accept, accept_default, has_fees)
  local list = requested_accept or accept_default
  if type(list) ~= 'table' or #list == 0 then
    return nil, 'pay_kit: gate ' .. tostring(name) .. ': accept resolved to empty list'
  end
  -- Dedup while preserving order.
  local seen, out = {}, {}
  for i = 1, #list do
    local s = list[i]
    if type(s) ~= 'string' then
      return nil, 'pay_kit: gate ' .. tostring(name) ..
        ': accept[' .. i .. '] must be a string'
    end
    if not seen[s] then seen[s] = true; out[#out + 1] = s end
  end
  if has_fees then
    -- Strip x402 silently UNLESS caller explicitly asked for it.
    local explicit_x402 = false
    if requested_accept then
      for i = 1, #requested_accept do
        if requested_accept[i] == 'x402' then explicit_x402 = true; break end
      end
    end
    if explicit_x402 then return nil, errors.X402_INCOMPATIBLE_WITH_FEES end
    local pruned = {}
    for i = 1, #out do
      if out[i] ~= 'x402' then pruned[#pruned + 1] = out[i] end
    end
    if #pruned == 0 then
      return nil, 'pay_kit: gate ' .. tostring(name) ..
        ': fees present and x402 auto-disabled; add "mpp" to accept'
    end
    out = pruned
  end
  return out
end

local function validate_denominations(name, amount, fees)
  local denoms = { [amount:denomination()] = true }
  for i = 1, #fees do
    denoms[fees[i]:price():denomination()] = true
  end
  local count = 0
  for _ in pairs(denoms) do count = count + 1 end
  if count > 1 then
    return nil, 'pay_kit: gate ' .. tostring(name) ..
      ': all amounts must share one denomination'
  end
  return true
end

local function validate_within_sum(name, amount, fees)
  local sum = 0
  for i = 1, #fees do
    if fees[i]:within() then sum = sum + fees[i]:units() end
  end
  if sum > amount:units() then
    return nil, 'pay_kit: gate ' .. tostring(name) ..
      ': sum(fee_within) exceeds amount'
  end
  return true
end

local function validate_fee_recipients(name, pay_to, fees)
  local seen = {}
  for i = 1, #fees do
    local r = fees[i]:recipient()
    if r == pay_to then
      return nil, 'pay_kit: gate ' .. tostring(name) ..
        ': fee recipient duplicates pay_to (fold the fee into amount instead)'
    end
    if seen[r] then
      return nil, 'pay_kit: gate ' .. tostring(name) ..
        ': duplicate fee recipient ' .. tostring(r)
    end
    seen[r] = true
  end
  return true
end

-- Internal: total = amount + sum(fee_on_top).
local function total_units(amount, fees)
  local sum = amount:units()
  for i = 1, #fees do
    if fees[i]:on_top() then sum = sum + fees[i]:units() end
  end
  return sum
end

-- Build a Gate. `defaults` is `{ pay_to, accept }` from the active
-- pay_kit.config so the caller does not have to thread config through
-- every gate() registration. Returns (gate, nil) or (nil, err).
function M.build(opts, defaults)
  opts = opts or {}
  defaults = defaults or {}

  local name = opts.name
  if type(name) ~= 'string' or name == '' then
    return nil, 'pay_kit: gate name must be a non-empty string'
  end

  local amount = opts.amount
  if not is_price(amount) then
    return nil, 'pay_kit: gate ' .. name ..
      ': amount must be a Price (use pay_kit.usd)'
  end

  local resolved_pay_to = opts.pay_to or defaults.pay_to
  if type(resolved_pay_to) ~= 'string' or resolved_pay_to == '' then
    return nil, 'pay_kit: gate ' .. name ..
      ': pay_to is required (set on gate or via operator.recipient)'
  end

  local fees, fee_err = fee_mod.from_hashes(opts.fee_within, opts.fee_on_top)
  if not fees then return nil, fee_err end

  local _, denom_err = validate_denominations(name, amount, fees)
  if denom_err then return nil, denom_err end

  local _, recip_err = validate_fee_recipients(name, resolved_pay_to, fees)
  if recip_err then return nil, recip_err end

  local _, sum_err = validate_within_sum(name, amount, fees)
  if sum_err then return nil, sum_err end

  local accept, accept_err = resolve_accept(name, opts.accept, defaults.accept, #fees > 0)
  if not accept then return nil, accept_err end

  return setmetatable({
    _name        = name,
    _amount      = amount,
    _pay_to      = resolved_pay_to,
    _fees        = fees,
    _accept      = accept,
    _description = opts.description,
    _external_id = opts.external_id,
  }, Gate)
end

function Gate:name()        return self._name end
function Gate:amount()      return self._amount end
function Gate:pay_to()      return self._pay_to end
function Gate:fees()        return self._fees end
function Gate:has_fees()    return #self._fees > 0 end
function Gate:accept()      return self._accept end
function Gate:description() return self._description end
function Gate:external_id() return self._external_id end

-- The total amount the customer actually pays: amount + sum(on_top).
function Gate:total_units()
  return total_units(self._amount, self._fees)
end

function Gate:x402_accepted()
  for i = 1, #self._accept do
    if self._accept[i] == 'x402' then return true end
  end
  return false
end

function Gate:mpp_accepted()
  for i = 1, #self._accept do
    if self._accept[i] == 'mpp' then return true end
  end
  return false
end

return M
