--[[
Price helper.

`pay_kit.usd("0.10", "USDC")` parses a decimal-dollar string into an
integer micro-unit count plus an ordered preference list of settlement
stablecoins. The integer is the canonical wire form: USDC / USDT / EURC
all use 6-decimal smallest-units, so "$0.10" -> 100000.

LuaJIT 2.1 holds 64-bit integers as `int64_t` cdata via FFI, so we
never need a bignum library for stablecoin amounts. Plain Lua 5.1
without FFI handles values up to 2^53 (well above any realistic
charge).

Floats are rejected at the call site: `pay_kit.usd(0.10)` returns
`(nil, "pay_kit: usd() expects a string amount, not a number")`. Pass
a string literal or a value already produced by another `usd()` call.

Future fiat denoms (`pay_kit.eur(...)`, `pay_kit.gbp(...)`) slot into
the same shape; v1 ships USD only.
]]

local M = {}

local DEFAULT_DECIMALS = 6   -- USDC, USDT, EURC, PYUSD all use 6 decimals.

local Price = {}
Price.__index = Price

function Price:units()
  return self._units
end

function Price:amount_string()
  return self._amount
end

function Price:denomination()
  return self._denom
end

function Price:settlements()
  -- Defensive shallow copy so callers cannot mutate the registry's
  -- price-table preference order.
  local out = {}
  for i = 1, #self._settlements do out[i] = self._settlements[i] end
  return out
end

function Price:primary_coin()
  return self._settlements[1]
end

-- Parse "0.10" (string) into the 6-decimal smallest-units integer.
-- Returns (units, nil) or (nil, err). Strict: rejects floats, empty
-- strings, multiple dots, non-digit characters, negative values.
local function parse_decimal_units(amount_str, decimals)
  if type(amount_str) ~= 'string' then
    return nil, 'pay_kit: usd() expects a string amount, not a ' .. type(amount_str)
  end
  if amount_str == '' then
    return nil, 'pay_kit: usd() empty amount'
  end
  if amount_str:sub(1, 1) == '-' then
    return nil, 'pay_kit: usd() amounts must be non-negative'
  end
  local whole, fraction
  local dot = amount_str:find('.', 1, true)
  if not dot then
    whole, fraction = amount_str, ''
  else
    whole = amount_str:sub(1, dot - 1)
    fraction = amount_str:sub(dot + 1)
    if fraction:find('.', 1, true) then
      return nil, 'pay_kit: usd() multiple decimal points'
    end
  end
  if whole == '' then whole = '0' end
  if not whole:match('^%d+$') then
    return nil, 'pay_kit: usd() invalid whole part: ' .. tostring(whole)
  end
  if fraction ~= '' and not fraction:match('^%d+$') then
    return nil, 'pay_kit: usd() invalid fractional part: ' .. tostring(fraction)
  end
  if #fraction > decimals then
    return nil, 'pay_kit: usd() amount has more than ' .. decimals ..
      ' fractional digits (got ' .. #fraction .. ')'
  end
  fraction = fraction .. string.rep('0', decimals - #fraction)
  local whole_units = tonumber(whole) * (10 ^ decimals)
  local frac_units = tonumber(fraction) or 0
  return whole_units + frac_units
end

local function build_settlement_list(coins, fallback)
  if #coins == 0 then
    return fallback or {'USDC'}
  end
  local seen, out = {}, {}
  for i = 1, #coins do
    local c = coins[i]
    if type(c) ~= 'string' or c == '' then
      return nil, 'pay_kit: usd() stablecoin must be a non-empty string'
    end
    if not seen[c] then
      seen[c] = true
      out[#out + 1] = c
    end
  end
  return out
end

-- Build a USD-denominated price.
--
-- Calling forms:
--   pay_kit.usd("0.10")                 -- uses configured default stablecoins
--   pay_kit.usd("0.10", "USDC")         -- single coin
--   pay_kit.usd("0.10", "USDC", "USDT") -- preference order
function M.usd(amount_str, ...)
  local units, err = parse_decimal_units(amount_str, DEFAULT_DECIMALS)
  if err then return nil, err end
  local coins = {...}
  local fallback
  if #coins == 0 then
    -- Lazy-require to avoid cyclic deps with config.
    local ok, config = pcall(require, 'pay_kit.internal.config')
    if ok and config.current then
      local cfg = config.current()
      if cfg and cfg.stablecoins then fallback = cfg.stablecoins end
    end
  end
  local settlements, lerr = build_settlement_list(coins, fallback)
  if lerr then return nil, lerr end
  return setmetatable({
    _denom       = 'USD',
    _amount      = amount_str,
    _units       = units,
    _settlements = settlements,
  }, Price)
end

-- Re-export the metatable so callers can `type-check` a price via
-- `getmetatable(p) == pay_kit.price.metatable()`.
function M.metatable()
  return Price
end

return M
