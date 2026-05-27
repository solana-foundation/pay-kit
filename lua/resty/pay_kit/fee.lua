--[[
Fee value object.

Two kinds, matching the design's rules-for-amount-and-fees section:

- "within": taken OUT of the amount. The pay_to recipient nets less.
- "on_top": added ON TOP of the amount. The customer pays more.

Both shapes are represented as `Fee.new(recipient, price, kind)`. The
Gate builder constructs them from the `fee_within` / `fee_on_top`
option tables (`{ [recipient] = price, ... }`).

Frozen at construction. Validation (`recipient` non-empty string,
`price` is a Price object, `kind` is one of the two literals) raises
so a bad fee dies at the boot-time `gate()` call, not at request time.
]]

local M = {}
local Fee = {}
Fee.__index = Fee

local KIND_WITHIN  = 'within'
local KIND_ON_TOP  = 'on_top'

M.KIND_WITHIN = KIND_WITHIN
M.KIND_ON_TOP = KIND_ON_TOP

local function is_price(p)
  if type(p) ~= 'table' then return false end
  return type(p.units) == 'function' and type(p.denomination) == 'function'
end

-- Build a Fee. Returns (fee, nil) or (nil, err).
function M.new(recipient, price, kind)
  if type(recipient) ~= 'string' or recipient == '' then
    return nil, 'pay_kit: fee.recipient must be a non-empty string'
  end
  if not is_price(price) then
    return nil, 'pay_kit: fee.price must be a Price object (use pay_kit.usd)'
  end
  if kind ~= KIND_WITHIN and kind ~= KIND_ON_TOP then
    return nil, 'pay_kit: fee.kind must be "within" or "on_top"'
  end
  return setmetatable({
    _recipient = recipient,
    _price     = price,
    _kind      = kind,
  }, Fee)
end

function Fee:recipient() return self._recipient end
function Fee:price()     return self._price end
function Fee:kind()      return self._kind end
function Fee:within()    return self._kind == KIND_WITHIN end
function Fee:on_top()    return self._kind == KIND_ON_TOP end
function Fee:units()     return self._price:units() end

-- Build the ordered list of Fee objects from the `fee_within` and
-- `fee_on_top` option tables. The combined ordering is "all within
-- first, then all on_top" so verifiers see a predictable iteration.
-- Hash tables in Lua have no order guarantees - callers wanting
-- deterministic order can pass an array of `{recipient, price}`
-- pairs instead (treated as ordered).
function M.from_hashes(fee_within, fee_on_top)
  local list = {}
  local function ingest(hash, kind)
    if hash == nil then return end
    if type(hash) ~= 'table' then
      return nil, 'pay_kit: fee_' .. kind .. ' must be a table'
    end
    if #hash > 0 then
      for i = 1, #hash do
        local entry = hash[i]
        if type(entry) ~= 'table' or entry[1] == nil or entry[2] == nil then
          return nil, 'pay_kit: fee_' .. kind .. '[' .. i ..
            '] must be { recipient, price }'
        end
        local f, err = M.new(entry[1], entry[2], kind)
        if not f then return nil, err end
        list[#list + 1] = f
      end
    else
      -- Hash form: deterministic-enough via paired iteration; sort
      -- by recipient for stability across Lua 5.1 vs LuaJIT iteration order.
      local pairs_list = {}
      for recipient, price in pairs(hash) do
        pairs_list[#pairs_list + 1] = {recipient, price}
      end
      table.sort(pairs_list, function(a, b) return a[1] < b[1] end)
      for i = 1, #pairs_list do
        local f, err = M.new(pairs_list[i][1], pairs_list[i][2], kind)
        if not f then return nil, err end
        list[#list + 1] = f
      end
    end
  end
  local err = ingest(fee_within, KIND_WITHIN)
  if err then return nil, err end
  err = ingest(fee_on_top, KIND_ON_TOP)
  if err then return nil, err end
  return list
end

return M
