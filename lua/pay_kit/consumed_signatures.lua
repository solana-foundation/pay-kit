--[[
Protocol-independent ledger of Solana transaction signatures that already
authorized a protected response.

MPP charge and x402 `exact` both claim here, so one on-chain payment
authorizes one request whichever protocol presents it: a transaction settled
through MPP cannot be presented again as an x402 payment on a gate that
shares the store, and vice versa. The key is the signature alone; a signature
commits to a message carrying a cluster-specific blockhash, so scoping by
network or protocol would only give each protocol its own namespace again.

The store must expose `put_if_absent(key, value)` (atomic, durable: the claim
must not expire while the transaction could still be presented) and
`delete(key)`. Both `pay_kit.protocols.mpp.store` and `pay_kit.store` do;
`pay_kit.store` keeps a non-numeric value with no expiry.
]]

local M = {}

M.PREFIX = 'solana:consumed-signature:'

function M.key(signature)
  return M.PREFIX .. signature
end

local Ledger = {}
Ledger.__index = Ledger

function M.new(store)
  if type(store) ~= 'table' or type(store.put_if_absent) ~= 'function' then
    error('pay_kit.consumed_signatures: store with put_if_absent is required')
  end
  return setmetatable({ store = store }, Ledger)
end

-- Keys under which MPP charge and x402 `exact` claimed signatures before
-- they shared this ledger.
local function legacy_keys(signature)
  return {
    'solana-charge:consumed:' .. signature,
    'x402-svm-exact:' .. signature .. ':consumed',
  }
end

-- `pay_kit.protocols.mpp.store` returns `(value, present)`, `pay_kit.store`
-- a truthy value.
local function store_has(store, key)
  local value, present = store:get(key)
  if present == nil then return value and true or false end
  return present == true
end

--- Whether `signature` was claimed under a pre-ledger MPP or x402 key, by a
--- replica running an older release or before this one upgraded. Read only
--- and fail closed: such a signature stays consumed, it is never migrated or
--- claimed again.
function Ledger:consumed_before_ledger(signature)
  if type(self.store.get) ~= 'function' then return false end
  for _, key in ipairs(legacy_keys(signature)) do
    if store_has(self.store, key) then return true end
  end
  return false
end

--- Atomically claim `signature`. `false` means an earlier presentation,
--- through any protocol, already claimed it.
function Ledger:claim(signature)
  if self:consumed_before_ledger(signature) then return false end
  return self.store:put_if_absent(M.key(signature), true) == true
end

--- Release a claim this caller made for a transaction that provably never
--- landed (for example a preflight rejection), so the payer may retry it.
function Ledger:release(signature)
  self.store:delete(M.key(signature))
end

--- The store both protocols must claim in under the PayKit umbrella: the
--- operator's shared `mpp.replay_store` when configured, else the
--- dispatcher's replay store. Resolving it in one place keeps MPP and x402
--- from each picking their own and splitting the ledger again.
function M.shared_store(config, fallback)
  local configured = config and config.mpp and config.mpp.replay_store
  return configured or fallback
end

return M
