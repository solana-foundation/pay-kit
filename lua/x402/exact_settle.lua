--[[
L8 broadcast-then-confirm-then-mark settlement helpers for x402 SVM-exact.

Extracted from `x402/bin/interop-server.lua` so the ordering — broadcast
the signed transaction, poll `getSignatureStatuses` until a definitive
outcome, only then `put_if_absent` the signature into the replay store —
can be unit-tested without standing up the full HTTP server.

The pattern mirrors the canonical reference in MPP `rust/src/server/charge.rs`
and the x402-sdk-implementation skill's `pr-readiness.md` L8 section:

  1. `send_raw_transaction` (broadcast).
  2. `await_signature_confirmation` (poll `getSignatureStatuses` until
     `confirmed` or `finalized`, bounded by an explicit RPC error result
     or the per-blockhash retry budget).
  3. `consume_signature` (`put_if_absent` on
     `x402-svm-exact:consumed:<base58_signature>`). A `false` return is the
     canonical `signature_consumed` rejection — never a 200.

There is NO release-on-failure path here, by design. A crash or RPC failure
before step 3 simply never inserts the key, and Solana's per-signature
replay protection prevents the same signed transaction from landing twice
within its blockhash window. Two concurrent settlement attempts on the same
signature collapse to one on-chain effect; the second observes the
already-consumed signature and reports it.
]]

local M = {}

M.REPLAY_KEY_PREFIX = 'x402-svm-exact:consumed:'

-- Default polling budget. Mirrors MPP charge_handler defaults (~30s of
-- polling) but kept local so the interop server can override via config
-- and the unit tests can drive zero-delay loops.
M.DEFAULT_CONFIRMATION_ATTEMPTS = 30
M.DEFAULT_CONFIRMATION_DELAY_SECONDS = 1

--- In-memory replay store. Only `put_if_absent` is part of the L8 contract;
--- the rest of the surface is convenience for tests and shared-process use.
local MemoryStore = {}
MemoryStore.__index = MemoryStore

function M.new_memory_store()
  return setmetatable({ data = {} }, MemoryStore)
end

function MemoryStore:put_if_absent(key, value)
  if self.data[key] ~= nil then
    return false
  end
  self.data[key] = value == nil and true or value
  return true
end

function MemoryStore:get(key)
  return self.data[key]
end

M.MemoryStore = MemoryStore

--- Raise a canonical `signature_consumed` error. The interop HTTP response
--- builder inspects `err.code` so a duplicate settlement never gets echoed
--- back as a fresh 200 PAYMENT-RESPONSE. Matches the canonical code in
--- `mpp/protocol/core/error_codes.lua`.
local function signature_consumed_error(signature)
  error({
    code = 'signature_consumed',
    message = 'Transaction signature already consumed: ' .. tostring(signature),
  })
end

--- Poll `getSignatureStatuses` until the signature is confirmed/finalized or
--- the attempt budget is exhausted. Raises on `meta.err` (explicit on-chain
--- failure) or timeout (blockhash window expiry surrogate). The polling loop
--- is bounded by either:
---   * an explicit RPC error result (raises), or
---   * `confirmation_attempts` ticks (each `confirmation_delay_seconds`
---     long), which approximates the per-blockhash validity window.
---
--- Returns the matching status table on success so callers can record it.
function M.await_signature_confirmation(opts)
  local signature = opts.signature
  local rpc_call = opts.rpc_call -- function(method, params) -> result
  local attempts = opts.confirmation_attempts or M.DEFAULT_CONFIRMATION_ATTEMPTS
  local delay = opts.confirmation_delay_seconds or M.DEFAULT_CONFIRMATION_DELAY_SECONDS
  local sleep = opts.sleep or function() end
  if type(signature) ~= 'string' or signature == '' then
    error('await_signature_confirmation: signature must be a non-empty string')
  end
  if type(rpc_call) ~= 'function' then
    error('await_signature_confirmation: rpc_call function is required')
  end

  for attempt = 1, attempts do
    local result = rpc_call('getSignatureStatuses', { { signature } })
    local statuses = result and result.value
    local status = statuses and statuses[1]
    if type(status) == 'table' then
      -- Solana returns `"err": null` on success. dkjson decodes that as
      -- Lua `nil`, so a non-nil err is a definitive on-chain failure —
      -- short-circuit the polling loop and surface the error.
      local err = status.err
      if err ~= nil then
        error('transaction ' .. signature .. ' failed: ' .. tostring(err))
      end
      local confirmation_status = status.confirmationStatus
      if confirmation_status == 'confirmed' or confirmation_status == 'finalized' then
        return status
      end
    end
    if attempt < attempts then
      sleep(delay)
    end
  end
  error('timed out waiting for transaction ' .. signature)
end

--- Mark the signature as consumed in the replay store. Returns the canonical
--- key on success; raises a `signature_consumed` table-error if the store
--- already records this signature.
function M.consume_signature(replay_store, signature)
  if type(signature) ~= 'string' or signature == '' then
    error('consume_signature: signature must be a non-empty string')
  end
  if replay_store == nil or type(replay_store.put_if_absent) ~= 'function' then
    error('consume_signature: replay_store with put_if_absent is required')
  end
  local key = M.REPLAY_KEY_PREFIX .. signature
  local inserted = replay_store:put_if_absent(key, true)
  if not inserted then
    signature_consumed_error(signature)
  end
  return key
end

--- L8 settlement entrypoint: broadcast → confirm → consume.
--- Callers supply a `broadcast` thunk (returns the base58 signature),
--- an `rpc_call(method, params)` for `getSignatureStatuses` polling, and
--- the `replay_store`. On success returns the signature; on duplicate
--- raises `{ code = 'signature_consumed', ... }`; on broadcast or
--- confirmation failure raises the underlying error WITHOUT touching the
--- replay store (no release path — the on-chain signature is the global
--- uniqueness primitive).
function M.broadcast_confirm_consume(opts)
  if type(opts) ~= 'table' then
    error('broadcast_confirm_consume: opts table is required')
  end
  if type(opts.broadcast) ~= 'function' then
    error('broadcast_confirm_consume: broadcast function is required')
  end
  if type(opts.rpc_call) ~= 'function' then
    error('broadcast_confirm_consume: rpc_call function is required')
  end
  if opts.replay_store == nil then
    error('broadcast_confirm_consume: replay_store is required')
  end

  -- Step 1: broadcast. Any failure here surfaces before the replay store
  -- is touched, so a retry can safely re-broadcast (Solana itself rejects
  -- a true duplicate inside the blockhash window).
  local signature = opts.broadcast()
  if type(signature) ~= 'string' or signature == '' then
    error('broadcast returned an empty signature')
  end

  -- Step 2: await confirmation. The polling loop is bounded — an explicit
  -- RPC error result short-circuits, and the attempt budget approximates
  -- the blockhash window. Failures raise; the replay key is NOT inserted,
  -- so a retry that lands on-chain can still consume the slot.
  M.await_signature_confirmation({
    signature = signature,
    rpc_call = opts.rpc_call,
    confirmation_attempts = opts.confirmation_attempts,
    confirmation_delay_seconds = opts.confirmation_delay_seconds,
    sleep = opts.sleep,
  })

  -- Step 3: consume. put_if_absent on the confirmed signature. A `false`
  -- return is the canonical `signature_consumed` rejection — surfaced as
  -- a structured table-error so the HTTP layer does NOT echo a fresh 200.
  M.consume_signature(opts.replay_store, signature)

  return signature
end

return M
