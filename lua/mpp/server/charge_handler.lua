--[[
Server-side charge settlement orchestrator for Lua MPP.

This module owns the full settlement lifecycle so callers do not have to
hand-roll the broadcast or fetch-by-signature flow themselves. It mirrors
`ruby/lib/mpp/internal/handler.rb` and `php/src/Server/SolanaChargeHandler.php`
so the cross-language contract stays diff-able.

Settlement order, matching the Rust spine in `rust/src/server/charge.rs` and
the Greptile P1 fix landed on PR #85:

  Pull mode:
    1. decode credential payload `{type='transaction', transaction=<base64>}`
    2. parse the signed transaction (delegated to the verifier hook so the
       handler stays Solana-codec-free)
    3. network blockhash check (rejects mainnet keys against a Surfpool
       sandbox and vice versa, before any RPC traffic)
    4. cosign with the server fee payer if configured (delegated to hook)
    5. `simulate_transaction` with 3-attempt 400 ms backoff
    6. `send_raw_transaction`
    7. `store:put_if_absent(replay_key, true)` — CONSUME the signature
       BEFORE awaiting confirmation so a confirmation timeout cannot leave
       a double-pay window open
    8. `await_confirmation` polls `getSignatureStatuses` up to the
       configured attempts/delay; raises on `meta.err` or final timeout

  Push mode:
    1. decode credential payload `{type='signature', signature=<base58>}`
    2. fetch the on-chain transaction by signature with backoff
    3. verify the on-chain transaction shape (delegated to the verifier)
    4. `store:put_if_absent(replay_key, true)` — CONSUME the signature
       only after the on-chain shape is known to be correct
    5. return; there is nothing to await because the client already
       broadcast and waited

The handler is wire-compatible with the existing
`mpp.server.Server:verify_credential[_with_expected]` API. Callers can use
this handler either by passing `verify_payment = handler:as_callback()` to
`mpp.server.new`, or by driving the handler directly with a credential and
expected request.
]]

local json = require('mpp.util.json')
local network_check = require('mpp.server.network_check')

local M = {}

local DEFAULT_CONFIRMATION_ATTEMPTS = 40
local DEFAULT_CONFIRMATION_DELAY_SECONDS = 0.25
local DEFAULT_SIMULATION_MAX_ATTEMPTS = 3
local DEFAULT_SIMULATION_RETRY_DELAY_SECONDS = 0.4
local CONSUMED_PREFIX = 'solana-charge:consumed:'

local Handler = {}
Handler.__index = Handler

local function monotonic_seconds()
  -- Wall-clock seconds. `os.clock` measures CPU time consumed by the
  -- process, which advances much slower than real time when the LuaJIT VM
  -- yields inside an OpenResty / Nginx worker, so a CPU-time busy-wait
  -- sleep becomes too short. Prefer `socket.gettime` from luasocket when
  -- available; fall back to `os.time` (1s resolution) otherwise.
  local ok, socket = pcall(require, 'socket')
  if ok and socket and type(socket.gettime) == 'function' then
    return socket.gettime()
  end
  return os.time()
end

local function default_sleep(seconds)
  -- Busy-loop on wall-clock time. Production callers should inject their
  -- own sleep through the constructor (e.g. `require('socket').sleep` or
  -- the OpenResty `ngx.sleep`); the busy-wait is a last-resort default.
  local target = monotonic_seconds() + (seconds or 0)
  while monotonic_seconds() < target do end
end

local function verifier_error(message)
  error({ code = 'verification-error', message = message })
end

--- Construct a new charge handler.
--
-- @param config table
--   url and transport-bearing keys:
--     rpc                              required `mpp.solana.rpc.Rpc` instance
--   identity / settlement:
--     network                          server-configured network slug (default 'mainnet')
--     replay_store                     replay store with `put_if_absent(key, value)`
--     transaction_verifier             function(transaction_b64, request) -> ok|raises
--                                      called on push mode after fetching the on-chain tx,
--                                      and on pull mode after decoding the credential payload
--                                      so cosign/transfer-shape verification happens before
--                                      sending. Required.
--     pull_transaction_signer          optional function(transaction_b64) -> signed_b64
--                                      called between verification and simulate when the
--                                      server is the fee payer. Receives the verified base64
--                                      transaction and must return a signed base64 transaction.
--     pull_blockhash_extractor         optional function(transaction_b64) -> blockhash_b58
--                                      called once before cosign so the network-blockhash gate
--                                      can run without forcing the handler to depend on a
--                                      Solana codec.
--   timing:
--     confirmation_attempts            default 40
--     confirmation_delay_seconds       default 0.25
--     simulation_max_attempts          default 3
--     simulation_retry_delay_seconds   default 0.4
--     sleep                            function(seconds); defaults to a busy-loop
function M.new(config)
  if type(config) ~= 'table' then
    error('config table is required')
  end
  if type(config.rpc) ~= 'table' then
    error('rpc client is required')
  end
  if type(config.replay_store) ~= 'table' then
    error('replay_store is required')
  end
  if type(config.transaction_verifier) ~= 'function' then
    error('transaction_verifier function is required')
  end
  local instance = {
    rpc = config.rpc,
    network = config.network or 'mainnet',
    replay_store = config.replay_store,
    transaction_verifier = config.transaction_verifier,
    pull_transaction_signer = config.pull_transaction_signer,
    pull_blockhash_extractor = config.pull_blockhash_extractor,
    confirmation_attempts = config.confirmation_attempts or DEFAULT_CONFIRMATION_ATTEMPTS,
    confirmation_delay_seconds = config.confirmation_delay_seconds or DEFAULT_CONFIRMATION_DELAY_SECONDS,
    simulation_max_attempts = config.simulation_max_attempts or DEFAULT_SIMULATION_MAX_ATTEMPTS,
    simulation_retry_delay_seconds = config.simulation_retry_delay_seconds or DEFAULT_SIMULATION_RETRY_DELAY_SECONDS,
    sleep = config.sleep or default_sleep,
  }
  return setmetatable(instance, Handler)
end

local function consume_replay(self, signature)
  local key = CONSUMED_PREFIX .. signature
  local inserted = self.replay_store:put_if_absent(key, true)
  if not inserted then
    verifier_error('Transaction signature already consumed')
  end
end

--- Pull-mode settlement.
-- The credential payload carries a base64 signed transaction. The handler
-- verifies the transaction shape, optionally cosigns it, simulates with
-- retry, broadcasts, consumes the signature, then awaits confirmation.
function Handler:settle_pull(transaction_base64, request)
  if type(transaction_base64) ~= 'string' or transaction_base64 == '' then
    verifier_error('missing or empty transaction payload')
  end

  -- Stage 1: shape verification. Failing here means we never touch the RPC.
  local ok, verify_err = pcall(self.transaction_verifier, transaction_base64, request)
  if not ok then
    local message = type(verify_err) == 'table' and verify_err.message or tostring(verify_err)
    verifier_error(message)
  end

  -- Stage 2: network-blockhash gate. Done after shape verification because
  -- the verifier may parse the transaction and stash the blockhash.
  if type(self.pull_blockhash_extractor) == 'function' then
    local blockhash = self.pull_blockhash_extractor(transaction_base64)
    if type(blockhash) == 'string' and blockhash ~= '' then
      local err = network_check.check_network_blockhash(self.network, blockhash)
      if err then
        verifier_error(err.message)
      end
    end
  end

  -- Stage 3: optional cosign. Returns a possibly-replaced base64 transaction.
  local signed_base64 = transaction_base64
  if type(self.pull_transaction_signer) == 'function' then
    local signer_ok, signer_result = pcall(self.pull_transaction_signer, signed_base64)
    if not signer_ok then
      local message = type(signer_result) == 'table' and signer_result.message or tostring(signer_result)
      verifier_error('cosign failed: ' .. message)
    end
    if type(signer_result) ~= 'string' or signer_result == '' then
      verifier_error('cosign returned empty transaction')
    end
    signed_base64 = signer_result
  end

  -- Stage 4: simulate with bounded retries. A program-level error fails
  -- the request immediately (no retry, because the result is deterministic
  -- and the next attempt would just consume another RPC round-trip to get
  -- the same error). A transport-level error (pcall returned false) is
  -- retried up to `simulation_max_attempts` times.
  local simulation, simulate_err
  for attempt = 1, self.simulation_max_attempts do
    local sim_ok, sim_result = pcall(self.rpc.simulate_transaction, self.rpc, signed_base64)
    if sim_ok then
      simulation = sim_result
      simulate_err = nil
      break
    end
    simulate_err = sim_result
    if attempt < self.simulation_max_attempts then
      self.sleep(self.simulation_retry_delay_seconds)
    end
  end
  if simulate_err ~= nil then
    local message = type(simulate_err) == 'table' and simulate_err.message or tostring(simulate_err)
    verifier_error('Simulation failed: ' .. message)
  end
  if simulation == nil then
    verifier_error('Simulation failed: empty simulation result')
  end
  -- `mpp.util.json` decodes JSON `null` as `json.null` (a table sentinel),
  -- not Lua `nil`. Solana JSON-RPC returns `"err": null` on success, so
  -- comparing against both nil and the sentinel is required to recognize
  -- a successful simulation.
  if simulation.err ~= nil and simulation.err ~= json.null then
    verifier_error('Simulation failed: ' .. tostring(simulation.err))
  end

  -- Stage 5: broadcast. Any RPC failure here surfaces as a typed error and
  -- the signature is not yet consumed so the client can retry safely.
  local signature = self.rpc:send_raw_transaction(signed_base64)

  -- Stage 6: consume BEFORE await. This is the Greptile P1 ordering from PR
  -- #85. A confirmation timeout must not leave a window where the same
  -- credential can settle a second payment, because the on-chain tx may
  -- still finalize asynchronously.
  consume_replay(self, signature)

  -- Stage 7: confirmation polling. Errors here surface but the signature
  -- is already consumed, mirroring the Rust spine.
  self:await_confirmation(signature)

  return signature
end

--- Push-mode settlement.
-- The credential payload carries a base58 signature for a transaction the
-- client already broadcast and awaited. The handler must fetch the
-- on-chain transaction, verify its shape, then consume the signature.
function Handler:settle_push(signature, request)
  if type(signature) ~= 'string' or signature == '' then
    verifier_error('missing or empty signature payload')
  end

  local transaction_base64 = self:fetch_settled_transaction(signature)
  local ok, verify_err = pcall(self.transaction_verifier, transaction_base64, request)
  if not ok then
    local message = type(verify_err) == 'table' and verify_err.message or tostring(verify_err)
    verifier_error(message)
  end

  consume_replay(self, signature)
  return signature
end

--- Drive the right mode based on the credential payload type. Convenience
-- wrapper used by `as_callback()` so callers do not branch themselves.
function Handler:settle(payload, request)
  if type(payload) ~= 'table' then
    verifier_error('payload table is required')
  end
  if payload.type == 'transaction' then
    return self:settle_pull(payload.transaction, request)
  elseif payload.type == 'signature' then
    return self:settle_push(payload.signature, request)
  end
  verifier_error('unsupported payload type: ' .. tostring(payload.type))
end

--- Build a `verify_payment` callback compatible with `mpp.server.new`. The
-- callback consumes the replay store inside the handler, so the server's
-- own `put_if_absent` call in `_finalize_verification` is a no-op for the
-- same reference. `options.replay_key_prefix` controls the prefix the
-- server-level consume uses; the suffix is always the on-chain signature
-- so each settlement still gets a distinct server-level key.
function Handler:as_callback(options)
  options = options or {}
  local prefix = options.replay_key_prefix or 'solana-charge:server-noop:'
  local handler = self
  return function(context)
    local signature = handler:settle(context.payload, context.request)
    return {
      reference = signature,
      -- Build the server-level replay_key as prefix + signature so the
      -- key is unique per settlement. The handler already consumed the
      -- real signature in the replay store; this server-level key only
      -- needs to be distinct from earlier settlements.
      replay_key = prefix .. signature,
    }
  end
end

--- Poll `getSignatureStatuses` until the signature is confirmed/finalized
-- or the attempt budget is exhausted. Raises on `meta.err` or timeout.
function Handler:await_confirmation(signature)
  for attempt = 1, self.confirmation_attempts do
    local statuses = self.rpc:signature_statuses({ signature })
    local status = statuses and statuses[1]
    if type(status) == 'table' then
      -- Solana JSON-RPC returns `"err": null` on success; mpp.util.json
      -- decodes that as `json.null`, not Lua `nil`. Treat both as success.
      if status.err ~= nil and status.err ~= json.null then
        verifier_error('Transaction ' .. signature .. ' failed: ' .. tostring(status.err))
      end
      local confirmation_status = status.confirmationStatus
      if confirmation_status == 'confirmed' or confirmation_status == 'finalized' then
        return
      end
    end
    if attempt < self.confirmation_attempts then
      self.sleep(self.confirmation_delay_seconds)
    end
  end
  verifier_error('Timed out waiting for transaction ' .. signature)
end

--- Fetch a settled push-mode transaction by signature, retrying until the
-- RPC reports a non-nil envelope or the attempt budget is exhausted.
-- Returns the base64-encoded on-chain transaction string for the verifier.
function Handler:fetch_settled_transaction(signature)
  for attempt = 1, self.confirmation_attempts do
    local response = self.rpc:transaction(signature)
    -- The RPC client returns the raw decoded `result`. JSON null for a
    -- not-yet-observed transaction decodes as `json.null`, a table sentinel.
    -- Treat both the sentinel and a plain `nil` as "retry later" so the
    -- handler does not fall into the meta-check branch and fail with a
    -- spurious "missing metadata" error. Matches the Ruby reference's
    -- `response.nil?` branch in `ruby/lib/mpp/internal/handler.rb`.
    local observed = response ~= nil and response ~= json.null
    if observed and type(response) == 'table' then
      local meta = response.meta
      if type(meta) ~= 'table' then
        verifier_error('getTransaction response is missing transaction metadata')
      end
      -- Same json.null sentinel handling as simulate and await_confirmation.
      if meta.err ~= nil and meta.err ~= json.null then
        verifier_error('Transaction ' .. signature .. ' failed: ' .. tostring(meta.err))
      end
      local wire = response.transaction
      if type(wire) == 'table' and type(wire[1]) == 'string' and wire[1] ~= '' then
        return wire[1]
      end
      verifier_error('getTransaction response is missing base64 transaction')
    end
    if attempt < self.confirmation_attempts then
      self.sleep(self.confirmation_delay_seconds)
    end
  end
  verifier_error('Timed out fetching transaction ' .. signature)
end

M.Handler = Handler
M.CONSUMED_PREFIX = CONSUMED_PREFIX
M.DEFAULT_CONFIRMATION_ATTEMPTS = DEFAULT_CONFIRMATION_ATTEMPTS
M.DEFAULT_CONFIRMATION_DELAY_SECONDS = DEFAULT_CONFIRMATION_DELAY_SECONDS
M.DEFAULT_SIMULATION_MAX_ATTEMPTS = DEFAULT_SIMULATION_MAX_ATTEMPTS
M.DEFAULT_SIMULATION_RETRY_DELAY_SECONDS = DEFAULT_SIMULATION_RETRY_DELAY_SECONDS

return M
