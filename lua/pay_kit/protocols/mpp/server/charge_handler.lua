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
    5. derive the final signature locally and CLAIM it in the
       consumed-signature ledger before anything is sent, so the transfer
       is recorded whatever happens after it leaves
    6. `simulate_transaction` with 3-attempt 400 ms backoff (a rejection
       releases the claim: nothing was sent)
    7. `send_raw_transaction`. Only a preflight rejection proves the node
       did not forward it (release + fail); any other send error leaves the
       outcome unknown, so the charge is kept PENDING under the local
       signature and the client is told settlement is in progress
    8. `await_confirmation` polls `getSignatureStatuses` up to the
       configured attempts/delay; raises on `meta.err`. A status that never
       surfaces keeps the charge pending: only an explicit on-chain outcome
       resolves it

  A later presentation of the same transaction under the same challenge
  while it is pending reconciles it against its on-chain status instead of
  paying again. The pending record is bound to that challenge: the same
  bytes under any other challenge are a replay, never reconciled.

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

local json = require('pay_kit.util.json')
local network_check = require('pay_kit.solana.network_check')
local error_codes = require('pay_kit.protocol.core.error_codes')
local consumed_signatures = require('pay_kit.consumed_signatures')

local M = {}

local DEFAULT_CONFIRMATION_ATTEMPTS = 40
local DEFAULT_CONFIRMATION_DELAY_SECONDS = 0.25
local DEFAULT_SIMULATION_MAX_ATTEMPTS = 3
local DEFAULT_SIMULATION_RETRY_DELAY_SECONDS = 0.4
-- JSON-RPC code of a sendTransaction preflight (simulation) failure.
local SEND_PREFLIGHT_FAILURE = -32002
-- A charge whose transaction may have been broadcast but whose outcome is
-- unknown. Written next to the ledger claim; resolved only by reconciliation.
-- Namespaced to this SDK: another SDK's pending record under a look-alike
-- key must never be reconciled (and granted) here, nor ours there.
local PENDING_PREFIX = 'pay-kit:lua:charge-pending:'
-- Single-winner token for the one request a reconciled transaction grants.
local RECONCILED_PREFIX = 'solana-charge:reconciled:'
-- Oldest landed transaction push mode accepts: an hour inside the durable
-- claim retention, so a claim never expires while its payment is acceptable.
local MAX_PUSH_AGE_SECONDS = require('pay_kit.store').DURABLE_RETENTION_SECONDS - 3600
-- The ledger shared with x402 `exact`, so a payment settled through either
-- protocol cannot authorize a second request through the other.
local CONSUMED_PREFIX = consumed_signatures.PREFIX

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

-- All settlement-side rejections funnel through `verifier_error` so the
-- response builder can map each to a canonical L6 error code. The default
-- code is PAYMENT_INVALID (the transaction's on-chain shape failed one of
-- the verifier's structural checks); callers pass an explicit override
-- for the network-mismatch and signature-consumed paths so the response
-- carries the right machine-readable code.
local function verifier_error(message, code)
  error({ code = code or error_codes.PAYMENT_INVALID, message = message })
end

--- Construct a new charge handler.
--
-- @param config table
--   url and transport-bearing keys:
--     rpc                              required `pay_kit.solana.rpc.Rpc` instance
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
--     pull_signature_extractor         optional function(transaction_b64) -> signature_b58
--                                      derives the final (fee-payer) signature of the
--                                      signed transaction before broadcast. Defaults to the
--                                      bundled Solana codec.
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
-- Every required signature must verify against the message. A forged one
-- would otherwise name the charge: the node refuses it without a preflight
-- result, it is kept as possibly sent, and a retry would reconcile on the
-- status of whatever landed transaction owns that signature.
-- This runs on the transaction as sent, after any co-sign, so no slot is
-- exempt; the charge verifier runs the same check before co-signing with
-- only the server's fee-payer slot exempt.
local function default_signature_verifier(signed_base64)
  local tx = require('pay_kit.solana.transaction').from_base64(signed_base64)
  local ok, reason = require('pay_kit.solana.signatures').check(tx, {})
  if not ok then error(reason) end
end

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
    -- Audit #5: push mode (type=signature credentials) is opt-in and default
    -- OFF. Spec §13.5 accepts that push binds a confirmed tx to a challenge by
    -- shape only ("first accepted presentation wins"); a server that does not
    -- need push should not carry that trade-off. Mirrors the Rust spine's
    -- default-off posture.
    accept_push_mode = config.accept_push_mode or false,
    transaction_verifier = config.transaction_verifier,
    pull_transaction_signer = config.pull_transaction_signer,
    pull_blockhash_extractor = config.pull_blockhash_extractor,
    pull_signature_extractor = config.pull_signature_extractor,
    -- Verifies every signature on the signed transaction before its
    -- signature is claimed or it is sent. Defaults to local Ed25519
    -- verification; a replacement must be at least as strict.
    pull_signature_verifier = config.pull_signature_verifier or default_signature_verifier,
    confirmation_attempts = config.confirmation_attempts or DEFAULT_CONFIRMATION_ATTEMPTS,
    confirmation_delay_seconds = config.confirmation_delay_seconds or DEFAULT_CONFIRMATION_DELAY_SECONDS,
    simulation_max_attempts = config.simulation_max_attempts or DEFAULT_SIMULATION_MAX_ATTEMPTS,
    simulation_retry_delay_seconds = config.simulation_retry_delay_seconds or DEFAULT_SIMULATION_RETRY_DELAY_SECONDS,
    sleep = config.sleep or default_sleep,
  }
  return setmetatable(instance, Handler)
end

local function consume_replay(self, signature)
  if not consumed_signatures.new(self.replay_store):claim(signature) then
    verifier_error('Transaction signature already consumed', error_codes.SIGNATURE_CONSUMED)
  end
end

-- `get` is `(value, present)` on the MPP store and a boolean on
-- `pay_kit.store`; read presence from either.
local function store_has(store, key)
  local value, present = store:get(key)
  if present == nil then return value and true or false end
  return present == true
end

local function default_signature_extractor(transaction_base64)
  local tx = require('pay_kit.solana.transaction').from_base64(transaction_base64)
  if #tx.signatures == 0 then
    error('transaction carries no signatures')
  end
  return require('pay_kit.solana.base58').encode(tx.signatures[1])
end

-- Only a preflight rejection proves the node did not forward the
-- transaction; every other send failure leaves the outcome unknown.
local function is_preflight_rejection(err)
  return type(err) == 'table' and err.code == 'rpc-error'
    and err.rpc_code == SEND_PREFLIGHT_FAILURE
end

local function error_message(err)
  return type(err) == 'table' and tostring(err.message) or tostring(err)
end

-- The pending charge `challenge_id` claimed (and may have broadcast) under
-- `signature`. Only that challenge may reconcile it: anyone can copy a landed
-- transaction's bytes, and presenting them under their own same-terms
-- challenge must not win the grant the payer's request is still confirming.
local function binding_key(signature, challenge_id)
  return PENDING_PREFIX .. signature .. ':' .. challenge_id
end

-- The charge stays pending: the claim is kept, because the transaction may
-- land, so the client must not be released to pay again.
local function settlement_pending(signature, detail)
  verifier_error('Settlement of transaction ' .. signature .. ' is in progress (' ..
    detail .. '); retry the same credential, do not pay again',
    error_codes.SETTLEMENT_IN_PROGRESS)
end

-- Bind the pending charge to its challenge with the claim, before anything is
-- sent. Written only after an ambiguous send, a store failure would leave a
-- claim with no record, and every retry would refuse a payment that may have
-- landed as consumed.
local function record_pending(self, signature, challenge_id)
  self.replay_store:put_if_absent(binding_key(signature, challenge_id), true)
end

-- Nothing was sent (or it provably never landed): drop the pending record
-- and give the claim back, unless a grant already took it.
--
-- A concurrent retry of the same credential may have reconciled the
-- transaction (it landed) and been granted while this request was still
-- simulating or sending. Releasing the claim then would let the same
-- signature be presented again (a push credential, an x402 payment) and
-- granted twice. So the release is made conditional on the grant token:
-- abandon takes that single-winner token first, and only while it holds it,
-- so no grant can happen meanwhile, does it drop the binding and release the
-- claim. A grant that took the token first means the payment authorized a
-- request: the claim stays. A retry that read the binding before it was
-- dropped re-checks it once it holds the token (see `grant`), so it cannot
-- be granted after the claim was given back.
local function abandon(self, ledger, signature, challenge_id)
  local fence = RECONCILED_PREFIX .. signature
  if not self.replay_store:put_if_absent(fence, true) then
    return
  end
  self.replay_store:delete(binding_key(signature, challenge_id))
  ledger:release(signature)
  self.replay_store:delete(fence)
end

-- One request per payment: every grant, inline or reconciled, takes this
-- single-winner token, so a retry reconciling the pending record cannot be
-- granted alongside the request that is still confirming it. The binding is
-- re-checked while the token is held: an `abandon` that ran since it was
-- read has given the claim back, so this payment can no longer be granted
-- under it.
local function grant(self, signature, challenge_id)
  local token = RECONCILED_PREFIX .. signature
  if not self.replay_store:put_if_absent(token, true) then
    verifier_error('Transaction signature already consumed', error_codes.SIGNATURE_CONSUMED)
  end
  if not store_has(self.replay_store, binding_key(signature, challenge_id)) then
    self.replay_store:delete(token)
    verifier_error('Transaction signature already consumed', error_codes.SIGNATURE_CONSUMED)
  end
  return signature
end

--- Resolve the pending charge `challenge_id` left under `signature` from its
--- on-chain status. Any other claim (a payment already settled on the shared
--- ledger, or another challenge's pending charge) is a replay. Only an
--- explicit on-chain outcome resolves it; anything else leaves it pending.
function Handler:reconcile_pending(signature, challenge_id)
  if type(challenge_id) ~= 'string' or challenge_id == ''
    or not store_has(self.replay_store, binding_key(signature, challenge_id))
    or store_has(self.replay_store, RECONCILED_PREFIX .. signature) then
    verifier_error('Transaction signature already consumed', error_codes.SIGNATURE_CONSUMED)
  end
  local ok, statuses = pcall(self.rpc.signature_statuses, self.rpc, { signature })
  if not ok then
    settlement_pending(signature, 'status unavailable: ' .. error_message(statuses))
  end
  local status = statuses and statuses[1]
  if type(status) == 'table' then
    if status.err ~= nil and status.err ~= json.null then
      self.replay_store:delete(binding_key(signature, challenge_id))
      verifier_error('Transaction ' .. signature .. ' landed on-chain but failed: ' .. tostring(status.err))
    end
    local confirmation_status = status.confirmationStatus
    if confirmation_status == 'confirmed' or confirmation_status == 'finalized' then
      return grant(self, signature, challenge_id)
    end
  end
  settlement_pending(signature, 'not yet confirmed')
end

--- Pull-mode settlement.
-- The credential payload carries a base64 signed transaction. The handler
-- verifies the transaction shape, optionally cosigns it, simulates with
-- retry, broadcasts, consumes the signature, then awaits confirmation.
function Handler:settle_pull(transaction_base64, request, challenge_id)
  if type(transaction_base64) ~= 'string' or transaction_base64 == '' then
    verifier_error('missing or empty transaction payload')
  end
  -- The pending charge is bound to the challenge that claimed it; without one
  -- a charge left pending could never be reconciled.
  if type(challenge_id) ~= 'string' or challenge_id == '' then
    verifier_error('missing challenge id for pull settlement')
  end

  -- Stage 1: shape verification. Failing here means we never touch the RPC.
  -- Preserve a canonical L6 code if the verifier hook raised one; the
  -- bundled verifier always raises PAYMENT_INVALID, but a third-party
  -- transaction_verifier might pick a different canonical code (e.g.
  -- WRONG_NETWORK) and we don't want the handler's rewrap to drop it.
  local ok, verify_err = pcall(self.transaction_verifier, transaction_base64, request)
  if not ok then
    local message = type(verify_err) == 'table' and verify_err.message or tostring(verify_err)
    local hook_code = (type(verify_err) == 'table'
      and error_codes.ALL[verify_err.code] and verify_err.code) or nil
    verifier_error(message, hook_code)
  end

  -- Stage 2: network-blockhash gate. Done after shape verification because
  -- the verifier may parse the transaction and stash the blockhash.
  if type(self.pull_blockhash_extractor) == 'function' then
    local blockhash = self.pull_blockhash_extractor(transaction_base64)
    if type(blockhash) == 'string' and blockhash ~= '' then
      local err = network_check.check_network_blockhash(self.network, blockhash)
      if err then
        verifier_error(err.message, error_codes.WRONG_NETWORK)
      end
    end
  end

  -- Stages 3-4: optional cosign, then derive the final signature and claim
  -- it before anything is sent. A transaction already claimed is either
  -- pending (reconcile it) or consumed.
  local signed_base64, local_signature = self:signed_transaction(transaction_base64)
  local verified = pcall(self.pull_signature_verifier, signed_base64)
  if not verified then
    verifier_error('transaction signature verification failed')
  end
  local ledger = consumed_signatures.new(self.replay_store)
  if not ledger:claim(local_signature) then
    local reconciled = self:reconcile_pending(local_signature, challenge_id)
    return reconciled
  end
  local recorded, record_err = pcall(record_pending, self, local_signature, challenge_id)
  if not recorded then
    pcall(abandon, self, ledger, local_signature, challenge_id)
    error(record_err, 0)
  end

  -- Stage 5: simulate with bounded retries. A program-level error fails
  -- the request immediately (no retry, because the result is deterministic
  -- and the next attempt would just consume another RPC round-trip to get
  -- the same error). A transport-level error (pcall returned false) is
  -- retried up to `simulation_max_attempts` times. Nothing has been sent,
  -- so every failure here releases the claim.
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
  local simulation_failure
  if simulate_err ~= nil then
    simulation_failure = 'Simulation failed: ' .. error_message(simulate_err)
  elseif simulation == nil then
    simulation_failure = 'Simulation failed: empty simulation result'
  -- `pay_kit.util.json` decodes JSON `null` as `json.null` (a table sentinel),
  -- not Lua `nil`. Solana JSON-RPC returns `"err": null` on success, so
  -- comparing against both nil and the sentinel is required to recognize
  -- a successful simulation.
  elseif simulation.err ~= nil and simulation.err ~= json.null then
    simulation_failure = 'Simulation failed: ' .. tostring(simulation.err)
  end
  if simulation_failure then
    abandon(self, ledger, local_signature, challenge_id)
    verifier_error(simulation_failure)
  end

  -- Stage 6: broadcast. Only a preflight rejection proves the node did not
  -- forward the transaction (release, the payer may present it again). Any
  -- other error (a lost response, a 5xx from a proxy that already forwarded
  -- it) leaves the outcome unknown: the claim is kept and the charge stays
  -- pending for reconciliation, so the client is never released to pay a
  -- replacement while the original can still land.
  local send_ok, signature = pcall(self.rpc.send_raw_transaction, self.rpc, signed_base64)
  if not send_ok then
    if is_preflight_rejection(signature) then
      abandon(self, ledger, local_signature, challenge_id)
      verifier_error('Simulation failed: ' .. error_message(signature))
    end
    settlement_pending(local_signature, 'broadcast outcome unknown: ' .. error_message(signature))
  end
  if signature ~= local_signature then
    settlement_pending(local_signature,
      'RPC returned signature ' .. tostring(signature) .. ' for a different transaction')
  end

  -- Stage 7: confirmation polling. Errors here surface but the signature
  -- is already consumed, mirroring the Rust spine.
  self:await_confirmation(signature)

  return grant(self, signature, challenge_id)
end

--- The transaction as this server broadcasts it (co-signed when it pays the
--- fee) and its first signature, which identifies it on chain.
function Handler:signed_transaction(transaction_base64)
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
  local extractor = self.pull_signature_extractor or default_signature_extractor
  local extract_ok, local_signature = pcall(extractor, signed_base64)
  if not extract_ok or type(local_signature) ~= 'string' or local_signature == '' then
    verifier_error('could not derive the transaction signature: ' .. error_message(local_signature))
  end
  return signed_base64, local_signature
end

--- Reconcile the pending charge an expired credential's challenge left
--- behind, from the chain only (never broadcast). Returns nil when that
--- challenge has no pending charge of its own, so the credential is refused
--- as expired.
function Handler:reconcile_expired(payload, challenge_id)
  if type(payload) ~= 'table' or payload.type ~= 'transaction'
    or type(payload.transaction) ~= 'string' or payload.transaction == ''
    or type(challenge_id) ~= 'string' or challenge_id == '' then
    return nil
  end
  local ok, _, signature = pcall(self.signed_transaction, self, payload.transaction)
  if not ok then
    return nil
  end
  if not store_has(self.replay_store, binding_key(signature, challenge_id)) then
    return nil
  end
  return self:reconcile_pending(signature, challenge_id)
end

--- Push-mode settlement.
-- The credential payload carries a base58 signature for a transaction the
-- client already broadcast and awaited. The handler must fetch the
-- on-chain transaction, verify its shape, then consume the signature.
function Handler:settle_push(signature, request)
  if type(signature) ~= 'string' or signature == '' then
    verifier_error('missing or empty signature payload')
  end

  local transaction_base64, block_time = self:fetch_settled_transaction(signature)
  -- A durable claim is kept for `pay_kit.store.DURABLE_RETENTION_SECONDS`.
  -- A landed transaction older than that could be presented again once its
  -- claim expired, so push mode accepts only payments well inside it; the
  -- claim made below then outlives every presentation it can see.
  if type(block_time) ~= 'number' then
    verifier_error('Transaction ' .. signature .. ' has no block time; its age cannot be checked')
  end
  if os.time() - block_time > MAX_PUSH_AGE_SECONDS then
    verifier_error('Transaction ' .. signature .. ' is too old to present as a payment')
  end
  local ok, verify_err = pcall(self.transaction_verifier, transaction_base64, request)
  if not ok then
    local message = type(verify_err) == 'table' and verify_err.message or tostring(verify_err)
    -- Same canonical-code passthrough as settle_pull: a third-party
    -- verifier may raise a non-payment-invalid canonical code and we
    -- want the response builder to see it intact.
    local hook_code = (type(verify_err) == 'table'
      and error_codes.ALL[verify_err.code] and verify_err.code) or nil
    verifier_error(message, hook_code)
  end

  consume_replay(self, signature)
  return signature
end

--- Drive the right mode based on the credential payload type. Convenience
-- wrapper used by `as_callback()` so callers do not branch themselves.
function Handler:settle(payload, request, challenge_id)
  if type(payload) ~= 'table' then
    verifier_error('payload table is required')
  end
  if payload.type == 'transaction' then
    return self:settle_pull(payload.transaction, request, challenge_id)
  elseif payload.type == 'signature' then
    -- Audit #5: reject push-mode credentials unless the operator opted in.
    if not self.accept_push_mode then
      verifier_error('Push-mode credentials are disabled on this server (enable accept_push_mode to opt in; spec §13.5)')
    end
    return self:settle_push(payload.signature, request)
  end
  verifier_error('unsupported payload type: ' .. tostring(payload.type))
end

--- Build a `verify_payment` callback compatible with `mpp.server.new`. The
-- callback consumes the replay store inside the handler (in `settle_pull`
-- between broadcast and await; in `settle_push` after on-chain shape
-- verification) and reports back with `consumed = true` so the outer
-- `Server:_finalize_verification` skips its own `put_if_absent` call.
-- This is the contract that lets the Kong / OpenResty wiring share a
-- single replay store between `charge_handler.new({ replay_store })` and
-- `mpp.server.new({ store })` without the second consume colliding with
-- the first and rejecting a valid first payment as `signature_consumed`.
-- `options.replay_key_prefix` is retained for backward compatibility and
-- still surfaces the namespaced server-level key in the returned table
-- even though the outer consume is now a no-op.
function Handler:as_callback(options)
  options = options or {}
  local prefix = options.replay_key_prefix or 'solana-charge:server-noop:'
  local handler = self
  return function(context)
    local challenge_id = context.credential and context.credential.challenge
      and context.credential.challenge.id
    local signature = handler:settle(context.payload, context.request, challenge_id)
    return {
      reference = signature,
      replay_key = prefix .. signature,
      -- Signals to `Server:_finalize_verification` that the durable
      -- replay marker is already in place; the outer put_if_absent is
      -- skipped so we do not re-assert against the same shared store.
      consumed = true,
    }
  end
end

--- Build a `reconcile_expired` callback for `mpp.server.new`: it finishes the
--- pending charge an expired credential's challenge left behind, and returns
--- nil (the server then refuses the credential as expired) when there is
--- none. Pass it beside `verify_payment = handler:as_callback()`.
function Handler:reconcile_expired_callback()
  local handler = self
  return function(context)
    local challenge_id = context.credential and context.credential.challenge
      and context.credential.challenge.id
    local signature = handler:reconcile_expired(context.payload, challenge_id)
    if signature == nil then
      return nil
    end
    return { reference = signature, consumed = true }
  end
end

--- Poll `getSignatureStatuses` until the signature is confirmed/finalized
-- or the attempt budget is exhausted. Raises on `meta.err`. A status that
-- never surfaces (null, still processing, or an RPC error) is not proof the
-- transaction did not execute: the queried node may lag or lack history for
-- a transaction that committed in time. The charge then stays pending for
-- reconciliation instead of failing, so the client is never released to pay
-- a replacement.
function Handler:await_confirmation(signature)
  local last_error
  for attempt = 1, self.confirmation_attempts do
    local ok, statuses = pcall(self.rpc.signature_statuses, self.rpc, { signature })
    if not ok then
      last_error = error_message(statuses)
      statuses = nil
    end
    local status = statuses and statuses[1]
    if type(status) == 'table' then
      -- Solana JSON-RPC returns `"err": null` on success; pay_kit.util.json
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
  settlement_pending(signature, 'timed out waiting for confirmation' ..
    (last_error and (': ' .. last_error) or ''))
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
        local block_time = response.blockTime
        if block_time == json.null then block_time = nil end
        return wire[1], block_time
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
