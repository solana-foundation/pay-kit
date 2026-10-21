local t = require('tests.test_helper')
local charge_handler = require('pay_kit.protocols.mpp.server.charge_handler')
local store = require('pay_kit.protocols.mpp.store')

-- A fake RPC that returns scripted responses for each method and records every
-- call so tests can assert ordering. Each `responses[<method>]` is a list of
-- table-or-function entries consumed in order.
local function fake_rpc(responses)
  local state = { calls = {} }
  local indices = {}
  local function next_response(method)
    indices[method] = (indices[method] or 0) + 1
    local list = responses[method]
    if list == nil then
      error('unexpected ' .. method .. ' call')
    end
    local response = list[indices[method]]
    if response == nil then
      error('exhausted responses for ' .. method)
    end
    if type(response) == 'function' then
      return response()
    end
    if response.error then
      error({ code = response.error.code or 'rpc-error', message = response.error.message })
    end
    return response.result
  end
  state.simulate_transaction = function(_self, tx)
    state.calls[#state.calls + 1] = { method = 'simulateTransaction', tx = tx }
    return next_response('simulateTransaction')
  end
  -- The signature the next sendTransaction answers with, standing in for the
  -- handler's local signature derivation on these opaque test payloads.
  state.peek_send = function()
    local list = responses.sendTransaction or {}
    local response = list[(indices.sendTransaction or 0) + 1]
    if type(response) == 'table' and type(response.result) == 'string' then
      return response.result
    end
    return 'unsent-signature'
  end
  state.send_raw_transaction = function(_self, tx)
    state.calls[#state.calls + 1] = { method = 'sendTransaction', tx = tx }
    return next_response('sendTransaction')
  end
  state.signature_statuses = function(_self, signatures)
    state.calls[#state.calls + 1] = { method = 'getSignatureStatuses', signatures = signatures }
    return next_response('getSignatureStatuses')
  end
  state.transaction = function(_self, signature)
    state.calls[#state.calls + 1] = { method = 'getTransaction', signature = signature }
    return next_response('getTransaction')
  end
  state.latest_blockhash = function(_self)
    state.calls[#state.calls + 1] = { method = 'getLatestBlockhash' }
    return next_response('getLatestBlockhash')
  end
  return state
end

local function new_handler(opts)
  opts = opts or {}
  local rpc = opts.rpc or fake_rpc({})
  return charge_handler.new({
    rpc = rpc,
    network = opts.network or 'localnet',
    replay_store = opts.replay_store or store.memory(),
    transaction_verifier = opts.transaction_verifier or function() end,
    pull_transaction_signer = opts.pull_transaction_signer,
    pull_blockhash_extractor = opts.pull_blockhash_extractor,
    pull_signature_extractor = opts.pull_signature_extractor or function() return rpc.peek_send() end,
    -- These payloads are opaque stand-ins, not signed wire transactions; the
    -- default Ed25519 verifier is covered by its own test.
    pull_signature_verifier = opts.pull_signature_verifier or function() end,
    confirmation_attempts = opts.confirmation_attempts or 2,
    confirmation_delay_seconds = 0,
    simulation_max_attempts = opts.simulation_max_attempts or 2,
    simulation_retry_delay_seconds = 0,
    sleep = function() end,
  }), rpc
end

-- ─── Constructor guards ───────────────────────────────────────────────────

t.test('handler constructor rejects non-table config', function()
  t.assert_error(function() charge_handler.new('nope') end, 'config table is required')
end)

t.test('handler constructor rejects missing rpc', function()
  t.assert_error(function()
    charge_handler.new({ replay_store = store.memory(), transaction_verifier = function() end })
  end, 'rpc client is required')
end)

t.test('handler constructor rejects missing replay_store', function()
  t.assert_error(function()
    charge_handler.new({ rpc = fake_rpc({}), transaction_verifier = function() end })
  end, 'replay_store is required')
end)

t.test('handler constructor rejects missing transaction_verifier', function()
  t.assert_error(function()
    charge_handler.new({ rpc = fake_rpc({}), replay_store = store.memory() })
  end, 'transaction_verifier function is required')
end)

-- ─── Pull mode ────────────────────────────────────────────────────────────

t.test('settle_pull happy path: verify → simulate → send → consume → await', function()
  local handler, rpc = new_handler({
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil, logs = { 'ok' } } } },
      sendTransaction = { { result = 'sig-1' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed', err = nil } } } },
    }),
  })
  local signature = handler:settle_pull('tx-b64', { amount = '1' }, 'ch')
  t.assert_equal(signature, 'sig-1')
  local methods = {}
  for _, call in ipairs(rpc.calls) do methods[#methods + 1] = call.method end
  t.assert_equal(methods[1], 'simulateTransaction')
  t.assert_equal(methods[2], 'sendTransaction')
  t.assert_equal(methods[3], 'getSignatureStatuses')
end)

t.test('settle_pull accepts json.null err sentinels through full lifecycle', function()
  -- Regression for the JSON null sentinel handling. pay_kit.util.json decodes
  -- JSON `null` as `json.null` (a table), not Lua `nil`. Solana JSON-RPC
  -- returns `"err": null` on success in simulateTransaction,
  -- getSignatureStatuses, and getTransaction. The previous code compared
  -- `simulation.err ~= nil` / `status.err ~= nil` / `meta.err ~= nil`,
  -- which is `true` against `json.null` and would raise a spurious
  -- "Simulation failed" / "Transaction failed" on every successful round
  -- trip in production. fake_rpc usually hands back Lua tables directly
  -- (bypassing the JSON codec), so this test forces the sentinel values
  -- the production codec would actually produce.
  local json = require('pay_kit.util.json')
  local handler, rpc = new_handler({
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = json.null, logs = { 'ok' } } } },
      sendTransaction = { { result = 'sig-json-null' } },
      getSignatureStatuses = {
        { result = { { confirmationStatus = 'confirmed', err = json.null } } },
      },
    }),
  })
  local signature = handler:settle_pull('tx-b64', { amount = '1' }, 'ch')
  t.assert_equal(signature, 'sig-json-null')
  t.assert_equal(#rpc.calls, 3)
end)

t.test('settle_pull rejects empty transaction payload', function()
  local handler = new_handler()
  t.assert_error(function() handler:settle_pull('', {}) end, 'missing or empty transaction')
end)

t.test('settle_pull surfaces verifier rejection without touching RPC', function()
  local rpc = fake_rpc({})
  local handler = new_handler({
    rpc = rpc,
    transaction_verifier = function() error({ code = 'verification-error', message = 'bad shape' }) end,
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'bad shape')
  t.assert_equal(#rpc.calls, 0)
end)

t.test('settle_pull network gate rejects surfpool tx against mainnet', function()
  local handler = new_handler({
    network = 'mainnet',
    pull_blockhash_extractor = function() return 'SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxxxxxxx' end,
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'localnet')
end)

t.test('settle_pull network gate allows surfpool tx on localnet', function()
  local handler = new_handler({
    network = 'localnet',
    pull_blockhash_extractor = function() return 'SURFNETxSAFEHASHxxxxx' end,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'finalized', err = nil } } } },
    }),
  })
  t.assert_equal(handler:settle_pull('tx', {}, 'ch'), 'sig')
end)

t.test('settle_pull cosign replaces transaction before simulate', function()
  local rpc = fake_rpc({
    simulateTransaction = { { result = { err = nil } } },
    sendTransaction = { { result = 'sig' } },
    getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed', err = nil } } } },
  })
  local handler = new_handler({
    rpc = rpc,
    pull_transaction_signer = function(_tx) return 'cosigned-tx' end,
  })
  handler:settle_pull('original-tx', {}, 'ch')
  t.assert_equal(rpc.calls[1].tx, 'cosigned-tx')
end)

t.test('settle_pull surfaces cosign failure as verification error', function()
  local handler = new_handler({
    pull_transaction_signer = function() error('signer offline') end,
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'cosign failed')
end)

t.test('settle_pull rejects empty cosign result', function()
  local handler = new_handler({
    pull_transaction_signer = function() return '' end,
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'empty transaction')
end)

t.test('settle_pull retries simulation on transient RPC failure', function()
  local handler, rpc = new_handler({
    rpc = fake_rpc({
      simulateTransaction = {
        { error = { code = 'transport-error', message = 'timeout' } },
        { result = { err = nil } },
      },
      sendTransaction = { { result = 'sig' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed', err = nil } } } },
    }),
    simulation_max_attempts = 3,
  })
  t.assert_equal(handler:settle_pull('tx', {}, 'ch'), 'sig')
  local sim_calls = 0
  for _, c in ipairs(rpc.calls) do if c.method == 'simulateTransaction' then sim_calls = sim_calls + 1 end end
  t.assert_equal(sim_calls, 2)
end)

t.test('settle_pull bails after exhausting simulation retries', function()
  local handler = new_handler({
    rpc = fake_rpc({
      simulateTransaction = {
        { error = { message = 'timeout-1' } },
        { error = { message = 'timeout-2' } },
        { error = { message = 'timeout-3' } },
      },
    }),
    simulation_max_attempts = 3,
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'Simulation failed')
end)

t.test('settle_pull fails when simulation reports program error', function()
  local handler = new_handler({
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = 'InsufficientFunds' } } },
    }),
    simulation_max_attempts = 1,
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'InsufficientFunds')
end)

t.test('settle_pull consumes signature before awaiting confirmation', function()
  -- Order check: send, then put_if_absent inserts the key, then status poll.
  -- Use a status that times out to ensure consume happened first.
  local replay = store.memory()
  local handler = new_handler({
    replay_store = replay,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig-x' } },
      getSignatureStatuses = {
        { result = { { confirmationStatus = 'processed', err = nil } } },
        { result = { { confirmationStatus = 'processed', err = nil } } },
      },
    }),
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'in progress')
  -- The replay store should already contain the consumed signature key.
  local _value, present = replay:get('solana:consumed-signature:sig-x')
  t.assert_true(present, 'signature must be consumed before confirmation poll completes')
end)

t.test('settle_pull rejects already-consumed signature', function()
  local replay = store.memory()
  replay:put('solana:consumed-signature:sig-dupe', true)
  local handler = new_handler({
    replay_store = replay,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig-dupe' } },
    }),
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'already consumed')
end)

t.test('settle_pull surfaces transaction failure during confirmation', function()
  local handler = new_handler({
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed', err = 'AccountInUse' } } } },
    }),
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'AccountInUse')
end)

t.test('settle_pull keeps the charge pending when confirmation never surfaces', function()
  local handler = new_handler({
    confirmation_attempts = 2,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig' } },
      getSignatureStatuses = {
        { result = { { confirmationStatus = 'processed', err = nil } } },
        { result = { { confirmationStatus = 'processed', err = nil } } },
      },
    }),
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'in progress')
end)

-- ─── Ambiguous broadcast (SOLA1-301) ─────────────────────────────────────

local error_codes = require('pay_kit.protocol.core.error_codes')

local function raised(fn)
  local ok, err = pcall(fn)
  t.assert_true(not ok, 'expected an error')
  return err
end

-- A send error other than a preflight rejection does not prove the node
-- dropped the transaction (the response may be lost after it was accepted),
-- so the charge stays pending under the locally derived signature and
-- reconciles; only a preflight rejection fails it and releases the claim.
t.test('ambiguous send error is pending, not failed, and reconciles on retry', function()
  local replay = store.memory()
  local handler = new_handler({
    replay_store = replay,
    pull_signature_extractor = function() return 'sig-lost' end,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { error = { code = 'transport-error', message = 'response lost' } } },
      getSignatureStatuses = {
        { result = {} },
        { result = { { confirmationStatus = 'confirmed' } } },
      },
    }),
  })

  local err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  local _v, claimed = replay:get('solana:consumed-signature:sig-lost')
  t.assert_true(claimed, 'the possibly-sent signature must stay claimed')

  -- Not visible yet: still pending, never failed.
  err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  -- It landed: the identical retry is granted, once.
  t.assert_equal(handler:settle_pull('tx', {}, 'ch'), 'sig-lost')
  err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.SIGNATURE_CONSUMED)
end)

t.test('preflight rejection fails the charge and releases the claim', function()
  local replay = store.memory()
  local handler = new_handler({
    replay_store = replay,
    pull_signature_extractor = function() return 'sig-rejected' end,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { function()
        error({ code = 'rpc-error', rpc_code = -32002,
                message = 'sendTransaction: Transaction simulation failed' })
      end },
    }),
  })
  local err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.PAYMENT_INVALID)
  t.assert_true(tostring(err.message):match('Simulation failed') ~= nil, tostring(err.message))
  local _v, claimed = replay:get('solana:consumed-signature:sig-rejected')
  t.assert_true(not claimed, 'an unsent transaction must be released')
end)

-- ─── Missing signature status (SOLA1-299) ────────────────────────────────

-- A null status (or an RPC that cannot answer) is never proof the transaction
-- did not execute: a lagging or history-less node returns null for one that
-- committed in time. Only an explicit on-chain outcome resolves the charge.
t.test('missing signature status never fails a pending charge', function()
  local replay = store.memory()
  local handler = new_handler({
    replay_store = replay,
    confirmation_attempts = 2,
    pull_signature_extractor = function() return 'sig-unseen' end,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig-unseen' } },
      getSignatureStatuses = {
        { result = {} },
        { error = { code = 'transport-error', message = 'node unreachable' } },
        { result = {} },
        { result = { { confirmationStatus = 'finalized' } } },
      },
    }),
  })
  local err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  -- When the status does surface, the same retry is granted.
  t.assert_equal(handler:settle_pull('tx', {}, 'ch'), 'sig-unseen')
end)

t.test('an explicit on-chain failure resolves a pending charge as failed', function()
  local handler = new_handler({
    confirmation_attempts = 1,
    pull_signature_extractor = function() return 'sig-failed' end,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig-failed' } },
      getSignatureStatuses = {
        { result = {} },
        { result = { { confirmationStatus = 'confirmed', err = { InstructionError = { 0, 'Custom' } } } } },
      },
    }),
  })
  local err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.PAYMENT_INVALID)
  t.assert_true(tostring(err.message):match('landed on%-chain but failed') ~= nil, tostring(err.message))
  err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.SIGNATURE_CONSUMED)
end)

-- ─── Shared consumed-signature ledger (SOLA1-289) ────────────────────────

-- One on-chain payment authorizes one request across protocols: a signature
-- settled through MPP cannot be presented again as an x402 payment on a gate
-- sharing the store, nor the other way round.
t.test('signature consumed by one protocol is rejected by the other', function()
  local x402_private = require('pay_kit.protocols.x402')._private
  local shared = require('pay_kit.store').memory()
  local handler = new_handler({
    replay_store = shared,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } }, { result = { err = nil } } },
      sendTransaction = { { result = 'mpp-paid' }, { result = 'x402-paid' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed' } } } },
    }),
  })

  t.assert_equal(handler:settle_pull('tx', {}, 'ch'), 'mpp-paid')
  t.assert_equal(x402_private.claim_signature(shared, shared, 'mpp-paid'), 'consumed')

  t.assert_equal(x402_private.claim_signature(shared, shared, 'x402-paid'), 'claimed')
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'already consumed')

  -- An unrelated payment is still accepted, and x402's own retry recovery
  -- of a signature it claimed keeps working.
  t.assert_equal(x402_private.claim_signature(shared, shared, 'third'), 'claimed')
  t.assert_equal(x402_private.claim_signature(shared, shared, 'x402-paid'), 'pending')
end)

-- A signature claimed under a pre-ledger MPP or x402 key (by an older
-- replica, or just before an upgrade) stays consumed for both protocols; the
-- legacy record is only read, never rewritten.
for _, case in ipairs({
  { name = 'MPP charge', key = 'solana-charge:consumed:legacy-sig' },
  { name = 'x402 exact', key = 'x402-svm-exact:legacy-sig:consumed' },
}) do
  t.test('pre-ledger ' .. case.name .. ' claim stays consumed', function()
    local consumed_signatures = require('pay_kit.consumed_signatures')
    for _, shared in ipairs({ require('pay_kit.store').memory(), require('pay_kit.protocols.mpp.store').memory() }) do
      shared:put_if_absent(case.key, true)
      local ledger = consumed_signatures.new(shared)
      t.assert_true(not ledger:claim('legacy-sig'), case.key)
      t.assert_true(not shared:get(consumed_signatures.key('legacy-sig')), case.key)
      t.assert_true(shared:get(case.key) and true or false, case.key)

      -- Signatures without a legacy record claim normally, once.
      t.assert_true(ledger:claim('fresh-sig'))
      t.assert_true(not ledger:claim('fresh-sig'))
    end
  end)
end

t.test('pre-ledger MPP charge claim is consumed for x402 and MPP settlement', function()
  local x402_private = require('pay_kit.protocols.x402')._private
  local shared = require('pay_kit.store').memory()
  shared:put_if_absent('solana-charge:consumed:legacy-sig', true)
  t.assert_equal(x402_private.claim_signature(shared, shared, 'legacy-sig'), 'consumed')
  local handler = new_handler({
    replay_store = shared,
    pull_signature_extractor = function() return 'legacy-sig' end,
    rpc = fake_rpc({}),
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch') end, 'already consumed')
end)

t.test('PayKit adapters resolve one ledger store for MPP and x402', function()
  local consumed_signatures = require('pay_kit.consumed_signatures')
  local dispatcher_store, operator_store = {}, {}
  t.assert_equal(consumed_signatures.shared_store({ mpp = {} }, dispatcher_store), dispatcher_store)
  t.assert_equal(consumed_signatures.shared_store(
    { mpp = { replay_store = operator_store } }, dispatcher_store), operator_store)
end)

t.test('pay_kit.store keeps a consumed-signature claim for the durable retention', function()
  local store_mod = require('pay_kit.store')
  local memory = store_mod.memory()
  local now = os.time()
  t.assert_true(memory:put_if_absent('durable', true))
  t.assert_true(memory:put_if_absent('leased', 15))
  t.assert_true(memory._entries.durable >= now + store_mod.DURABLE_RETENTION_SECONDS)
  t.assert_true(memory._entries.leased < now + 60)
  t.assert_true(not memory:put_if_absent('durable', true))
end)

-- A full shared zone must fail the claim loudly, never read as a duplicate
-- (which would answer every later, already-sent payment SIGNATURE_CONSUMED),
-- and durable claims carry a bounded expiry so the zone does not fill up.
t.test('pay_kit.store shared dict bounds durable claims and raises when full', function()
  local store_mod = require('pay_kit.store')
  local calls = {}
  local full = false
  local dict = {
    _data = {},
    safe_add = function(self, key, value, exptime)
      calls[#calls + 1] = { 'safe_add', key, exptime }
      if full then return false, 'no memory' end
      if self._data[key] then return false, 'exists' end
      self._data[key] = value
      return true
    end,
    add = function(self, key, value, exptime)
      calls[#calls + 1] = { 'add', key, exptime }
      if self._data[key] then return false, 'exists' end
      self._data[key] = value
      return true
    end,
    get = function(self, key) return self._data[key] end,
    delete = function(self, key) self._data[key] = nil end,
  }
  local saved = rawget(_G, 'ngx')
  rawset(_G, 'ngx', { shared = { pay_kit_replay = dict } })
  local ok, err = pcall(function()
    local shared = assert(store_mod.shared_dict('pay_kit_replay'))
    t.assert_true(shared:put_if_absent('claim', true))
    t.assert_equal(calls[1][3], store_mod.DURABLE_RETENTION_SECONDS)
    t.assert_true(not shared:put_if_absent('claim', true))
    full = true
    local raised_ok, raised_err = pcall(shared.put_if_absent, shared, 'another', true)
    t.assert_true(not raised_ok, 'a full zone must raise')
    t.assert_true(tostring(raised_err):find('no memory', 1, true) ~= nil, tostring(raised_err))
  end)
  rawset(_G, 'ngx', saved)
  if not ok then error(err, 0) end
end)

-- ─── Push mode ────────────────────────────────────────────────────────────

t.test('settle_push happy path: fetch → verify → consume', function()
  local replay = store.memory()
  local verify_called = false
  local handler = new_handler({
    replay_store = replay,
    transaction_verifier = function(tx, _req)
      verify_called = true
      t.assert_equal(tx, 'on-chain-b64')
    end,
    rpc = fake_rpc({
      getTransaction = { { result = { meta = { err = nil }, transaction = { 'on-chain-b64', 'base64' }, blockTime = os.time() } } },
    }),
  })
  local sig = handler:settle_push('sig-push', {})
  t.assert_equal(sig, 'sig-push')
  t.assert_true(verify_called)
  local _v, present = replay:get('solana:consumed-signature:sig-push')
  t.assert_true(present)
end)

t.test('settle_push rejects empty signature payload', function()
  local handler = new_handler()
  t.assert_error(function() handler:settle_push('', {}) end, 'missing or empty signature')
end)

t.test('settle_push retries until transaction is observed', function()
  local handler, rpc = new_handler({
    confirmation_attempts = 3,
    rpc = fake_rpc({
      getTransaction = {
        { result = nil },
        { result = nil },
        { result = { meta = { err = nil }, transaction = { 'tx-b64', 'base64' }, blockTime = os.time() } },
      },
    }),
  })
  t.assert_equal(handler:settle_push('sig', {}), 'sig')
  local gt_calls = 0
  for _, c in ipairs(rpc.calls) do if c.method == 'getTransaction' then gt_calls = gt_calls + 1 end end
  t.assert_equal(gt_calls, 3)
end)

t.test('settle_push treats json.null transaction result as "not yet observed"', function()
  -- Regression test for codex review P1: getTransaction returning JSON null
  -- (the wire encoding for an unobserved signature) must drive the retry
  -- loop, not fall into the meta-check branch and fail with
  -- "missing transaction metadata".
  local json = require('pay_kit.util.json')
  local handler, rpc = new_handler({
    confirmation_attempts = 3,
    rpc = fake_rpc({
      getTransaction = {
        { result = json.null },
        { result = json.null },
        { result = { meta = { err = nil }, transaction = { 'tx-b64', 'base64' }, blockTime = os.time() } },
      },
    }),
  })
  t.assert_equal(handler:settle_push('sig', {}), 'sig')
  local gt_calls = 0
  for _, c in ipairs(rpc.calls) do if c.method == 'getTransaction' then gt_calls = gt_calls + 1 end end
  t.assert_equal(gt_calls, 3)
end)

t.test('settle_push surfaces on-chain err from meta', function()
  local handler = new_handler({
    rpc = fake_rpc({
      getTransaction = { { result = { meta = { err = 'InsufficientFunds' }, transaction = { 'tx', 'base64' } } } },
    }),
  })
  t.assert_error(function() handler:settle_push('sig', {}) end, 'InsufficientFunds')
end)

t.test('settle_push rejects missing meta field', function()
  local handler = new_handler({
    rpc = fake_rpc({
      getTransaction = { { result = { transaction = { 'tx', 'base64' } } } },
    }),
  })
  t.assert_error(function() handler:settle_push('sig', {}) end, 'missing transaction metadata')
end)

t.test('settle_push rejects missing transaction field', function()
  local handler = new_handler({
    rpc = fake_rpc({
      getTransaction = { { result = { meta = { err = nil } } } },
    }),
  })
  t.assert_error(function() handler:settle_push('sig', {}) end, 'missing base64 transaction')
end)

t.test('settle_push times out when transaction never observed', function()
  local handler = new_handler({
    confirmation_attempts = 2,
    rpc = fake_rpc({
      getTransaction = { { result = nil }, { result = nil } },
    }),
  })
  t.assert_error(function() handler:settle_push('sig', {}) end, 'Timed out fetching')
end)

t.test('settle_push surfaces verifier rejection after fetch', function()
  local replay = store.memory()
  local handler = new_handler({
    replay_store = replay,
    transaction_verifier = function() error({ code = 'verification-error', message = 'wrong recipient' }) end,
    rpc = fake_rpc({
      getTransaction = { { result = { meta = { err = nil }, transaction = { 'tx', 'base64' }, blockTime = os.time() } } },
    }),
  })
  t.assert_error(function() handler:settle_push('sig', {}) end, 'wrong recipient')
  -- Signature must NOT be consumed when verification fails post-fetch.
  local _v, present = replay:get('solana:consumed-signature:sig')
  t.assert_true(not present, 'failed-shape settlements must not consume the signature')
end)

t.test('settle_push rejects already-consumed signature', function()
  local replay = store.memory()
  replay:put('solana:consumed-signature:sig-dupe', true)
  local handler = new_handler({
    replay_store = replay,
    rpc = fake_rpc({
      getTransaction = { { result = { meta = { err = nil }, transaction = { 'tx', 'base64' }, blockTime = os.time() } } },
    }),
  })
  t.assert_error(function() handler:settle_push('sig-dupe', {}) end, 'already consumed')
end)

-- ─── Mode dispatch + callback adapter ────────────────────────────────────

t.test('settle dispatches based on payload type', function()
  local handler = new_handler({
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'pull-sig' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed', err = nil } } } },
    }),
  })
  t.assert_equal(handler:settle({ type = 'transaction', transaction = 'tx' }, {}, 'ch'), 'pull-sig')
end)

t.test('settle rejects unknown payload type', function()
  local handler = new_handler()
  t.assert_error(function() handler:settle({ type = 'wat' }, {}) end, 'unsupported payload')
end)

t.test('settle rejects non-table payload', function()
  local handler = new_handler()
  t.assert_error(function() handler:settle(nil, {}) end, 'payload table is required')
end)

t.test('as_callback returns a function usable by mpp.server', function()
  local handler = new_handler({
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'cb-sig' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed', err = nil } } } },
    }),
  })
  local cb = handler:as_callback()
  local result = cb({ payload = { type = 'transaction', transaction = 'tx' }, request = {},
    credential = { challenge = { id = 'ch' } } })
  t.assert_equal(result.reference, 'cb-sig')
  t.assert_true(result.replay_key:find('server-noop', 1, true) ~= nil)
  -- The callback must signal that the durable replay marker is already in
  -- place so the outer `Server:_finalize_verification` skips its own
  -- `put_if_absent` call against the (potentially shared) store. Without
  -- this signal the Kong wiring would double-consume the same key.
  t.assert_equal(result.consumed, true)
end)

-- Kong / OpenResty wiring regression. The Kong plugin shares a single
-- replay_store between `charge_handler.new({ replay_store = shared })` and
-- `mpp.server.new({ store = shared })`. Codex round 3 on PR #103 flagged
-- that without the `consumed` signal (or namespaced replay_key) the inner
-- `settle_pull` consume of `solana:consumed-signature:<sig>` collides with
-- the outer `Server:_finalize_verification` put_if_absent of the same
-- key on `result.reference`, returning `signature_consumed` for the
-- first valid payment. This test drives the full Kong-style stack
-- against a real `mpp.store.memory()` and asserts:
--   1. first valid settlement returns a receipt (no signature_consumed)
--   2. resubmission of the same signature is rejected as signature_consumed
t.test('Kong-style shared replay_store does not double-consume on first payment', function()
  local mpp = require('tests._mpp')
  local SECRET = 'kong-test-secret-key-long-enough-32b'
  local RECIPIENT = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h'

  local shared = store.memory()
  local handler = new_handler({
    replay_store = shared,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig-kong-1' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed', err = nil } } } },
    }),
  })
  local server = mpp.server.new({
    recipient = RECIPIENT,
    currency = 'USDC',
    decimals = 6,
    network = 'localnet',
    secret_key = SECRET,
    realm = 'MPP',
    store = shared,
    verify_payment = handler:as_callback(),
  })

  local challenge = server:charge('1.00')
  -- The route-expected request must carry the SAME methodDetails the
  -- challenge was issued with; `verify_credential_with_expected` now binds
  -- the full methodDetails (modulo recentBlockhash). Decode the issued
  -- request so the expected shape matches exactly (a real route rebuilds
  -- the same methodDetails it advertised).
  local expected_request = challenge.request:decode()
  local function build_credential()
    return mpp.NewPaymentCredential(challenge:to_echo(), {
      type = 'transaction',
      transaction = 'fake-tx-base64',
    })
  end

  -- First valid settlement must succeed; the shared store's consume
  -- happens once (inside settle_pull) and the outer finalize honors the
  -- `consumed` signal so it does not re-assert the same key.
  local receipt = server:verify_credential_with_expected(build_credential(), expected_request)
  t.assert_equal(receipt.reference, 'sig-kong-1')

  -- A second settlement with the same signature must hit the durable
  -- replay marker inside `settle_pull` and raise `signature_consumed`.
  -- Use a fresh handler bound to the same `shared` store so the RPC
  -- script is replayable; the consume marker is in the shared store.
  local replay_handler = new_handler({
    replay_store = shared,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig-kong-1' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed', err = nil } } } },
    }),
  })
  local replay_server = mpp.server.new({
    recipient = RECIPIENT,
    currency = 'USDC',
    decimals = 6,
    network = 'localnet',
    secret_key = SECRET,
    realm = 'MPP',
    store = shared,
    verify_payment = replay_handler:as_callback(),
  })
  local ok, err = pcall(function()
    replay_server:verify_credential_with_expected(build_credential(), expected_request)
  end)
  t.assert_true(not ok, 'replay must be rejected')
  local message = type(err) == 'table' and err.message or tostring(err)
  t.assert_true(message:find('consumed', 1, true) ~= nil,
    'expected signature_consumed-style error, got: ' .. tostring(message))
end)

-- A broadcast whose response was lost stays pending. A retry after the
-- challenge expired must still reconcile it (the payment may have landed),
-- without broadcasting it again; an expired credential never starts a
-- payment, nor reconciles a charge another challenge left pending.
t.test('pending charge reconciles after its challenge expires', function()
  local mpp = require('tests._mpp')
  local SECRET = 'expiry-test-secret-key-long-enough-32b'
  local RECIPIENT = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h'
  local shared = store.memory()
  local handler, rpc = new_handler({
    replay_store = shared,
    pull_signature_extractor = function(tx) return 'sig-' .. tx end,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } }, { result = { err = nil } } },
      sendTransaction = {
        { error = { code = 'transport-error', message = 'response lost' } },
        { error = { code = 'transport-error', message = 'response lost' } },
      },
      getSignatureStatuses = {
        { result = {} },
        { result = { { confirmationStatus = 'confirmed' } } },
      },
    }),
  })
  local server = mpp.server.new({
    recipient = RECIPIENT, currency = 'USDC', decimals = 6, network = 'localnet',
    secret_key = SECRET, realm = 'MPP', store = shared,
    verify_payment = handler:as_callback(),
    reconcile_expired = handler:reconcile_expired_callback(),
  })
  local function issue(description)
    local challenge = server:charge_with_options('1.00', { expires = '2030-01-01T00:00:00Z', description = description })
    return challenge, challenge.request:decode()
  end
  local function credential(challenge, tx)
    return mpp.NewPaymentCredential(challenge:to_echo(), { type = 'transaction', transaction = tx })
  end
  local later = os.time({ year = 2031, month = 1, day = 1, hour = 0 })
  local function sends()
    local n = 0
    for _, call in ipairs(rpc.calls) do
      if call.method == 'sendTransaction' then n = n + 1 end
    end
    return n
  end

  local challenge, expected = issue('first')
  local err = raised(function() server:verify_credential_with_expected(credential(challenge, 'tx-a'), expected) end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)

  -- Expired, still unresolved: in progress, not expired.
  err = raised(function()
    server:verify_credential_with_expected(credential(challenge, 'tx-a'), expected, later)
  end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  -- It landed: the same credential is granted once, never re-broadcast.
  local receipt = server:verify_credential_with_expected(credential(challenge, 'tx-a'), expected, later)
  t.assert_equal(receipt.reference, 'sig-tx-a')
  t.assert_equal(sends(), 1)
  err = raised(function()
    server:verify_credential_with_expected(credential(challenge, 'tx-a'), expected, later)
  end)
  t.assert_equal(err.code, error_codes.SIGNATURE_CONSUMED)

  -- An expired credential never starts a payment.
  local fresh, fresh_expected = issue('fresh')
  err = raised(function()
    server:verify_credential_with_expected(credential(fresh, 'tx-b'), fresh_expected, later)
  end)
  t.assert_equal(err.code, error_codes.CHALLENGE_EXPIRED)
  t.assert_equal(sends(), 1)

  -- Nor reconciles a pending charge another challenge left behind.
  local owner, owner_expected = issue('owner')
  err = raised(function() server:verify_credential_with_expected(credential(owner, 'tx-c'), owner_expected) end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  local other, other_expected = issue('other')
  err = raised(function()
    server:verify_credential_with_expected(credential(other, 'tx-c'), other_expected, later)
  end)
  t.assert_equal(err.code, error_codes.CHALLENGE_EXPIRED)
end)

-- Without the reconcile hook an expired challenge is refused outright and
-- never reaches `verify_payment`, which would start a new payment.
t.test('expired challenge never reaches verify_payment', function()
  local mpp = require('tests._mpp')
  local called = false
  local server = mpp.server.new({
    recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h', currency = 'USDC', decimals = 6,
    network = 'localnet', secret_key = 'expiry-test-secret-key-long-enough-32b', realm = 'MPP',
    verify_payment = function() called = true return { reference = 'x' } end,
  })
  local challenge = server:charge_with_options('1.00', { expires = '2030-01-01T00:00:00Z' })
  local expected = challenge.request:decode()
  local err = raised(function()
    server:verify_credential_with_expected(
      mpp.NewPaymentCredential(challenge:to_echo(), { type = 'transaction', transaction = 'tx' }),
      expected, os.time({ year = 2031, month = 1, day = 1, hour = 0 }))
  end)
  t.assert_equal(err.code, error_codes.CHALLENGE_EXPIRED)
  t.assert_true(not called, 'verify_payment must not run for an expired challenge')
end)

-- Rolling upgrade: an MPP replica on the previous release claims and checks
-- only `solana-charge:consumed:<sig>`. Every claim takes that key too, so such
-- a replica refuses a payment this release accepted; a release gives it back.
t.test('a claim is visible to MPP replicas on the previous release', function()
  local consumed_signatures = require('pay_kit.consumed_signatures')
  for _, shared in ipairs({ require('pay_kit.store').memory(), require('pay_kit.protocols.mpp.store').memory() }) do
    local ledger = consumed_signatures.new(shared)
    t.assert_true(ledger:claim('sig-new'))
    t.assert_true(not shared:put_if_absent('solana-charge:consumed:sig-new', true),
      'a previous-release replica could claim a signature this release accepted')
    ledger:release('sig-new')
    t.assert_true(not shared:get('solana-charge:consumed:sig-new'), 'release left the legacy key behind')
    t.assert_true(ledger:claim('sig-new'))

    -- A refused claim gives back the legacy key it took.
    shared:put_if_absent(consumed_signatures.key('sig-held'), true)
    t.assert_true(not ledger:claim('sig-held'))
    t.assert_true(not shared:get('solana-charge:consumed:sig-held'))
  end
end)

-- A signature copied from any landed transaction must not name the charge:
-- the node refuses a forged one without a preflight result, so it would be
-- kept as possibly sent and reconciled on the status of the transaction that
-- owns it. The default verifier refuses it before anything is claimed or sent.
t.test('a forged client signature is refused before it is claimed', function()
  local ed25519 = require('pay_kit.util.ed25519')
  local base64 = require('pay_kit.util.base64_std')
  local secret = ed25519.generate()
  if not secret then return end -- no luasodium: the backend cannot mint keys here
  local public = ed25519.derive_public(secret)
  -- Legacy message: header (1 signer), one account key, blockhash, no instructions.
  local message = string.char(1, 0, 0) .. string.char(1) .. public .. string.rep('\9', 32) .. string.char(0)
  local function wire(signature)
    return base64.encode(string.char(1) .. signature .. message)
  end
  local signed = wire(assert(ed25519.sign(secret, message)))
  local forged = wire(string.rep('\7', 64))

  local replay = store.memory()
  local rpc = fake_rpc({
    simulateTransaction = { { result = { err = nil } } },
    sendTransaction = { { result = 'sent' } },
    getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed' } } } },
  })
  local handler = charge_handler.new({
    rpc = rpc, network = 'localnet', replay_store = replay,
    transaction_verifier = function() end,
    sleep = function() end,
  })
  for _ = 1, 2 do
    local err = raised(function() handler:settle_pull(forged, {}, 'ch') end)
    t.assert_true(tostring(err.message):find('signature verification failed', 1, true) ~= nil, tostring(err.message))
  end
  t.assert_equal(#rpc.calls, 0)

  -- Positive control: the same transaction, really signed, passes the check
  -- and reaches simulation.
  pcall(function() handler:settle_pull(signed, {}, 'ch') end)
  t.assert_equal(rpc.calls[1] and rpc.calls[1].method, 'simulateTransaction')
end)

-- Pending records are namespaced per SDK. Go records its pending charges as
-- `solana-charge:pending:<sig>`; Lua must not mistake one for its own and
-- grant a payment the Go replica owns (and grants itself).
t.test('a pending charge another SDK recorded is not reconciled here', function()
  local replay = store.memory()
  require('pay_kit.consumed_signatures').new(replay):claim('sig-go')
  replay:put_if_absent('solana-charge:pending:sig-go', '{"challengeId":"go-challenge"}')
  local handler = new_handler({
    replay_store = replay,
    pull_signature_extractor = function() return 'sig-go' end,
    rpc = fake_rpc({
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed' } } } },
    }),
  })
  local err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.SIGNATURE_CONSUMED)
end)

-- The pending record a retry reconciles is written with the claim, before
-- anything is sent: written after an ambiguous send, a store failure would
-- strand a payment that may have landed (claimed, with nothing to reconcile).
t.test('the pending record is written before anything is sent', function()
  local inner = store.memory()
  local failing = true
  local flaky = setmetatable({
    put_if_absent = function(self, key, value)
      if failing and key:find('charge-pending', 1, true) then error('injected store outage') end
      return inner:put_if_absent(key, value)
    end,
  }, { __index = function(_, k) return function(_, ...) return inner[k](inner, ...) end end })
  local handler, rpc = new_handler({
    replay_store = flaky,
    pull_signature_extractor = function() return 'sig-recorded' end,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { error = { code = 'transport-error', message = 'response lost' } } },
    }),
  })
  local err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_true(tostring(err):find('injected store outage', 1, true) ~= nil, tostring(err))
  t.assert_equal(#rpc.calls, 0)
  local _, claimed = inner:get('solana:consumed-signature:sig-recorded')
  t.assert_true(not claimed, 'nothing was sent, so the claim is given back')

  failing = false
  err = raised(function() handler:settle_pull('tx', {}, 'ch') end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  local _, pending = inner:get('pay-kit:lua:charge-pending:sig-recorded:ch')
  t.assert_true(pending, 'an ambiguous send leaves a pending record')
end)

-- A durable claim is kept for a bounded retention, so push mode only accepts
-- a landed payment well inside it: once its claim expired, an older payment
-- could otherwise be presented again under a fresh challenge.
t.test('settle_push refuses a payment older than the claim retention', function()
  local json = require('pay_kit.util.json')
  local store_mod = require('pay_kit.store')
  for _, case in ipairs({
    { block_time = os.time() - store_mod.DURABLE_RETENTION_SECONDS, err = 'too old' },
    { block_time = json.null, err = 'no block time' },
  }) do
    local replay = store.memory()
    local handler = new_handler({
      replay_store = replay,
      accept_push_mode = true,
      rpc = fake_rpc({
        getTransaction = { { result = { meta = { err = nil }, transaction = { 'old-b64', 'base64' }, blockTime = case.block_time } } },
      }),
    })
    t.assert_error(function() handler:settle_push('sig-old', {}) end, case.err)
    local _, claimed = replay:get('solana:consumed-signature:sig-old')
    t.assert_true(not claimed, 'an old payment is refused before it is claimed')
  end
end)

-- ─── Pending charges are bound to their challenge (PR #386) ──────────────

local function count_calls(rpc, method)
  local n = 0
  for _, call in ipairs(rpc.calls) do
    if call.method == method then n = n + 1 end
  end
  return n
end

-- Anyone can copy a landed transaction's bytes. Presented under their own
-- same-terms challenge while the payer's request is confirming, they must not
-- reconcile (and win the grant for) the payer's pending charge: the payer
-- would be charged and refused as SIGNATURE_CONSUMED.
t.test('a pending charge is not reconciled under another challenge', function()
  local handler, rpc = new_handler({
    pull_signature_extractor = function() return 'sig-copied' end,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { error = { code = 'transport-error', message = 'response lost' } } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed' } } } },
    }),
  })
  local err = raised(function() handler:settle_pull('tx', {}, 'ch-payer') end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)

  -- The same bytes under another challenge: a replay, never reconciled.
  err = raised(function() handler:settle_pull('tx', {}, 'ch-copier') end)
  t.assert_equal(err.code, error_codes.SIGNATURE_CONSUMED)
  t.assert_equal(count_calls(rpc, 'getSignatureStatuses'), 0)

  -- Positive control: the payer's own retry reconciles and gets its delivery.
  t.assert_equal(handler:settle_pull('tx', {}, 'ch-payer'), 'sig-copied')
  err = raised(function() handler:settle_pull('tx', {}, 'ch-copier') end)
  t.assert_equal(err.code, error_codes.SIGNATURE_CONSUMED)
end)

t.test('settle_pull refuses a transaction without a challenge to bind it to', function()
  local handler, rpc = new_handler({ rpc = fake_rpc({}) })
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'missing challenge id')
  t.assert_error(function() handler:settle_pull('tx', {}, '') end, 'missing challenge id')
  t.assert_equal(#rpc.calls, 0)
end)

local function push_landed_tx()
  return { result = { meta = { err = require('pay_kit.util.json').null },
    transaction = { 'landed-b64', 'base64' }, blockTime = os.time() } }
end

-- A concurrent retry of the same credential can reconcile the landed
-- transaction and be granted while the owner request is still simulating or
-- sending. If the owner then fails (an already-processed simulation or
-- preflight error) it must not hand the claim back: a push credential for the
-- same signature would be granted a second time.
for _, case in ipairs({
  { name = 'simulation', fail_in = 'simulateTransaction' },
  { name = 'preflight', fail_in = 'sendTransaction' },
}) do
  t.test('abandon after a concurrent grant keeps the claim (' .. case.name .. ')', function()
    local replay = store.memory()
    local handler, retry
    local function concurrent_retry()
      retry = handler:settle_pull('tx', {}, 'ch-payer')
    end
    local responses = {
      simulateTransaction = { { result = { err = nil } } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed' } } } },
      getTransaction = { push_landed_tx() },
    }
    if case.fail_in == 'simulateTransaction' then
      responses.simulateTransaction = { function()
        concurrent_retry()
        return { err = 'AlreadyProcessed' }
      end }
    else
      responses.sendTransaction = { function()
        concurrent_retry()
        error({ code = 'rpc-error', rpc_code = -32002,
                message = 'Transaction simulation failed: This transaction has already been processed' })
      end }
    end
    handler = new_handler({
      replay_store = replay,
      pull_signature_extractor = function() return 'sig-landed' end,
      rpc = fake_rpc(responses),
    })
    local err = raised(function() handler:settle_pull('tx', {}, 'ch-payer') end)
    t.assert_true(tostring(err.message):find('Simulation failed', 1, true) ~= nil, tostring(err.message))
    t.assert_equal(retry, 'sig-landed')
    local _, claimed = replay:get('solana:consumed-signature:sig-landed')
    t.assert_true(claimed, 'a granted payment must stay claimed')

    err = raised(function() handler:settle_push('sig-landed', {}) end)
    t.assert_equal(err.code, error_codes.SIGNATURE_CONSUMED)
  end)
end

-- Positive control: with no grant, a failed simulation gives the claim back,
-- so the same signature is accepted once afterwards.
t.test('abandon without a grant releases the claim', function()
  local replay = store.memory()
  local handler = new_handler({
    replay_store = replay,
    pull_signature_extractor = function() return 'sig-unsent' end,
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = 'InsufficientFundsForFee' } } },
      getTransaction = { push_landed_tx() },
    }),
  })
  t.assert_error(function() handler:settle_pull('tx', {}, 'ch-payer') end, 'Simulation failed')
  local _, claimed = replay:get('solana:consumed-signature:sig-unsent')
  t.assert_true(not claimed, 'an unsent transaction must be released')
  t.assert_equal(handler:settle_push('sig-unsent', {}), 'sig-unsent')
end)

-- A retry that read the binding before the owner abandoned the charge, and
-- reaches the grant after the claim was given back, must not be granted:
-- the released signature could then be granted again through another path.
t.test('a retry is not granted after the owner released the claim', function()
  local replay = store.memory()
  local owner
  local handler = new_handler({
    replay_store = replay,
    pull_signature_extractor = function() return 'sig-raced' end,
    rpc = fake_rpc({
      simulateTransaction = { function()
        coroutine.yield()
        return { err = 'AlreadyProcessed' }
      end },
      getSignatureStatuses = { function()
        -- The owner finishes (and abandons) while this retry awaits the status.
        t.assert_true(coroutine.resume(owner))
        t.assert_equal(coroutine.status(owner), 'dead')
        return { { confirmationStatus = 'confirmed' } }
      end },
      getTransaction = { push_landed_tx(), push_landed_tx() },
    }),
  })
  owner = coroutine.create(function()
    local ok = pcall(handler.settle_pull, handler, 'tx', {}, 'ch-payer')
    t.assert_true(not ok, 'the owner abandons')
  end)
  t.assert_true(coroutine.resume(owner))

  local err = raised(function() handler:settle_pull('tx', {}, 'ch-payer') end)
  t.assert_equal(err.code, error_codes.SIGNATURE_CONSUMED)
  -- The claim was given back, and the payment is granted exactly once.
  t.assert_equal(handler:settle_push('sig-raced', {}), 'sig-raced')
  err = raised(function() handler:settle_push('sig-raced', {}) end)
  t.assert_equal(err.code, error_codes.SIGNATURE_CONSUMED)
end)
