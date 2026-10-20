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
  local signature = handler:settle_pull('tx-b64', { amount = '1' })
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
  local signature = handler:settle_pull('tx-b64', { amount = '1' })
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
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'bad shape')
  t.assert_equal(#rpc.calls, 0)
end)

t.test('settle_pull network gate rejects surfpool tx against mainnet', function()
  local handler = new_handler({
    network = 'mainnet',
    pull_blockhash_extractor = function() return 'SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxxxxxxx' end,
  })
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'localnet')
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
  t.assert_equal(handler:settle_pull('tx', {}), 'sig')
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
  handler:settle_pull('original-tx', {})
  t.assert_equal(rpc.calls[1].tx, 'cosigned-tx')
end)

t.test('settle_pull surfaces cosign failure as verification error', function()
  local handler = new_handler({
    pull_transaction_signer = function() error('signer offline') end,
  })
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'cosign failed')
end)

t.test('settle_pull rejects empty cosign result', function()
  local handler = new_handler({
    pull_transaction_signer = function() return '' end,
  })
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'empty transaction')
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
  t.assert_equal(handler:settle_pull('tx', {}), 'sig')
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
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'Simulation failed')
end)

t.test('settle_pull fails when simulation reports program error', function()
  local handler = new_handler({
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = 'InsufficientFunds' } } },
    }),
    simulation_max_attempts = 1,
  })
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'InsufficientFunds')
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
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'Timed out waiting')
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
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'already consumed')
end)

t.test('settle_pull surfaces transaction failure during confirmation', function()
  local handler = new_handler({
    rpc = fake_rpc({
      simulateTransaction = { { result = { err = nil } } },
      sendTransaction = { { result = 'sig' } },
      getSignatureStatuses = { { result = { { confirmationStatus = 'confirmed', err = 'AccountInUse' } } } },
    }),
  })
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'AccountInUse')
end)

t.test('settle_pull times out when confirmation status never reaches confirmed', function()
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
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'Timed out waiting')
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

  local err = raised(function() handler:settle_pull('tx', {}) end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  local _v, claimed = replay:get('solana:consumed-signature:sig-lost')
  t.assert_true(claimed, 'the possibly-sent signature must stay claimed')

  -- Not visible yet: still pending, never failed.
  err = raised(function() handler:settle_pull('tx', {}) end)
  t.assert_equal(err.code, error_codes.SETTLEMENT_IN_PROGRESS)
  -- It landed: the identical retry is granted, once.
  t.assert_equal(handler:settle_pull('tx', {}), 'sig-lost')
  err = raised(function() handler:settle_pull('tx', {}) end)
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
  local err = raised(function() handler:settle_pull('tx', {}) end)
  t.assert_equal(err.code, error_codes.PAYMENT_INVALID)
  t.assert_true(tostring(err.message):match('Simulation failed') ~= nil, tostring(err.message))
  local _v, claimed = replay:get('solana:consumed-signature:sig-rejected')
  t.assert_true(not claimed, 'an unsent transaction must be released')
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

  t.assert_equal(handler:settle_pull('tx', {}), 'mpp-paid')
  t.assert_equal(x402_private.claim_signature(shared, shared, 'mpp-paid'), 'consumed')

  t.assert_equal(x402_private.claim_signature(shared, shared, 'x402-paid'), 'claimed')
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'already consumed')

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
  t.assert_error(function() handler:settle_pull('tx', {}) end, 'already consumed')
end)

t.test('PayKit adapters resolve one ledger store for MPP and x402', function()
  local consumed_signatures = require('pay_kit.consumed_signatures')
  local dispatcher_store, operator_store = {}, {}
  t.assert_equal(consumed_signatures.shared_store({ mpp = {} }, dispatcher_store), dispatcher_store)
  t.assert_equal(consumed_signatures.shared_store(
    { mpp = { replay_store = operator_store } }, dispatcher_store), operator_store)
end)

t.test('pay_kit.store keeps a consumed-signature claim with no expiry', function()
  local memory = require('pay_kit.store').memory()
  t.assert_true(memory:put_if_absent('durable', true))
  t.assert_true(memory:put_if_absent('leased', 15))
  t.assert_equal(memory._entries.durable, math.huge)
  t.assert_true(memory._entries.leased < math.huge)
  t.assert_true(not memory:put_if_absent('durable', true))
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
      getTransaction = { { result = { meta = { err = nil }, transaction = { 'on-chain-b64', 'base64' } } } },
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
        { result = { meta = { err = nil }, transaction = { 'tx-b64', 'base64' } } },
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
        { result = { meta = { err = nil }, transaction = { 'tx-b64', 'base64' } } },
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
      getTransaction = { { result = { meta = { err = nil }, transaction = { 'tx', 'base64' } } } },
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
      getTransaction = { { result = { meta = { err = nil }, transaction = { 'tx', 'base64' } } } },
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
  t.assert_equal(handler:settle({ type = 'transaction', transaction = 'tx' }, {}), 'pull-sig')
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
  local result = cb({ payload = { type = 'transaction', transaction = 'tx' }, request = {} })
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
