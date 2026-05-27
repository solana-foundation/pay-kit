local t = require('tests.test_helper')
local mpp = require('tests._mpp')

local function new_server()
  return mpp.server.new({
    recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
    currency = 'USDC',
    decimals = 6,
    network = 'localnet',
    secret_key = 'test-secret',
    store = mpp.store.memory(),
    verify_payment = function(context)
      if context.payload.type == 'signature' then
        return { reference = context.payload.signature }
      end
      return { reference = context.payload.transaction }
    end,
  })
end

t.test('server charge builds challenge', function()
  local server = new_server()
  local challenge = server:charge_with_options('0.001', {
    description = 'demo',
    external_id = 'order-1',
  })
  t.assert_equal(challenge.method, 'solana')
  t.assert_equal(challenge.intent, 'charge')
  t.assert_true(challenge.realm ~= '')
  local request = challenge.request:decode()
  t.assert_equal(request.amount, '1000')
  t.assert_equal(request.currency, 'USDC')
  t.assert_equal(request.externalId, 'order-1')
end)

t.test('verify credential success', function()
  local server = new_server()
  local challenge = server:charge('0.001')
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), {
    type = 'signature',
    signature = '5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv',
  })
  local receipt = server:verify_credential(credential, 1770000000)
  t.assert_equal(receipt.status, 'success')
  t.assert_equal(receipt.challengeId, challenge.id)
end)

t.test('verify credential rejects replay', function()
  local server = new_server()
  local challenge = server:charge('0.001')
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), {
    type = 'signature',
    signature = 'already-seen',
  })
  server:verify_credential(credential, 1770000000)
  t.assert_error(function()
    server:verify_credential(credential, 1770000000)
  end, 'payment already consumed')
end)

t.test('verify credential rejects expired challenge', function()
  local server = new_server()
  local challenge = server:charge_with_options('0.001', {
    expires = '2020-01-01T00:00:00Z',
  })
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), {
    type = 'signature',
    signature = 'sig',
  })
  t.assert_error(function()
    server:verify_credential(credential, 1770000000)
  end, 'challenge expired')
end)

t.test('verify credential rejects challenge mismatch', function()
  local server = new_server()
  local request = mpp.NewBase64URLJSONValue({
    amount = '1000',
    currency = 'USDC',
    recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
  })
  local challenge = mpp.NewChallengeWithSecret('wrong-secret', 'realm', 'solana', 'charge', request)
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), {
    type = 'signature',
    signature = 'sig',
  })
  t.assert_error(function()
    server:verify_credential(credential, 1770000000)
  end, 'challenge ID mismatch')
end)

t.test('verify credential rejects sponsored push mode', function()
  local server = mpp.server.new({
    recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
    currency = 'USDC',
    decimals = 6,
    network = 'localnet',
    secret_key = 'test-secret',
    fee_payer = true,
    verify_payment = function(context)
      return { reference = context.payload.signature or context.payload.transaction }
    end,
  })
  local challenge = server:charge('0.001')
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), {
    type = 'signature',
    signature = 'sig',
  })
  t.assert_error(function()
    server:verify_credential(credential, 1770000000)
  end, 'server.side fee payer')
end)

t.test('verify credential requires verification callback', function()
  local server = mpp.server.new({
    recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
    secret_key = 'test-secret',
  })
  local challenge = server:charge('1')
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), {
    type = 'signature',
    signature = 'sig',
  })
  t.assert_error(function()
    server:verify_credential(credential, 1770000000)
  end, 'verify_payment callback is required')
end)

t.test('verify credential accepts transaction payload when lua verifier hooks are used', function()
  local server = mpp.server.new({
    recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
    currency = 'sol',
    decimals = 9,
    secret_key = 'test-secret',
    verifier_hooks = (function()
      local pull_tx = {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              {
                program = 'system',
                parsed = {
                  type = 'transfer',
                  info = {
                    destination = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
                    lamports = '1000000000',
                  },
                },
              },
            },
          },
        },
      }
      return {
        parse_transaction = function(transaction)
          t.assert_equal(transaction, 'deadbeef')
          return pull_tx.transaction
        end,
        send_transaction = function(transaction)
          t.assert_equal(transaction, 'deadbeef')
          return 'sig-transaction'
        end,
        await_transaction = function(signature)
          t.assert_equal(signature, 'sig-transaction')
          return pull_tx
        end,
      }
    end)(),
  })
  local challenge = server:charge('1')
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), {
    type = 'transaction',
    transaction = 'deadbeef',
  })
  local receipt = server:verify_credential(credential, 1770000000)
  t.assert_equal(receipt.reference, 'sig-transaction')
end)

-- ─── charge_with_options Tier-0 splits guards ────────────────────────────
-- These mirror the cross-SDK fault matrix's G28 scenarios. The verifier
-- already rejects an on-chain transaction whose splits consume the full
-- amount, but rejecting at challenge issuance lets the harness see the
-- canonical 402 + payment_invalid pair without having to broadcast first.

t.test('charge_with_options rejects splits whose sum equals the amount', function()
  local server = new_server()
  local ok, err = pcall(function()
    server:charge_with_options('0.001', {
      splits = {
        { recipient = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU', amount = '1000' },
      },
    })
  end)
  t.assert_true(not ok, 'expected splits-sum-equals-amount to raise')
  t.assert_equal(type(err) == 'table' and err.code, 'payment_invalid')
  t.assert_true(tostring(err.message):match('split amounts exceed total amount') ~= nil)
end)

t.test('charge_with_options rejects splits whose sum exceeds the amount', function()
  local server = new_server()
  local ok, err = pcall(function()
    server:charge_with_options('0.001', {
      splits = {
        { recipient = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU', amount = '999' },
        { recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h', amount = '2' },
      },
    })
  end)
  t.assert_true(not ok, 'expected splits-over-amount to raise')
  t.assert_equal(type(err) == 'table' and err.code, 'payment_invalid')
end)

t.test('charge_with_options rejects more than 8 splits at issuance', function()
  local server = new_server()
  local splits = {}
  for _ = 1, 9 do
    splits[#splits + 1] = { recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h', amount = '1' }
  end
  local ok, err = pcall(function()
    server:charge_with_options('0.001', { splits = splits })
  end)
  t.assert_true(not ok, 'expected too-many-splits to raise')
  t.assert_equal(type(err) == 'table' and err.code, 'payment_invalid')
  t.assert_true(tostring(err.message):match('too many splits') ~= nil)
end)

t.test('charge_with_options accepts splits whose sum is strictly under the amount', function()
  local server = new_server()
  local challenge = server:charge_with_options('0.001', {
    splits = {
      { recipient = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU', amount = '250' },
    },
  })
  local request = challenge.request:decode()
  t.assert_equal(request.amount, '1000')
  t.assert_equal(request.methodDetails.splits[1].amount, '250')
end)

t.test('charge_with_options threads explicit token_program override into methodDetails', function()
  -- Token-2022 scenarios that use an arbitrary mint pubkey (not in the
  -- KNOWN_MINTS table) need a way to tell the SDK which token program
  -- owns the mint without modifying the stablecoin allowlist. Mirrors the
  -- TOKEN_2022_PROGRAM threading path the lua interop adapter takes when
  -- MPP_INTEROP_TOKEN_PROGRAM is set.
  local server = new_server()
  local challenge = server:charge_with_options('0.001', {
    token_program = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  })
  local request = challenge.request:decode()
  t.assert_equal(request.methodDetails.tokenProgram, 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
end)
