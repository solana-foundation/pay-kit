local t = require('tests.test_helper')
local mpp = require('tests._mpp')

local function new_server()
  return mpp.server.new({
    recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
    currency = 'USDC',
    decimals = 6,
    network = 'localnet',
    secret_key = 'test-secret-key-long-enough-for-hmac',
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
    secret_key = 'test-secret-key-long-enough-for-hmac',
    fee_payer = true,
    -- Audit #16: feePayer=true now requires a fee_payer_key at boot.
    fee_payer_key = '9yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
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
    secret_key = 'test-secret-key-long-enough-for-hmac',
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
    secret_key = 'test-secret-key-long-enough-for-hmac',
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
  -- TOKEN_2022_PROGRAM threading path the lua harness adapter takes when
  -- MPP_HARNESS_TOKEN_PROGRAM is set.
  local server = new_server()
  local challenge = server:charge_with_options('0.001', {
    token_program = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  })
  local request = challenge.request:decode()
  t.assert_equal(request.methodDetails.tokenProgram, 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
end)

local VALID_RECIPIENT = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h'
local SPLIT_A = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'
local SPLIT_B = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ'

local function server_with(overrides)
  local cfg = {
    recipient = VALID_RECIPIENT,
    currency = 'USDC',
    decimals = 6,
    network = 'localnet',
    secret_key = 'test-secret-key-long-enough-for-hmac',
    store = mpp.store.memory(),
    verify_payment = function(context)
      return { reference = context.payload.signature or context.payload.transaction }
    end,
  }
  for k, v in pairs(overrides or {}) do cfg[k] = v end
  return mpp.server.new(cfg)
end

-- Audit #24: weak secret key.
t.test('audit #24: rejects secret key shorter than 32 bytes', function()
  t.assert_error(function()
    server_with({ secret_key = 'short-secret' })
  end, 'at least 32 bytes')
end)

t.test('audit #24: accepts secret key at the 32-byte minimum', function()
  local server = server_with({ secret_key = string.rep('a', 32) })
  t.assert_true(server ~= nil)
end)

t.test('audit #24: MPP_SECRET_KEY env path is also length-gated', function()
  local real = os.getenv
  os.getenv = function(name)  -- luacheck: ignore
    if name == 'MPP_SECRET_KEY' then return 'tiny' end
    return real(name)
  end
  local ok = pcall(function()
    mpp.server.new({ recipient = VALID_RECIPIENT, network = 'localnet' })
  end)
  os.getenv = real  -- luacheck: ignore
  t.assert_true(not ok, 'expected short env secret to be rejected')
end)

-- Audit #15: per-recipient default realm.
t.test('audit #15: default realm is derived per-recipient (not the shared default)', function()
  local a = server_with({ recipient = VALID_RECIPIENT })
  local b = server_with({ recipient = SPLIT_B })
  t.assert_true(a.realm ~= 'MPP Payment')
  t.assert_true(a.realm ~= b.realm)
  -- Deterministic for the same recipient.
  local a2 = server_with({ recipient = VALID_RECIPIENT })
  t.assert_equal(a.realm, a2.realm)
end)

t.test('audit #15: explicit empty realm is rejected', function()
  t.assert_error(function()
    server_with({ realm = '' })
  end, 'non%-empty')
end)

-- Audit #37: network allowlist.
t.test('audit #37: rejects unknown network slug at boot', function()
  t.assert_error(function()
    server_with({ network = 'testnet' })
  end, 'unsupported network')
end)

t.test('audit #37: rejects the mainnet-beta alias at boot', function()
  t.assert_error(function()
    server_with({ network = 'mainnet-beta' })
  end, 'unsupported network')
end)

t.test('audit #37: accepts the three canonical networks', function()
  for _, net in ipairs({ 'mainnet', 'devnet', 'localnet' }) do
    local server = server_with({ network = net })
    t.assert_equal(server.network, net)
  end
end)

-- Audit #16: feePayer=true requires a key.
t.test('audit #16: rejects fee_payer=true without a fee_payer_key at boot', function()
  t.assert_error(function()
    server_with({ fee_payer = true })
  end, 'requires fee_payer_key')
end)

t.test('audit #16: accepts fee_payer=true with a fee_payer_key and emits both fields', function()
  local server = server_with({ fee_payer = true, fee_payer_key = SPLIT_A })
  local request = server:charge('0.001').request:decode()
  t.assert_equal(request.methodDetails.feePayer, true)
  t.assert_equal(request.methodDetails.feePayerKey, SPLIT_A)
end)

t.test('audit #16: per-call fee_payer override without a key is rejected', function()
  local server = server_with({})
  t.assert_error(function()
    server:charge_with_options('0.001', { fee_payer = true })
  end, 'requires a fee_payer_key')
end)

-- Audit #21: split validation at issuance.
t.test('audit #21: rejects a zero-amount split', function()
  local server = server_with({})
  t.assert_error(function()
    server:charge_with_options('0.001', {
      splits = {{ recipient = SPLIT_A, amount = '0' }},
    })
  end, 'greater than zero')
end)

t.test('audit #21: rejects an unparseable split recipient', function()
  local server = server_with({})
  t.assert_error(function()
    server:charge_with_options('0.001', {
      splits = {{ recipient = 'not-a-pubkey', amount = '10' }},
    })
  end, 'valid Solana address')
end)

t.test('audit #21: rejects duplicate split recipients', function()
  local server = server_with({})
  t.assert_error(function()
    server:charge_with_options('0.001', {
      splits = {
        { recipient = SPLIT_A, amount = '10' },
        { recipient = SPLIT_A, amount = '20' },
      },
    })
  end, 'duplicate split recipient')
end)

-- Audit #38: primary recipient + ataCreationRequired.
t.test('audit #38: rejects primary recipient in splits with ataCreationRequired', function()
  local server = server_with({})
  t.assert_error(function()
    server:charge_with_options('0.010', {
      splits = {{ recipient = VALID_RECIPIENT, amount = '10', ataCreationRequired = true }},
    })
  end, 'primary recipient cannot appear in splits')
end)

t.test('audit #38: allows primary recipient in splits without ataCreationRequired', function()
  local server = server_with({})
  local request = server:charge_with_options('0.010', {
    splits = {{ recipient = VALID_RECIPIENT, amount = '10' }},
  }).request:decode()
  t.assert_equal(request.methodDetails.splits[1].recipient, VALID_RECIPIENT)
end)

-- Audit #28: arbitrary-mint token program resolution.
t.test('audit #28: arbitrary mint currency without token_program is rejected at boot', function()
  -- A 32-byte base58 pubkey not in KNOWN_MINTS: cannot guess the program.
  t.assert_error(function()
    server_with({ currency = SPLIT_B })
  end, 'arbitrary mint')
end)

t.test('audit #28: arbitrary mint resolves via an explicit token_program', function()
  local server = server_with({
    currency = SPLIT_B,
    token_program = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  })
  local request = server:charge('0.001').request:decode()
  t.assert_equal(request.methodDetails.tokenProgram, 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
end)

t.test('audit #28: arbitrary mint resolves via a token_program_resolver hook', function()
  local server = server_with({
    currency = SPLIT_B,
    token_program_resolver = function(_mint)
      return 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
    end,
  })
  local request = server:charge('0.001').request:decode()
  t.assert_equal(request.methodDetails.tokenProgram, 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
end)

t.test('audit #28: known stablecoin still resolves from the static table', function()
  local server = server_with({ currency = 'PYUSD' })
  local request = server:charge('0.001').request:decode()
  t.assert_equal(request.methodDetails.tokenProgram, 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
end)
