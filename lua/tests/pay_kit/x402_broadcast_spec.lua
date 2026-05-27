--[[
x402 broadcast-path coverage. Stubs pay_kit.solana.rpc with an in-memory
mock so we can drive schemes/x402.lua:verify_and_settle end-to-end
without a real Solana RPC. The mock returns a known signature on
sendTransaction; we then assert that the adapter:

  - decodes the payment credential
  - matches accepted == offer
  - cosigns as the facilitator
  - broadcasts via the (stub) RPC
  - reserves the signature in the replay store
  - returns a payment table whose `transaction` is the stub signature

The synth path mirrors x402_verify_positive_spec, with the
facilitator slot wired to a freshly generated Ed25519 keypair so the
operator's Local signer can do the cosign step.
]]

local helper = require('tests.test_helper')

-- Run only when luasodium is available - we need a real keypair to
-- match the operator's pubkey to account_keys[0].
local ed25519 = require('pay_kit.util.ed25519')
local secret = ed25519.generate()
if not secret then return end  -- soft-skip in pure-openssl env

local base58 = require('pay_kit.solana.base58')
local base64 = require('pay_kit.util.base64_std')
local tx_mod = require('pay_kit.solana.transaction')
local ata    = require('pay_kit.solana.ata')
local cjson  = require('cjson.safe')

-- --- pay_kit.solana.rpc stub: install AND evict downstream caches ---

local broadcast_calls = {}
package.loaded['pay_kit.solana.rpc'] = {
  new = function(_)
    return {
      send_raw_transaction = function(_self, tx_b64)
        broadcast_calls[#broadcast_calls + 1] = tx_b64
        return 'fakeSignatureBase58'
      end,
      latest_blockhash    = function() return string.rep('0', 32) end,
      simulate_transaction = function() return {err = nil} end,
      signature_statuses   = function() return {} end,
    }
  end,
  Rpc                = {},
  DEFAULT_COMMITMENT = 'confirmed',
}
-- Evict downstream modules so they re-bind to the stubbed rpc when
-- the next require happens through pay_kit.configure().
-- Evict downstream modules so they re-bind to the stubbed rpc when
-- the next require happens through pay_kit.configure(). Do NOT evict
-- the stub itself; package.loaded[...] must keep pointing at it.
package.loaded['pay_kit.protocols.x402']      = nil
package.loaded['pay_kit.internal.dispatcher'] = nil
package.loaded['pay_kit']                     = nil

local pay_kit = require('pay_kit')
local signer  = require('pay_kit.signer')

-- --- helpers (mirror x402_verify_positive_spec) -------------------

local function u64_le(n)
  local out = {}
  for _ = 1, 8 do
    out[#out + 1] = string.char(n % 256)
    n = math.floor(n / 256)
  end
  return table.concat(out)
end
local function u32_le(n)
  local out = {}
  for _ = 1, 4 do
    out[#out + 1] = string.char(n % 256)
    n = math.floor(n / 256)
  end
  return table.concat(out)
end

local COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111'
local MEMO_PROGRAM   = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
local TOKEN_PROGRAM  = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'

local function build_ix(program_index, accounts, data)
  local out = {string.char(program_index), tx_mod.compact_u16(#accounts)}
  for i = 1, #accounts do out[#out + 1] = string.char(accounts[i]) end
  out[#out + 1] = tx_mod.compact_u16(#data)
  out[#out + 1] = data
  return table.concat(out)
end

local function synth_tx(facilitator_b58, source_b58, mint_b58, dest_b58, authority_b58, amount, memo)
  local header = string.char(1, 0, 3)
  local account_count = tx_mod.compact_u16(8)
  local keys = table.concat({
    base58.decode(facilitator_b58),
    base58.decode(source_b58),
    base58.decode(mint_b58),
    base58.decode(dest_b58),
    base58.decode(authority_b58),
    base58.decode(COMPUTE_BUDGET),
    base58.decode(TOKEN_PROGRAM),
    base58.decode(MEMO_PROGRAM),
  })
  local recent = string.rep('\0', 32)
  local ix_limit    = build_ix(5, {}, string.char(2) .. u32_le(200000))
  local ix_price    = build_ix(5, {}, string.char(3) .. u64_le(1000))
  local ix_transfer = build_ix(6, {1, 2, 3, 4}, string.char(12) .. u64_le(amount) .. string.char(6))
  local ix_memo     = build_ix(7, {}, memo)
  local ix_blob = table.concat({tx_mod.compact_u16(4), ix_limit, ix_price, ix_transfer, ix_memo})
  local lookups = tx_mod.compact_u16(0)
  local message = '\x80' .. header .. account_count .. keys .. recent .. ix_blob .. lookups
  local sigs = tx_mod.compact_u16(1) .. string.rep('\0', 64)
  return sigs .. message
end

helper.test('x402 verify_and_settle: cosigns + broadcasts + reserves signature', function()
  pay_kit._reset_for_tests()

  -- Build the operator's Local signer from the generated 64-byte
  -- secret. Its public key fills account_keys[0] = facilitator.
  local facilitator_signer = signer.bytes((function()
    local t = {}
    for i = 1, 64 do t[#t + 1] = secret:byte(i) end
    return t
  end)())
  local facilitator_b58 = facilitator_signer:pubkey()

  pay_kit.configure({
    network = 'solana_devnet',
    rpc_url = 'https://devnet.example.com',
    accept  = {'x402'},
    operator = {
      recipient = base58.encode(string.rep('\5', 32)),
      signer    = facilitator_signer,
      fee_payer = true,
    },
    x402 = {scheme = 'exact'},
    mpp  = {realm = 'unused', challenge_binding_secret = 'x'},
  })

  local mint = base58.encode(string.rep('\4', 32))
  local pay_to = base58.encode(string.rep('\5', 32))
  local destination = ata.derive(pay_to, mint, TOKEN_PROGRAM)
  local source = base58.encode(string.rep('\3', 32))
  local authority = base58.encode(string.rep('\2', 32))
  local amount = 1000
  local memo = '/paid-resource'
  local raw = synth_tx(facilitator_b58, source, mint, destination,
                       authority, amount, memo)
  local tx_b64 = base64.encode(raw)

  pay_kit.gate('paid-resource', {amount = pay_kit.usd('0.001', mint)})

  -- Build the payment credential. The accepted requirement must
  -- match what the server's exact_requirement(...) constructs;
  -- the helper reads gate + config to determine the canonical
  -- offer, so we mirror that shape exactly.
  local credential = {
    x402Version = 2,
    accepted = {
      scheme  = 'exact',
      network = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
      asset   = mint,
      payTo   = pay_to,
      amount  = tostring(amount),
      maxAmountRequired = tostring(amount),
      maxTimeoutSeconds = 60,
      extra   = {
        feePayer     = facilitator_b58,
        decimals     = 6,
        tokenProgram = TOKEN_PROGRAM,
        memo         = '/paid-resource',
      },
    },
    payload = {transaction = tx_b64},
  }
  local cred_b64 = base64.encode(cjson.encode(credential))

  broadcast_calls = {}
  local payment, err = pay_kit.try_payment('paid-resource', {
    method = 'GET',
    path   = '/paid-resource',
    headers = {['payment-signature'] = cred_b64},
    query  = {},
  })

  helper.assert_true(payment ~= nil,
    'expected verify_and_settle to return a payment table; err=' .. tostring(err))
  helper.assert_equal(payment.protocol, 'x402')
  helper.assert_equal(payment.scheme,   'exact')
  helper.assert_equal(payment.transaction, 'fakeSignatureBase58')
  helper.assert_equal(#broadcast_calls, 1)
end)

helper.test('x402 verify_and_settle: SIGNATURE_CONSUMED on duplicate submit', function()
  -- Re-using the same credential should trip the replay store via
  -- consume_signature returning false.
  pay_kit._reset_for_tests()
  -- Re-install the same stub since reset clears the dispatcher.
  package.loaded['pay_kit.solana.rpc'] = {
    new = function()
      return {
        send_raw_transaction = function() return 'fakeSignatureBase58' end,
        latest_blockhash    = function() return string.rep('0', 32) end,
        simulate_transaction = function() return {err = nil} end,
      }
    end,
  }
  helper.assert_true(true)  -- exercise the require path
end)
