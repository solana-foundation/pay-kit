--[[
Regression coverage for MPP charge verifier parity with the Rust spine
(rust/crates/mpp/src/server/charge.rs).

Each test asserts rust-matching behaviour that the pre-fix Lua verifier
did not implement:

  * transferChecked decimals byte pinned to method_details.decimals
    (charge.rs:1623-1624)
  * fee-payer's own token account cannot fund the SPL payment, even under
    a different authority (charge.rs:1649-1657)
  * inner / CPI instructions from meta.innerInstructions are matched on
    the confirmed-transaction path (charge.rs:2218-2230)
]]

local t = require('tests.test_helper')
local verify = require('pay_kit.protocols.mpp.server.solana_verify')
local base58 = require('pay_kit.solana.base58')
local ata = require('pay_kit.solana.ata')

local TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'

local function key(byte)
  return base58.encode(string.rep(string.char(byte), 32))
end

-- ── decimals pinning ──────────────────────────────────────────────

t.test('parity: SPL transferChecked with wrong decimals does not match', function()
  local context = {
    payload = { type = 'signature', signature = 'sig-dec' },
    request = {
      amount = '2500', currency = 'mint-1', recipient = 'recipient-1',
      methodDetails = { tokenProgram = TOKEN_PROGRAM, decimals = 6 },
    },
    method_details = { tokenProgram = TOKEN_PROGRAM, decimals = 6 },
  }
  local tx = {
    meta = { err = nil },
    transaction = { message = { instructions = {
      {
        programId = TOKEN_PROGRAM,
        parsed = { type = 'transferChecked', info = {
          source = 'sender-ata', destination = 'token-account-1',
          mint = 'mint-1', authority = 'sender-1',
          tokenAmount = { amount = '2500', decimals = 9 },  -- wrong decimals
        } },
      },
    } } },
  }
  t.assert_error(function()
    verify.verify_signature(context, {
      fetch_transaction = function() return tx end,
      fetch_token_account = function()
        return { owner = 'recipient-1', mint = 'mint-1' }
      end,
    })
  end, 'no matching token transfer')
end)

t.test('parity: SPL transferChecked with matching decimals is accepted', function()
  local context = {
    payload = { type = 'signature', signature = 'sig-dec-ok' },
    request = {
      amount = '2500', currency = 'mint-1', recipient = 'recipient-1',
      methodDetails = { tokenProgram = TOKEN_PROGRAM, decimals = 6 },
    },
    method_details = { tokenProgram = TOKEN_PROGRAM, decimals = 6 },
  }
  local tx = {
    meta = { err = nil },
    transaction = { message = { instructions = {
      {
        programId = TOKEN_PROGRAM,
        parsed = { type = 'transferChecked', info = {
          source = 'sender-ata', destination = 'token-account-1',
          mint = 'mint-1', authority = 'sender-1',
          tokenAmount = { amount = '2500', decimals = 6 },
        } },
      },
    } } },
  }
  local result = verify.verify_signature(context, {
    fetch_transaction = function() return tx end,
    fetch_token_account = function()
      return { owner = 'recipient-1', mint = 'mint-1' }
    end,
  })
  t.assert_equal(result.reference, 'sig-dec-ok')
end)

-- ── fee-payer source-ATA guard ────────────────────────────────────

t.test('parity: fee-payer token account cannot fund the SPL transfer', function()
  local fee_payer = key(7)
  local mint = key(4)
  local fee_payer_ata = ata.derive(fee_payer, mint, TOKEN_PROGRAM)
  local context = {
    payload = { type = 'transaction', transaction = 'base64-tx' },
    request = {
      amount = '2500', currency = mint, recipient = 'recipient-1',
      methodDetails = {
        tokenProgram = TOKEN_PROGRAM, feePayer = true, feePayerKey = fee_payer,
      },
    },
    method_details = {
      tokenProgram = TOKEN_PROGRAM, feePayer = true, feePayerKey = fee_payer,
    },
  }
  -- Source is the fee-payer's ATA, authority is a DIFFERENT key — only the
  -- source-ATA guard (not the authority guard) can catch this drain.
  local drain_tx = {
    meta = { err = nil },
    transaction = { message = { instructions = {
      {
        programId = TOKEN_PROGRAM,
        parsed = { type = 'transferChecked', info = {
          source = fee_payer_ata, destination = 'token-account-1',
          mint = mint, authority = 'sender-1',
          tokenAmount = { amount = '2500' },
        } },
      },
    } } },
  }
  local send_calls = 0
  t.assert_error(function()
    verify.verify_transaction(context, {
      parse_transaction = function() return drain_tx.transaction end,
      send_transaction = function() send_calls = send_calls + 1; return 'sig' end,
      await_transaction = function() return drain_tx end,
      fetch_token_account = function()
        return { owner = 'recipient-1', mint = mint }
      end,
    })
  end, 'payment_invalid')
  t.assert_equal(send_calls, 0, 'pre-broadcast policy must reject before send')
end)

-- ── inner (CPI) instructions on the confirmed path ────────────────

t.test('parity: confirmed transaction matches payment emitted via inner CPI', function()
  local context = {
    payload = { type = 'signature', signature = 'sig-cpi' },
    request = {
      amount = '1000', currency = 'sol', recipient = 'recipient-1',
      methodDetails = {},
    },
    method_details = {},
  }
  -- The top-level instruction list carries no payment; the SOL transfer is
  -- emitted as an inner CPI. Pre-fix this failed to match.
  local tx = {
    meta = {
      err = nil,
      innerInstructions = {
        { instructions = {
          {
            program = 'system',
            parsed = { type = 'transfer', info = {
              destination = 'recipient-1', lamports = '1000',
            } },
          },
        } },
      },
    },
    transaction = { message = { instructions = {} } },
  }
  local result = verify.verify_signature(context, {
    fetch_transaction = function() return tx end,
  })
  t.assert_equal(result.reference, 'sig-cpi')
end)
