local t = require('tests.test_helper')
local verify = require('mpp.server.solana_verify')
local mpp = require('mpp')
local MEMO_PROGRAM = mpp.protocol.solana.MEMO_PROGRAM

local function signature_context(overrides)
  local base = {
    payload = {
      type = 'signature',
      signature = 'sig-123',
    },
    request = {
      amount = '1000',
      currency = 'sol',
      recipient = 'recipient-1',
      methodDetails = {},
    },
    method_details = {},
  }
  for key, value in pairs(overrides or {}) do
    base[key] = value
  end
  return base
end

t.test('signature verifier succeeds for native SOL transfer', function()
  local result = verify.verify_signature(signature_context(), {
    fetch_transaction = function(signature)
      t.assert_equal(signature, 'sig-123')
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              {
                program = 'system',
                parsed = {
                  type = 'transfer',
                  info = {
                    destination = 'recipient-1',
                    lamports = '1000',
                  },
                },
              },
            },
          },
        },
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
end)

t.test('signature verifier succeeds with externalId memo', function()
  local result = verify.verify_signature(signature_context({
    request = {
      amount = '1000',
      currency = 'sol',
      externalId = 'order-123',
      recipient = 'recipient-1',
      methodDetails = {},
    },
    method_details = {},
  }), {
    fetch_transaction = function()
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-1', lamports = '1000' } } },
              { program = 'spl-memo', parsed = 'order-123' },
            },
          },
        },
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
end)

t.test('signature verifier accepts memo parsed as info.memo', function()
  local result = verify.verify_signature(signature_context({
    request = {
      amount = '1000',
      currency = 'sol',
      externalId = 'order-123',
      recipient = 'recipient-1',
      methodDetails = {},
    },
    method_details = {},
  }), {
    fetch_transaction = function()
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-1', lamports = '1000' } } },
              { programId = MEMO_PROGRAM, parsed = { info = { memo = 'order-123' } } },
            },
          },
        },
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
end)

t.test('signature verifier accepts split memo', function()
  local context = signature_context({
    request = {
      amount = '1000',
      currency = 'sol',
      recipient = 'recipient-1',
      methodDetails = {
        splits = {
          { recipient = 'recipient-2', amount = '200', memo = 'platform fee' },
        },
      },
    },
    method_details = {
      splits = {
        { recipient = 'recipient-2', amount = '200', memo = 'platform fee' },
      },
    },
  })
  local result = verify.verify_signature(context, {
    fetch_transaction = function()
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-1', lamports = '800' } } },
              { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-2', lamports = '200' } } },
              { programId = MEMO_PROGRAM, parsed = { info = { data = 'platform fee' } } },
            },
          },
        },
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
end)

t.test('signature verifier rejects missing externalId memo', function()
  t.assert_error(function()
    verify.verify_signature(signature_context({
      request = {
        amount = '1000',
        currency = 'sol',
        externalId = 'order-123',
        recipient = 'recipient-1',
        methodDetails = {},
      },
      method_details = {},
    }), {
      fetch_transaction = function()
        return {
          meta = { err = nil },
          transaction = {
            message = {
              instructions = {
                { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-1', lamports = '1000' } } },
              },
            },
          },
        }
      end,
    })
  end, 'No memo instruction found for externalId memo')
end)

t.test('signature verifier rejects unexpected memo', function()
  t.assert_error(function()
    verify.verify_signature(signature_context(), {
      fetch_transaction = function()
        return {
          meta = { err = nil },
          transaction = {
            message = {
              instructions = {
                { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-1', lamports = '1000' } } },
                { program = 'spl-memo', parsed = 'unexpected' },
              },
            },
          },
        }
      end,
    })
  end, 'unexpected Memo Program instruction')
end)

t.test('transaction verifier broadcasts and verifies confirmed transfer', function()
  local sent = nil
  local tx_shape = {
    meta = { err = nil },
    transaction = {
      message = {
        instructions = {
          {
            program = 'system',
            parsed = {
              type = 'transfer',
              info = {
                destination = 'recipient-1',
                lamports = '1000',
              },
            },
          },
        },
      },
    },
  }
  local result = verify.verify_transaction({
    payload = {
      type = 'transaction',
      transaction = 'base64-tx',
    },
    request = {
      amount = '1000',
      currency = 'sol',
      recipient = 'recipient-1',
      methodDetails = {},
    },
    method_details = {},
  }, {
    parse_transaction = function(transaction)
      t.assert_equal(transaction, 'base64-tx')
      return tx_shape.transaction
    end,
    send_transaction = function(transaction)
      sent = transaction
      return 'sig-456'
    end,
    await_transaction = function(signature)
      t.assert_equal(signature, 'sig-456')
      return tx_shape
    end,
  })
  t.assert_equal(sent, 'base64-tx')
  t.assert_equal(result.reference, 'sig-456')
end)

t.test('signature verifier succeeds for SPL transfer using token account lookup', function()
  local context = signature_context({
    request = {
      amount = '2500',
      currency = 'mint-1',
      recipient = 'recipient-1',
      methodDetails = {
        tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      },
    },
    method_details = {
      tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
    },
  })

  local result = verify.verify_signature(context, {
    fetch_transaction = function()
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              {
                programId = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                parsed = {
                  type = 'transferChecked',
                  info = {
                    destination = 'token-account-1',
                    mint = 'mint-1',
                    tokenAmount = { amount = '2500' },
                  },
                },
              },
            },
          },
        },
      }
    end,
    fetch_token_account = function(address)
      t.assert_equal(address, 'token-account-1')
      return {
        owner = 'recipient-1',
        mint = 'mint-1',
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
end)

t.test('signature verifier resolves USDC alias for localnet', function()
  local context = signature_context({
    request = {
      amount = '2500',
      currency = 'USDC',
      recipient = 'recipient-1',
      methodDetails = {
        network = 'localnet',
        tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      },
    },
    method_details = {
      network = 'localnet',
      tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
    },
  })

  local result = verify.verify_signature(context, {
    fetch_transaction = function()
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              {
                programId = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                parsed = {
                  type = 'transferChecked',
                  info = {
                    destination = 'token-account-1',
                    mint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
                    tokenAmount = { amount = '2500' },
                  },
                },
              },
            },
          },
        },
      }
    end,
    fetch_token_account = function(address)
      t.assert_equal(address, 'token-account-1')
      return {
        owner = 'recipient-1',
        mint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
end)

t.test('signature verifier defaults USDG alias to Token-2022', function()
  local context = signature_context({
    request = {
      amount = '2500',
      currency = 'USDG',
      recipient = 'recipient-1',
      methodDetails = {
        network = 'mainnet-beta',
      },
    },
    method_details = {
      network = 'mainnet-beta',
    },
  })

  local result = verify.verify_signature(context, {
    fetch_transaction = function()
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              {
                programId = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
                parsed = {
                  type = 'transferChecked',
                  info = {
                    destination = 'token-account-1',
                    mint = '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH',
                    tokenAmount = { amount = '2500' },
                  },
                },
              },
            },
          },
        },
      }
    end,
    fetch_token_account = function(address)
      t.assert_equal(address, 'token-account-1')
      return {
        owner = 'recipient-1',
        mint = '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH',
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
end)

t.test('signature verifier supports split transfers', function()
  local context = signature_context({
    request = {
      amount = '1000',
      currency = 'sol',
      recipient = 'recipient-1',
      methodDetails = {
        splits = {
          { recipient = 'recipient-2', amount = '200' },
          { recipient = 'recipient-3', amount = '100' },
        },
      },
    },
    method_details = {
      splits = {
        { recipient = 'recipient-2', amount = '200' },
        { recipient = 'recipient-3', amount = '100' },
      },
    },
  })
  local result = verify.verify_signature(context, {
    fetch_transaction = function()
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-1', lamports = '700' } } },
              { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-2', lamports = '200' } } },
              { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-3', lamports = '100' } } },
            },
          },
        },
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
end)

t.test('signature verifier matches same-recipient SOL transfers by amount', function()
  local context = signature_context({
    request = {
      amount = '1000',
      currency = 'sol',
      recipient = 'recipient-2',
      methodDetails = {
        splits = {
          { recipient = 'recipient-2', amount = '200' },
        },
      },
    },
    method_details = {
      splits = {
        { recipient = 'recipient-2', amount = '200' },
      },
    },
  })
  local result = verify.verify_signature(context, {
    fetch_transaction = function()
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-2', lamports = '800' } } },
              { program = 'system', parsed = { type = 'transfer', info = { destination = 'recipient-2', lamports = '200' } } },
            },
          },
        },
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
end)

t.test('signature verifier matches same-recipient SPL transfers by amount', function()
  local context = signature_context({
    request = {
      amount = '1000',
      currency = 'mint-1',
      recipient = 'recipient-2',
      methodDetails = {
        tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
        splits = {
          { recipient = 'recipient-2', amount = '200' },
        },
      },
    },
    method_details = {
      tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      splits = {
        { recipient = 'recipient-2', amount = '200' },
      },
    },
  })

  local calls = 0
  local result = verify.verify_signature(context, {
    fetch_transaction = function()
      return {
        meta = { err = nil },
        transaction = {
          message = {
            instructions = {
              {
                programId = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                parsed = {
                  type = 'transferChecked',
                  info = {
                    destination = 'token-account-primary',
                    mint = 'mint-1',
                    tokenAmount = { amount = '800' },
                  },
                },
              },
              {
                programId = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                parsed = {
                  type = 'transferChecked',
                  info = {
                    destination = 'token-account-split',
                    mint = 'mint-1',
                    tokenAmount = { amount = '200' },
                  },
                },
              },
            },
          },
        },
      }
    end,
    fetch_token_account = function(_)
      calls = calls + 1
      return {
        owner = 'recipient-2',
        mint = 'mint-1',
      }
    end,
  })
  t.assert_equal(result.reference, 'sig-123')
  t.assert_equal(calls, 2)
end)

t.test('signature verifier rejects missing signature', function()
  t.assert_error(function()
    verify.verify_signature(signature_context({
      payload = { type = 'signature' },
    }), {
      fetch_transaction = function()
        return nil
      end,
    })
  end, 'missing signature')
end)

t.test('transaction verifier rejects missing transaction payload', function()
  t.assert_error(function()
    verify.verify_transaction({
      payload = { type = 'transaction' },
      request = {
        amount = '1000',
        currency = 'sol',
        recipient = 'recipient-1',
        methodDetails = {},
      },
      method_details = {},
    }, {
      send_transaction = function()
        return 'sig-123'
      end,
      await_transaction = function()
        return nil
      end,
    })
  end, 'missing transaction')
end)

t.test('signature verifier rejects missing transaction result', function()
  t.assert_error(function()
    verify.verify_signature(signature_context(), {
      fetch_transaction = function()
        return nil
      end,
    })
  end, 'transaction not found')
end)

t.test('signature verifier rejects failed transactions', function()
  t.assert_error(function()
    verify.verify_signature(signature_context(), {
      fetch_transaction = function()
        return {
          meta = { err = { InstructionError = { 0, 'Custom' } } },
          transaction = { message = { instructions = {} } },
        }
      end,
    })
  end, 'transaction failed on%-chain')
end)

t.test('signature verifier rejects missing SOL transfer', function()
  t.assert_error(function()
    verify.verify_signature(signature_context(), {
      fetch_transaction = function()
        return {
          meta = { err = nil },
          transaction = { message = { instructions = {} } },
        }
      end,
    })
  end, 'no matching SOL transfer')
end)

t.test('signature verifier rejects missing token account callback', function()
  t.assert_error(function()
    verify.verify_signature(signature_context({
      request = {
        amount = '1000',
        currency = 'mint-1',
        recipient = 'recipient-1',
        methodDetails = {},
      },
      method_details = {},
    }), {
      fetch_transaction = function()
        return {
          meta = { err = nil },
          transaction = { message = { instructions = {} } },
        }
      end,
    })
  end, 'fetch_token_account callback is required')
end)

t.test('signature verifier rejects unmatched token owner', function()
  t.assert_error(function()
    verify.verify_signature(signature_context({
      request = {
        amount = '2500',
        currency = 'mint-1',
        recipient = 'recipient-1',
        methodDetails = {
          tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
        },
      },
      method_details = {
        tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      },
    }), {
      fetch_transaction = function()
        return {
          meta = { err = nil },
          transaction = {
            message = {
              instructions = {
                {
                  programId = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                  parsed = {
                    type = 'transferChecked',
                    info = {
                      destination = 'token-account-1',
                      mint = 'mint-1',
                      tokenAmount = { amount = '2500' },
                    },
                  },
                },
              },
            },
          },
        }
      end,
      fetch_token_account = function()
        return {
          owner = 'wrong-owner',
          mint = 'mint-1',
        }
      end,
    })
  end, 'no matching token transfer')
end)

t.test('signature verifier handles transaction payload mode through pull verification', function()
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
                destination = 'recipient-1',
                lamports = '1000',
              },
            },
          },
        },
      },
    },
  }
  local verifier = verify.new_signature_verifier({
    parse_transaction = function(transaction)
      t.assert_equal(transaction, 'deadbeef')
      return pull_tx.transaction
    end,
    send_transaction = function(transaction)
      t.assert_equal(transaction, 'deadbeef')
      return 'sig-pull'
    end,
    await_transaction = function(signature)
      t.assert_equal(signature, 'sig-pull')
      return pull_tx
    end,
  })
  local result = verifier(signature_context({
    payload = {
      type = 'transaction',
      transaction = 'deadbeef',
    },
  }))
  t.assert_equal(result.reference, 'sig-pull')
end)

t.test('server can wire verifier hooks automatically', function()
  local server = mpp.server.new({
    recipient = 'recipient-1',
    currency = 'sol',
    decimals = 9,
    network = 'localnet',
    secret_key = 'test-secret',
    verifier_hooks = {
      fetch_transaction = function(signature)
        t.assert_equal(signature, 'sig-123')
        return {
          meta = { err = nil },
          transaction = {
            message = {
              instructions = {
                {
                  program = 'system',
                  parsed = {
                    type = 'transfer',
                    info = {
                      destination = 'recipient-1',
                      lamports = '1',
                    },
                  },
                },
              },
            },
          },
        }
      end,
    },
  })
  local challenge = server:charge('0.000000001')
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), {
    type = 'signature',
    signature = 'sig-123',
  })
  local receipt = server:verify_credential(credential, 1770000000)
  t.assert_equal(receipt.reference, 'sig-123')
end)

-- B34: push-mode credentials must be rejected on fee-payer routes. A
-- signature-only credential references an already-landed transaction the
-- client paid the fee for, defeating the server-funded charge. Reject
-- before any RPC call. Mirrors Rust spine and Ruby / PHP #100 / Python #106.

t.test('B34: rejects signature credential when method_details.feePayer is true', function()
  local fetch_called = false
  t.assert_error(function()
    verify.verify_signature(signature_context({
      method_details = { feePayer = true, feePayerKey = 'fee-payer-1' },
    }), {
      fetch_transaction = function()
        fetch_called = true
        return nil
      end,
    })
  end, 'Push%-mode credentials are not allowed')
  t.assert_equal(fetch_called, false, 'B34 must reject before fetch_transaction is called')
end)

-- SECURITY (PR #102 codex P1 mirror of Python PR #106 6925f4e + 5bf71d9):
-- on fee-payer-enabled SPL routes the instruction allowlist must reject any
-- SystemProgram::Transfer sourced from the fee-payer pubkey. Without this
-- guard a malicious client appends an extra system transfer FROM fee-payer
-- TO an attacker on top of a valid SPL payment; the SPL verifier passes
-- (required transferChecked is present), the allowlist accepts SYSTEM_PROGRAM,
-- and the server co-signs the entire transaction, draining fee-payer SOL.
t.test('SECURITY: rejects extra SystemProgram transfer sourced from fee-payer on SPL route', function()
  local context = signature_context({
    payload = { type = 'transaction', transaction = 'base64-tx' },
    request = {
      amount = '2500',
      currency = 'mint-1',
      recipient = 'recipient-1',
      methodDetails = {
        tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
        feePayer = true,
        feePayerKey = 'fee-payer-1',
      },
    },
    method_details = {
      tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      feePayer = true,
      feePayerKey = 'fee-payer-1',
    },
  })
  local drain_tx = {
    meta = { err = nil },
    transaction = {
      message = {
        instructions = {
          {
            programId = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
            parsed = {
              type = 'transferChecked',
              info = {
                source = 'sender-ata',
                destination = 'token-account-1',
                mint = 'mint-1',
                authority = 'sender-1',
                tokenAmount = { amount = '2500' },
              },
            },
          },
          -- Attacker-appended drain: fee-payer SOL to attacker address.
          {
            program = 'system',
            parsed = {
              type = 'transfer',
              info = {
                source = 'fee-payer-1',
                destination = 'attacker',
                lamports = '5000000000',
              },
            },
          },
        },
      },
    },
  }
  local send_calls = 0
  t.assert_error(function()
    verify.verify_transaction(context, {
      parse_transaction = function() return drain_tx.transaction end,
      send_transaction = function() send_calls = send_calls + 1; return 'sig-drain' end,
      await_transaction = function() return drain_tx end,
      fetch_token_account = function()
        return { owner = 'recipient-1', mint = 'mint-1' }
      end,
    })
  end, 'payment_invalid')
  -- Pre-broadcast guard must reject BEFORE send_transaction is called.
  t.assert_equal(send_calls, 0, 'send_transaction must not be called when pre-broadcast policy rejects')
end)

t.test('SECURITY: rejects SPL transferChecked authorized by fee-payer on SPL route', function()
  -- Same shape, different lever: attacker funds the required transferChecked
  -- itself FROM the fee-payer token account (authority = fee-payer). Mirrors
  -- Python test_spl_drain_with_fee_payer_ata_as_source_is_rejected.
  local context = signature_context({
    payload = { type = 'transaction', transaction = 'base64-tx' },
    request = {
      amount = '2500',
      currency = 'mint-1',
      recipient = 'recipient-1',
      methodDetails = {
        tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
        feePayer = true,
        feePayerKey = 'fee-payer-1',
      },
    },
    method_details = {
      tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      feePayer = true,
      feePayerKey = 'fee-payer-1',
    },
  })
  local drain_tx2 = {
    meta = { err = nil },
    transaction = {
      message = {
        instructions = {
          {
            programId = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
            parsed = {
              type = 'transferChecked',
              info = {
                source = 'fee-payer-ata',
                destination = 'token-account-1',
                mint = 'mint-1',
                authority = 'fee-payer-1',
                tokenAmount = { amount = '2500' },
              },
            },
          },
        },
      },
    },
  }
  local send_calls2 = 0
  t.assert_error(function()
    verify.verify_transaction(context, {
      parse_transaction = function() return drain_tx2.transaction end,
      send_transaction = function() send_calls2 = send_calls2 + 1; return 'sig-drain' end,
      await_transaction = function() return drain_tx2 end,
      fetch_token_account = function()
        return { owner = 'recipient-1', mint = 'mint-1' }
      end,
    })
  end, 'payment_invalid')
  t.assert_equal(send_calls2, 0, 'send_transaction must not be called when pre-broadcast policy rejects')
end)

t.test('SECURITY: accepts SPL payment + ComputeBudget on fee-payer route', function()
  -- Positive control: a legitimate SPL payment + ComputeBudget + fee-payer
  -- co-sign must still pass. Mirrors Python
  -- test_legitimate_spl_payment_with_fee_payer_cosign_is_accepted.
  local context = signature_context({
    payload = { type = 'transaction', transaction = 'base64-tx' },
    request = {
      amount = '2500',
      currency = 'mint-1',
      recipient = 'recipient-1',
      methodDetails = {
        tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
        feePayer = true,
        feePayerKey = 'fee-payer-1',
      },
    },
    method_details = {
      tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      feePayer = true,
      feePayerKey = 'fee-payer-1',
    },
  })
  local ok_tx = {
    meta = { err = nil },
    transaction = {
      message = {
        instructions = {
          {
            programId = 'ComputeBudget111111111111111111111111111111',
            parsed = { type = 'setComputeUnitLimit', info = { units = 100000 } },
          },
          {
            programId = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
            parsed = {
              type = 'transferChecked',
              info = {
                source = 'sender-ata',
                destination = 'token-account-1',
                mint = 'mint-1',
                authority = 'sender-1',
                tokenAmount = { amount = '2500' },
              },
            },
          },
        },
      },
    },
  }
  local result = verify.verify_transaction(context, {
    parse_transaction = function() return ok_tx.transaction end,
    send_transaction = function() return 'sig-ok' end,
    await_transaction = function() return ok_tx end,
    fetch_token_account = function()
      return { owner = 'recipient-1', mint = 'mint-1' }
    end,
  })
  t.assert_equal(result.reference, 'sig-ok')
end)

t.test('SECURITY: accepts SystemProgram transfer to recipient from non-fee-payer source', function()
  -- Mixed-route negative-of-negative: fee-payer is configured (SPL route),
  -- but the extra system transfer sources from a non-fee-payer account, so
  -- it does not drain server funds. The allowlist must accept it. (The SPL
  -- verifier handles the required transferChecked; the extra system transfer
  -- is below the allowlist's drain guard.)
  local context = signature_context({
    payload = { type = 'transaction', transaction = 'base64-tx' },
    request = {
      amount = '2500',
      currency = 'mint-1',
      recipient = 'recipient-1',
      methodDetails = {
        tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
        feePayer = true,
        feePayerKey = 'fee-payer-1',
      },
    },
    method_details = {
      tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      feePayer = true,
      feePayerKey = 'fee-payer-1',
    },
  })
  local ok2_tx = {
    meta = { err = nil },
    transaction = {
      message = {
        instructions = {
          {
            programId = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
            parsed = {
              type = 'transferChecked',
              info = {
                source = 'sender-ata',
                destination = 'token-account-1',
                mint = 'mint-1',
                authority = 'sender-1',
                tokenAmount = { amount = '2500' },
              },
            },
          },
          {
            program = 'system',
            parsed = {
              type = 'transfer',
              info = {
                source = 'sender-1',
                destination = 'recipient-1',
                lamports = '1000',
              },
            },
          },
        },
      },
    },
  }
  local result = verify.verify_transaction(context, {
    parse_transaction = function() return ok2_tx.transaction end,
    send_transaction = function() return 'sig-ok2' end,
    await_transaction = function() return ok2_tx end,
    fetch_token_account = function()
      return { owner = 'recipient-1', mint = 'mint-1' }
    end,
  })
  t.assert_equal(result.reference, 'sig-ok2')
end)

t.test('B34: signature verifier path runs when feePayer is absent', function()
  -- Sanity check: B34 must not fire when feePayer is not set. The fetch
  -- callback must be reached. Returning nil ends in a downstream
  -- 'transaction not found' error which is the correct downstream concern.
  local fetch_called = false
  t.assert_error(function()
    verify.verify_signature(signature_context(), {
      fetch_transaction = function()
        fetch_called = true
        return nil
      end,
    })
  end, 'transaction not found')
  t.assert_equal(fetch_called, true, 'verifier must reach fetch_transaction when feePayer is absent')
end)

-- SECURITY (PR #102 codex round 3 P1): pre-broadcast compute-budget cap.
-- A malicious client that sets SetComputeUnitLimit above the cap must be
-- rejected BEFORE send_transaction; the previous post-broadcast ordering
-- let the transaction land on-chain before policy fired.
t.test('SECURITY: rejects compute-budget over cap pre-broadcast', function()
  local context = signature_context({
    payload = { type = 'transaction', transaction = 'base64-tx' },
    request = {
      amount = '1000',
      currency = 'sol',
      recipient = 'recipient-1',
      methodDetails = {},
    },
    method_details = {},
  })
  local over_cap_tx = {
    meta = { err = nil },
    transaction = {
      message = {
        instructions = {
          {
            programId = 'ComputeBudget111111111111111111111111111111',
            parsed = { type = 'setComputeUnitLimit', info = { units = 5000000 } },
          },
          {
            program = 'system',
            parsed = {
              type = 'transfer',
              info = { destination = 'recipient-1', lamports = '1000' },
            },
          },
        },
      },
    },
  }
  local send_calls = 0
  t.assert_error(function()
    verify.verify_transaction(context, {
      parse_transaction = function() return over_cap_tx.transaction end,
      send_transaction = function() send_calls = send_calls + 1; return 'sig-evil' end,
      await_transaction = function() return over_cap_tx end,
    })
  end, 'compute unit limit exceeds cap')
  t.assert_equal(send_calls, 0, 'send_transaction must not be called when pre-broadcast policy rejects')
end)

t.test('SECURITY: rejects unknown program instruction pre-broadcast', function()
  local context = signature_context({
    payload = { type = 'transaction', transaction = 'base64-tx' },
    request = {
      amount = '1000',
      currency = 'sol',
      recipient = 'recipient-1',
      methodDetails = {},
    },
    method_details = {},
  })
  local unknown_tx = {
    meta = { err = nil },
    transaction = {
      message = {
        instructions = {
          {
            program = 'system',
            parsed = {
              type = 'transfer',
              info = { destination = 'recipient-1', lamports = '1000' },
            },
          },
          {
            programId = 'NotAnAllowedProgram1111111111111111111111111',
            parsed = { type = 'mystery' },
          },
        },
      },
    },
  }
  local send_calls = 0
  t.assert_error(function()
    verify.verify_transaction(context, {
      parse_transaction = function() return unknown_tx.transaction end,
      send_transaction = function() send_calls = send_calls + 1; return 'sig-evil' end,
      await_transaction = function() return unknown_tx end,
    })
  end, 'Unexpected program instruction')
  t.assert_equal(send_calls, 0, 'send_transaction must not be called when pre-broadcast policy rejects')
end)

t.test('SECURITY: requires parse_transaction hook for pull-mode pre-broadcast policy', function()
  local context = signature_context({
    payload = { type = 'transaction', transaction = 'base64-tx' },
    request = {
      amount = '1000',
      currency = 'sol',
      recipient = 'recipient-1',
      methodDetails = {},
    },
    method_details = {},
  })
  t.assert_error(function()
    verify.verify_transaction(context, {
      send_transaction = function() return 'sig' end,
      await_transaction = function() return nil end,
    })
  end, 'parse_transaction callback is required')
end)

-- Codex round 3 P2: result.consumed=true must NOT be set when context.store
-- is nil (no replay marker actually written). Without this fix the server's
-- outer put_if_absent guard would also be skipped, silently disabling replay
-- protection. Mirrors the Python L4 lock direction.
t.test('SECURITY: result.consumed is not set when context.store is absent', function()
  local ok_tx = {
    meta = { err = nil },
    transaction = {
      message = {
        instructions = {
          {
            program = 'system',
            parsed = {
              type = 'transfer',
              info = { destination = 'recipient-1', lamports = '1000' },
            },
          },
        },
      },
    },
  }
  local result = verify.verify_transaction({
    payload = { type = 'transaction', transaction = 'base64-tx' },
    request = {
      amount = '1000',
      currency = 'sol',
      recipient = 'recipient-1',
      methodDetails = {},
    },
    method_details = {},
    -- NOTE: no `store` on purpose.
  }, {
    parse_transaction = function() return ok_tx.transaction end,
    send_transaction = function() return 'sig-no-store' end,
    await_transaction = function() return ok_tx end,
  })
  t.assert_equal(result.reference, 'sig-no-store')
  t.assert_equal(result.consumed, nil, 'must not claim consumed when no replay marker was written')
  t.assert_equal(result.replay_key, nil)
end)

