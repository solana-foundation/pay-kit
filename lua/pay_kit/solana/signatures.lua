--[[
Client-signature verification for a parsed Solana transaction.

A server must refuse, before it claims, co-signs or sends a transaction, one
whose signatures do not authorize this message (RULINGS SIG1). A signature
that does not verify names some other transaction: a server that keys its
replay or pending record on it and reconciles by its on-chain status serves
the resource for a payment that never happened.

The rule, checked here once for every caller (MPP charge verification, the
charge settle path, x402 exact verification):

  * the signature list has exactly `header.required_signatures` entries;
  * every slot verifies over the message bytes under the matching account
    key, except the slots of keys the server signs itself (its fee payer),
    which are still empty before it co-signs.
]]

local base58 = require('pay_kit.solana.base58')
local ed25519 = require('pay_kit.util.ed25519')

local M = {}

local EMPTY_SIGNATURE = string.rep('\0', 64)

--- Verify `tx` (as returned by `pay_kit.solana.transaction.from_bytes` /
--- `from_base64`). `server_signers` lists the base58 keys whose slots the
--- server fills itself; they are skipped. Returns true, or nil and a reason.
function M.check(tx, server_signers)
  local skip = {}
  for _, key in ipairs(server_signers or {}) do
    skip[key] = true
  end
  local required = tx.message.header.required_signatures
  local signatures = tx.signatures
  if #signatures ~= required then
    return nil, string.format('the message requires %d signatures but the transaction carries %d',
      required, #signatures)
  end
  local keys = tx.message.account_keys
  if required > #keys then
    return nil, 'the message requires more signatures than it has account keys'
  end
  for i = 1, required do
    local key = keys[i]
    if not skip[key] then
      local signature = signatures[i]
      if signature == EMPTY_SIGNATURE then
        return nil, 'signature slot ' .. (i - 1) .. ' (' .. key .. ') is empty'
      end
      if not ed25519.verify(base58.decode(key), tx.message.raw, signature) then
        return nil, 'signature slot ' .. (i - 1) .. ' (' .. key .. ') does not verify over the message'
      end
    end
  end
  return true
end

return M
