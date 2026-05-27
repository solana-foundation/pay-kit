--[[
Network / blockhash sanity check.

The Surfpool localnet implementation embeds a recognizable prefix into
every blockhash it returns. We use this to catch the common footgun where
a client signs a transaction against a Surfpool RPC and submits it to a
server configured for a real cluster (mainnet/devnet).

The check is asymmetric:

  - If the blockhash starts with the Surfpool prefix, the transaction
    was DEFINITELY signed against a Surfpool localnet. The only network
    slug for which that's valid is `localnet` — any other slug must
    reject the credential up-front.

  - If the blockhash does NOT start with the Surfpool prefix, we can't
    tell what cluster it came from (real localnet doesn't add a prefix
    either), so we accept it.

The Lua server delegates transaction decoding to user-provided
`verify_payment` callbacks (since Lua has no built-in Solana SDK), so this
module exposes a pure check that callback authors must invoke once they
have the blockhash in hand.
]]

local error_codes = require('pay_kit.protocol.core.error_codes')

local M = {}

--- Base58 prefix embedded in every blockhash returned by the Surfpool
--- localnet implementation.
M.SURFPOOL_BLOCKHASH_PREFIX = 'SURFNETxSAFEHASH'

--- Network slug for Solana's local validator. The only network for which
--- a Surfpool-prefixed blockhash is valid.
M.LOCALNET_NETWORK = 'localnet'

--- Pure check: returns nil if the blockhash is acceptable for the given
--- network, or an error table `{ code = 'wrong-network', message = '...' }`
--- if a Surfpool-prefixed blockhash is being submitted to a server
--- configured for any network other than `localnet`.
---
--- A non-Surfpool blockhash is accepted on any network because we can't
--- tell which real cluster it came from.
---
--- @param network string Server-configured network slug.
--- @param blockhash_b58 string Base58-encoded recent blockhash from the signed tx.
--- @return table|nil err Error table on mismatch, nil on success.
function M.check_network_blockhash(network, blockhash_b58)
  local hash = blockhash_b58 or ''
  local has_prefix = string.sub(hash, 1, #M.SURFPOOL_BLOCKHASH_PREFIX) == M.SURFPOOL_BLOCKHASH_PREFIX
  if not has_prefix then
    return nil
  end
  if network == M.LOCALNET_NETWORK then
    return nil
  end
  -- Blockhash detail is debug-grade and not actionable for end users.
  -- The returned table mirrors the canonical structured-error shape so
  -- callers can either re-raise via error_codes.raise or feed it through
  -- the response builder unchanged.
  return {
    code = error_codes.WRONG_NETWORK,
    message = 'Signed against localnet but the server expects ' .. tostring(network) .. '. '
      .. 'Switch your client RPC to ' .. tostring(network) .. ' and re-sign.',
  }
end

--- Convenience: same as `check_network_blockhash` but raises through
--- error_codes.raise so the credential's WRONG_NETWORK code propagates
--- across the pcall boundary into the response builder.
function M.assert_network_blockhash(network, blockhash_b58)
  local err = M.check_network_blockhash(network, blockhash_b58)
  if err then
    error_codes.raise(error_codes.WRONG_NETWORK, err.message)
  end
end

return M
