local M = {
  TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  ASSOCIATED_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
  SYSTEM_PROGRAM = '11111111111111111111111111111111',
  MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',
}

local KNOWN_MINTS = {
  USDC = {
    devnet = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    testnet = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    mainnet = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  },
  USDT = {
    mainnet = 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
  },
  USDG = {
    devnet = '4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7',
    testnet = '4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7',
    mainnet = '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH',
  },
  PYUSD = {
    devnet = 'CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM',
    testnet = 'CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM',
    mainnet = '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo',
  },
  CASH = {
    mainnet = 'CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH',
  },
}

local TOKEN_PROGRAMS = {
  USDC = M.TOKEN_PROGRAM,
  USDT = M.TOKEN_PROGRAM,
  USDG = M.TOKEN_2022_PROGRAM,
  PYUSD = M.TOKEN_2022_PROGRAM,
  CASH = M.TOKEN_2022_PROGRAM,
}

-- Audit #37: the canonical network slugs are exactly these three. The legacy
-- `mainnet-beta` spelling is the Solana RPC *hostname* convention only and is
-- NOT a valid network slug here (mirrors the Rust spine's `validate_network`,
-- which rejects `mainnet-beta`). `validate_network` is the boot-time allowlist
-- gate; `default_rpc_url` only ever sees a slug that has already passed it.
M.NETWORKS = {
  mainnet = true,
  devnet = true,
  localnet = true,
}

-- Validate a network slug against the allowlist. Returns `(true)` on success
-- and `(false, message)` on an unknown / empty slug so callers can raise with
-- their own error shape (mirrors Rust `validate_network`).
function M.validate_network(network)
  if type(network) ~= 'string' or network == '' then
    return false, 'network is required (one of mainnet, devnet, localnet)'
  end
  if not M.NETWORKS[network] then
    return false, string.format(
      "unsupported network '%s' (must be one of mainnet, devnet, localnet)",
      tostring(network))
  end
  return true
end

function M.default_rpc_url(network)
  if network == 'devnet' then
    return 'https://api.devnet.solana.com'
  elseif network == 'localnet' then
    -- Hosted Surfpool clone of mainnet state. Lets `pay_kit.configure
    -- { network = 'solana_localnet' }` boot against something
    -- reachable without the developer running a local validator
    -- (mirrors Ruby PR #142 follow-up).
    return 'https://402.surfnet.dev:8899'
  end
  return 'https://api.mainnet-beta.solana.com'
end

-- Maintainer canonical for the mainnet slug is `mainnet`. Mint-table lookups
-- key on the canonical slug; the boot-time `validate_network` gate already
-- rejects `mainnet-beta` and any unknown slug, so this only canonicalizes the
-- known three (and tolerates the legacy alias when called directly for a
-- table key, e.g. from the verifier with a methodDetails-supplied network).
local function normalize_network(network)
  local lower = string.lower(network or '')
  if lower == 'mainnet' or lower == 'mainnet-beta' then
    return 'mainnet'
  end
  return network
end

function M.resolve_mint(currency, network)
  local normalized = string.upper(currency or '')
  if normalized == 'SOL' then
    return nil
  end

  local known = KNOWN_MINTS[normalized]
  if known then
    return known[normalize_network(network)] or known.mainnet
  end

  return currency
end

function M.stablecoin_symbol(currency)
  local normalized = string.upper(currency or '')
  if KNOWN_MINTS[normalized] then
    return normalized
  end
  for symbol, mints in pairs(KNOWN_MINTS) do
    for _, mint in pairs(mints) do
      if currency == mint then
        return symbol
      end
    end
  end
  return nil
end

-- Return the token program for a KNOWN stablecoin currency (symbol or known
-- mint address). For an arbitrary mint address NOT in our table this returns
-- `nil` rather than silently guessing legacy Token.
--
-- Audit #28 (part 2): the previous implementation fell back to legacy
-- `TOKEN_PROGRAM` for any unknown currency. An arbitrary Token-2022 mint would
-- then ship with the wrong token program (challenge issuance) or derive the
-- wrong destination ATA (verification). The Rust spine resolves the mint owner
-- on-chain at boot and rejects an unexpected owner; the Lua server boot path
-- has no synchronous account-fetch wired, so we fail closed instead of
-- guessing. Callers that CAN resolve the owner on-chain pass a resolver to
-- `M.resolve_token_program`.
function M.default_token_program_for_currency(currency, network)
  local symbol = M.stablecoin_symbol(M.resolve_mint(currency, network)) or M.stablecoin_symbol(currency)
  if symbol then
    return TOKEN_PROGRAMS[symbol]
  end
  return nil
end

local base58 = require('pay_kit.solana.base58')

-- True when `value` decodes as a 32-byte base58 string, i.e. a syntactically
-- valid Solana public key (mint or account address). Used both to gate
-- recipient parseability (audit #21) and to distinguish a known-symbol
-- currency from an arbitrary mint address (audit #28).
function M.is_pubkey(value)
  if type(value) ~= 'string' or value == '' then
    return false
  end
  local ok, decoded = pcall(base58.decode, value)
  return ok and #decoded == 32
end

-- Resolve the token program for a charge currency, failing closed on an
-- unresolvable arbitrary mint instead of guessing legacy Token (audit #28).
--
--   * `SOL`                       -> nil (native, no token program)
--   * known stablecoin symbol/mint -> static table answer
--   * arbitrary mint address      -> `resolver(mint)` if a resolver is given
--                                    (e.g. an on-chain owner lookup), else a
--                                    `(nil, message)` rejection
--   * anything else               -> `(nil, message)` rejection
--
-- Returns `(program)` on success or `(nil, message)` so the caller raises with
-- its own error shape. The optional `resolver` is `function(mint) ->
-- program | nil` and MUST return one of the two token programs.
function M.resolve_token_program(currency, network, resolver)
  if string.lower(currency or '') == 'sol' then
    return nil
  end
  local known = M.default_token_program_for_currency(currency, network)
  if known then
    return known
  end
  if M.is_pubkey(currency) then
    if type(resolver) == 'function' then
      local program = resolver(currency)
      if program == M.TOKEN_PROGRAM or program == M.TOKEN_2022_PROGRAM then
        return program
      end
      return nil, string.format(
        "could not resolve a supported token program for mint '%s'", currency)
    end
    return nil, string.format(
      "token program for arbitrary mint '%s' is unknown; pass options.token_program "
      .. 'or a token_program_resolver so the wrong (legacy) program is not assumed',
      currency)
  end
  return nil, string.format("unknown currency '%s' (not a known symbol or mint address)", currency)
end

return M
