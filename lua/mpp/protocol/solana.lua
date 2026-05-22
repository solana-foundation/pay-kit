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

function M.default_rpc_url(network)
  if network == 'devnet' then
    return 'https://api.devnet.solana.com'
  elseif network == 'localnet' then
    return 'http://localhost:8899'
  end
  return 'https://api.mainnet-beta.solana.com'
end

-- Maintainer canonical for the mainnet slug is `mainnet`. The legacy
-- `mainnet-beta` spelling is accepted as a backward-compatible alias and
-- normalized to `mainnet`. Other networks pass through unchanged.
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

function M.default_token_program_for_currency(currency, network)
  local symbol = M.stablecoin_symbol(M.resolve_mint(currency, network)) or M.stablecoin_symbol(currency)
  if symbol then
    return TOKEN_PROGRAMS[symbol]
  end
  return M.TOKEN_PROGRAM
end

return M
