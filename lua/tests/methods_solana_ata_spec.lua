local helper = require('tests.test_helper')
local ata = require('pay_kit.solana.ata')

-- Known fixture: derive the ATA for a USDC mainnet mint and a randomly
-- chosen owner. The expected value below is cross-checked against the
-- Ruby reference at ruby/lib/mpp/methods/solana/associated_token.rb
-- and against `spl-token` CLI output. If any value here changes, the
-- ATA derivation is broken.
local USDC_MAINNET_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
local TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
local OWNER = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'

helper.test('ata.derive matches the Ruby reference for the USDC SPL Token ATA', function()
  -- Pinned against `ruby/lib/mpp/methods/solana/associated_token.rb` for
  -- the same owner / mint / token program triple.
  helper.assert_equal(
    ata.derive(OWNER, USDC_MAINNET_MINT, TOKEN_PROGRAM),
    '3EjekkZPxiKdDB91mdJjUcjFjRmyWjP1Y4ySvfwSaQ4b'
  )
end)

helper.test('ata.derive matches the Ruby reference for the USDC Token-2022 ATA', function()
  local TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
  helper.assert_equal(
    ata.derive(OWNER, USDC_MAINNET_MINT, TOKEN_2022),
    'J1AgP9czKVx1tHY2TrQxMd73tguFUE7rVYynxEWsq8nr'
  )
end)

helper.test('ata.derive is stable across repeated calls', function()
  -- `derive` memoizes on (owner, mint, token_program). A cache that keyed
  -- on the wrong tuple, or that handed back a stale entry, would surface
  -- here as a second call disagreeing with the pinned fixture. The
  -- Token-2022 spec above pins the same owner / mint against a different
  -- token program, so a key that collapsed the token program would fail
  -- that assertion too.
  local first = ata.derive(OWNER, USDC_MAINNET_MINT, TOKEN_PROGRAM)
  local second = ata.derive(OWNER, USDC_MAINNET_MINT, TOKEN_PROGRAM)
  helper.assert_equal(second, first)
  helper.assert_equal(second, '3EjekkZPxiKdDB91mdJjUcjFjRmyWjP1Y4ySvfwSaQ4b')
end)

helper.test('ata.derive rejects malformed input even after a cached success', function()
  -- The byte-length validation runs before the cache lookup, so a bad
  -- input never short-circuits into a cached address.
  helper.assert_error(function()
    ata.derive(OWNER, USDC_MAINNET_MINT, '1111')
  end, 'ATA derivation requires base58 inputs that decode to 32 bytes')
end)

helper.test('find_program_address rejects a non-32-byte program id', function()
  helper.assert_error(function()
    ata.find_program_address({ string.rep('\0', 32) }, '1111')
  end, 'program id must decode to 32 bytes')
end)

helper.test('on-curve check matches known reference vectors after the bignum cleanup', function()
  -- Regression guard for the previously-dead forward-direction right-shift
  -- loop in the modular-arithmetic on-curve helper. If the shift ever
  -- regresses to LSB-into-MSB direction, the exponent `(p+3)/8` loses low
  -- bits and the Tonelli sqrt diverges, flipping these results.
  --
  --   - all-zero candidate: on-curve (y = 0 satisfies the Edwards equation).
  --   - canonical USDC mainnet pubkey: on-curve (valid Ed25519 point).
  --   - y = 2 little-endian: off-curve. Cross-checked against the Ruby
  --     reference at ruby/lib/mpp/methods/solana/public_key.rb#on_curve?,
  --     which returns false for the same input.
  local internals = ata._internals
  local base58 = require('pay_kit.solana.base58')
  helper.assert_equal(internals.is_on_curve(string.rep('\0', 32)), true)
  helper.assert_equal(
    internals.is_on_curve(base58.decode('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')),
    true
  )
  helper.assert_equal(
    internals.is_on_curve(string.char(2) .. string.rep('\0', 31)),
    false
  )
end)
