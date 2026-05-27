local t = require('tests.test_helper')
local nc = require('pay_kit.protocols.mpp.server.network_check')

-- Pure-function tests for the Surfpool-prefix-vs-non-localnet check.
-- The check is asymmetric: a Surfpool-prefixed blockhash is only valid
-- on `localnet`, but a non-prefixed blockhash is accepted on any network
-- (we can't tell from a non-prefixed hash which real cluster it came from).

-- ── happy paths ───────────────────────────────────────────────────────────

t.test('network_check: localnet + surfpool hash is ok', function()
  t.assert_equal(
    nc.check_network_blockhash('localnet', 'SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad'),
    nil
  )
end)

t.test('network_check: localnet + real hash is ok', function()
  -- Real localnet validator (not Surfpool) — also valid.
  t.assert_equal(
    nc.check_network_blockhash('localnet', '11111111111111111111111111111111'),
    nil
  )
end)

t.test('network_check: mainnet + real hash is ok', function()
  t.assert_equal(
    nc.check_network_blockhash('mainnet', '9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F'),
    nil
  )
end)

t.test('network_check: devnet + real hash is ok', function()
  t.assert_equal(
    nc.check_network_blockhash('devnet', 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N'),
    nil
  )
end)

-- ── the actual bug surface ────────────────────────────────────────────────

t.test('network_check: mainnet rejects surfpool hash with explicit context', function()
  local err = nc.check_network_blockhash('mainnet', 'SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad')
  t.assert_true(err ~= nil, 'expected error table, got nil')
  -- Canonical L6 code (underscore form). Matches the audit-row code set
  -- shared with Python and the cross-SDK fault matrix.
  t.assert_equal(err.code, 'wrong_network')
  t.assert_true(err.message:find('Signed against localnet', 1, true) ~= nil, 'missing received-side: ' .. err.message)
  t.assert_true(err.message:find('server expects mainnet', 1, true) ~= nil, 'missing expected-side: ' .. err.message)
  t.assert_true(err.message:find('re%-sign') ~= nil, 'missing actionable hint: ' .. err.message)
end)

t.test('network_check: devnet rejects surfpool hash', function()
  local err = nc.check_network_blockhash('devnet', 'SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad')
  t.assert_true(err ~= nil)
  t.assert_true(err.message:find('server expects devnet', 1, true) ~= nil)
end)

-- ── edge cases ────────────────────────────────────────────────────────────

t.test('network_check: partial prefix (SURFNETx) does not match', function()
  t.assert_equal(
    nc.check_network_blockhash('mainnet', 'SURFNETx9zrUHnA1nCByPksy'),
    nil
  )
end)

t.test('network_check: exact prefix only is treated as surfpool', function()
  t.assert_equal(nc.check_network_blockhash('localnet', nc.SURFPOOL_BLOCKHASH_PREFIX), nil)
  local err = nc.check_network_blockhash('mainnet', nc.SURFPOOL_BLOCKHASH_PREFIX)
  t.assert_true(err ~= nil)
end)

t.test('network_check: non-surfpool hash passes anywhere', function()
  -- Asymmetric design: a non-prefixed blockhash is accepted on every
  -- network because we can't tell which real cluster it came from.
  for _, network in ipairs({ 'mainnet', 'devnet', 'localnet' }) do
    t.assert_equal(nc.check_network_blockhash(network, '11111111111111111111111111111111'), nil)
  end
end)
