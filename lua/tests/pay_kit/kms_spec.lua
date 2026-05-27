--[[
P1 KMS namespace reservation. The factories all raise "not implemented"
so a caller who reaches for them early gets a clear error instead of
a silent nil.
]]

local helper = require('tests.test_helper')
local kms = require('pay_kit.kms')

helper.test('kms.gcp returns not-implemented', function()
  local sgn, err = kms.gcp({key_name = 'projects/...'})
  helper.assert_true(sgn == nil)
  helper.assert_true(err and err:find('not implemented'), err)
end)

helper.test('kms.aws returns not-implemented', function()
  local sgn, err = kms.aws({key_id = 'alias/...'})
  helper.assert_true(sgn == nil)
  helper.assert_true(err and err:find('not implemented'), err)
end)

helper.test('kms.vault returns not-implemented', function()
  local sgn, err = kms.vault({addr = 'https://...'})
  helper.assert_true(sgn == nil)
  helper.assert_true(err and err:find('not implemented'), err)
end)
