--[[
P7 deprecation shim. `require('mpp')` keeps its full legacy surface
working; first load also emits a warn-once notice pointing at the new
`resty.pay_kit` entry point.
]]

-- luacheck: globals io
local helper = require('tests.test_helper')

helper.test('require("mpp") still returns the legacy surface', function()
  -- Force a fresh load to exercise the warn path. Stash + restore the
  -- shim's "already warned" sentinel so test order does not matter.
  package.loaded._pay_kit_mpp_warned = nil
  package.loaded['mpp'] = nil

  local captured = ''
  local orig_stderr = io.stderr
  io.stderr = setmetatable({}, {__index = {
    write = function(_, text) captured = captured .. (text or ''); end,
  }})

  local ok, mpp_or_err = pcall(require, 'mpp')

  io.stderr = orig_stderr

  helper.assert_true(ok, tostring(mpp_or_err))
  helper.assert_true(mpp_or_err.server ~= nil,    'mpp.server missing')
  helper.assert_true(mpp_or_err.protocol ~= nil,  'mpp.protocol missing')
  helper.assert_true(mpp_or_err.store ~= nil,     'mpp.store missing')
  helper.assert_true(captured:find('DEPRECATION', 1, true),
    'expected deprecation warn on first require, got: ' .. tostring(captured))
end)

helper.test('subsequent require("mpp") does not warn again', function()
  -- The first test above primed the warn-once sentinel. Loading again
  -- should be silent.
  package.loaded['mpp'] = nil
  local captured = ''
  local orig_stderr = io.stderr
  io.stderr = setmetatable({}, {__index = {
    write = function(_, text) captured = captured .. (text or ''); end,
  }})
  require('mpp')
  io.stderr = orig_stderr
  helper.assert_true(not captured:find('DEPRECATION', 1, true),
    'subsequent require should be silent, got: ' .. tostring(captured))
end)
