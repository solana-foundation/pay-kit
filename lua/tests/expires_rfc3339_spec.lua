-- RFC 3339 expires parser test cases for the Lua SDK. Isolated from
-- core_spec.lua per PR #102 review (inline comment 3298060956) so RFC
-- 8785 (canonical JSON) and RFC 3339 (expires) live in dedicated files.
-- Battle-tested vector imports are tracked separately (see follow-up
-- issue referenced on the same PR thread).
local t = require('tests.test_helper')

t.test('expires parser is strict RFC 3339', function()
  local expires = require('pay_kit.protocols.mpp.expires')
  t.assert_true(expires.parse_rfc3339('2099-01-01T00:00:00Z') ~= nil)
  t.assert_true(expires.parse_rfc3339('2099-01-01T00:00:00+00:00') ~= nil)
  t.assert_true(expires.parse_rfc3339('2099-01-01T00:00:00.123Z') ~= nil)
  t.assert_true(expires.parse_rfc3339('2099-01-01t00:00:00z') ~= nil)
  t.assert_true(expires.parse_rfc3339('tomorrow') == nil)
  t.assert_true(expires.parse_rfc3339('10000-01-01T00:00:00Z') == nil)
  t.assert_true(expires.parse_rfc3339('2099-02-30T00:00:00Z') == nil)
  t.assert_true(expires.parse_rfc3339('2099-13-01T00:00:00Z') == nil)
  t.assert_true(expires.parse_rfc3339('2099-01-01T24:00:00Z') == nil)
end)

t.test('expires parser rejects bare fractional dot (RFC 3339 sec 5.6)', function()
  -- Codex P3 on PR #102. The dot must be followed by at least one digit.
  local expires = require('pay_kit.protocols.mpp.expires')
  t.assert_true(expires.parse_rfc3339('2026-01-01T00:00:00.Z') == nil)
  t.assert_true(expires.parse_rfc3339('2026-01-01T00:00:00.+00:00') == nil)
  -- A normal fractional value still parses.
  t.assert_true(expires.parse_rfc3339('2026-01-01T00:00:00.5Z') ~= nil)
end)
