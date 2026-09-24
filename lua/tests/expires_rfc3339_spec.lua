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

-- Additional parser edge cases (merged from library_coverage_spec).

t.test('expires.parse_rfc3339 rejects non-string input', function()
  local expires = require('pay_kit.protocols.mpp.expires')
  local value, err = expires.parse_rfc3339(123)
  t.assert_true(value == nil)
  t.assert_true(err ~= nil)
end)

t.test('expires.parse_rfc3339 accepts fractional seconds longer than 9 digits', function()
  local expires = require('pay_kit.protocols.mpp.expires')
  t.assert_equal(expires.parse_rfc3339('2099-01-01T00:00:00.1234567890Z'), 4070908800)
end)

t.test('expires.parse_rfc3339 rejects out-of-range offset hours', function()
  local expires = require('pay_kit.protocols.mpp.expires')
  local value, err = expires.parse_rfc3339('2099-01-01T00:00:00+25:00')
  t.assert_true(value == nil)
  t.assert_true(err and err:find('offset'))
end)

t.test('expires.parse_rfc3339 accepts April 30 (30-day month)', function()
  local expires = require('pay_kit.protocols.mpp.expires')
  local epoch = expires.parse_rfc3339('2099-04-30T00:00:00Z')
  t.assert_true(type(epoch) == 'number')
end)

t.test('expires.is_expired returns true on unparseable input', function()
  local expires = require('pay_kit.protocols.mpp.expires')
  t.assert_equal(expires.is_expired('not-a-timestamp', 0), true)
end)

-- The Lua rows on issue #284: 13 RC-3 (secfrac digit cap) and 3 RC-2 (:60 off a leap-second instant), one test per row.

local RC3_ACCEPT = {
  { 'go_longfrac_10digits_0000000000', '2021-09-29T16:04:33.0000000000Z' },
  { 'go_longfrac_10digits_0000000001', '2021-09-29T16:04:33.0000000001Z' },
  { 'go_longfrac_10digits_0123456789', '2021-09-29T16:04:33.0123456789Z' },
  { 'go_longfrac_10digits_1000000000', '2021-09-29T16:04:33.1000000000Z' },
  { 'go_longfrac_10digits_1000000009', '2021-09-29T16:04:33.1000000009Z' },
  { 'go_longfrac_10digits_9999999999', '2021-09-29T16:04:33.9999999999Z' },
  { 'go_longfrac_11digits_00123456789', '2021-09-29T16:04:33.00123456789Z' },
  { 'go_longfrac_11digits_10000000000', '2021-09-29T16:04:33.10000000000Z' },
  { 'go_longfrac_12digits_000123456789', '2021-09-29T16:04:33.000123456789Z' },
  { 'go_longfrac_16digits_9999999999999999', '2021-09-29T16:04:33.9999999999999999Z' },
  { 'jsts_date_time_026', '1985-04-12T00:59:59.999999999999999Z', 482115599 },
  { 'secfrac_10_digits', '2026-01-29T12:00:00.1234567890Z', 1769688000 },
  { 'secfrac_19_digits_exceeds_int64', '2026-01-29T12:00:00.9999999999999999999Z', 1769688000 },
}

local RC2_REJECT = {
  { 'jsts_date_time_008', '1998-12-31T23:58:60Z' },
  { 'jsts_date_time_009', '1998-12-31T22:59:60Z' },
  { 'leap_second_offset_rolls_local_date_forward_wrong_offset', '1999-01-01T00:59:60+02:00' },
}

for _, row in ipairs(RC3_ACCEPT) do
  t.test('#284 RC-3 ' .. row[1] .. ' parses and truncates to whole seconds', function()
    local expires = require('pay_kit.protocols.mpp.expires')
    t.assert_equal(expires.parse_rfc3339(row[2]), row[3] or 1632931473, row[1])
  end)
end

for _, row in ipairs(RC2_REJECT) do
  t.test('#284 RC-2 ' .. row[1] .. ' is rejected as a non-leap-second :60', function()
    local expires = require('pay_kit.protocols.mpp.expires')
    local value, err = expires.parse_rfc3339(row[2])
    t.assert_true(value == nil, row[1])
    t.assert_true(err and err:find('leap second'), row[1])
  end)
end

t.test('#284 the leap seconds the corpus accepts still parse', function()
  local expires = require('pay_kit.protocols.mpp.expires')
  for _, value in ipairs({
    '1998-12-31T23:59:60Z', '1998-12-31T15:59:60.123-08:00', '1972-06-30T23:59:60Z',
    '1999-01-01T00:59:60+01:00', '1990-12-31T15:59:60-08:00', '1990-12-31T23:59:60Z',
  }) do
    t.assert_true(expires.parse_rfc3339(value) ~= nil, value)
  end
end)

t.test('#284 RC-2 an offset that rolls the UTC day forward off the month end rejects', function()
  -- 1998-12-31T23:59:60-08:00 is 1999-01-01T07:59:60Z, not a leap-second instant.
  local expires = require('pay_kit.protocols.mpp.expires')
  t.assert_true(expires.parse_rfc3339('1998-12-31T23:59:60-08:00') == nil)
end)
