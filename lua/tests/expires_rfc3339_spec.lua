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

t.test('expires.parse_rfc3339 rejects fractional seconds longer than 9 digits', function()
  local expires = require('pay_kit.protocols.mpp.expires')
  local value, err = expires.parse_rfc3339('2099-01-01T00:00:00.1234567890Z')
  t.assert_true(value == nil)
  t.assert_true(err and err:find('fractional'))
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

-- ── Cross-SDK RFC 3339 conformance corpus (issue #111) ──
--
-- Vectors live in `harness/vectors/mpp-protocol/expires-rfc3339-corpus.json`
-- under the `expires.parse` operation. Every SDK asserts the same ACCEPT /
-- REJECT verdict against the same vectors, so a divergence between two SDKs
-- shows up as a failing test in exactly one of them rather than as silence.
--
-- Only the `applies_to == "date-time"` slice runs here. The corpus also carries
-- `full-date` and `full-time` scenarios, which answer a different question than
-- an `expires` field asks -- `1963-06-19` is a valid RFC 3339 `full-date` and no
-- `date-time` parser should accept it. Selection is on the first-class
-- `applies_to` field, never on a name prefix or a description string.
--
-- Decoding uses the SDK's own `pay_kit.util.json`, so the suite gains no new
-- dependency. The runner has no fixture-loading facility and no per-vector
-- test-registration idiom, so the corpus runs as a single aggregate test that
-- collects EVERY divergence and reports them all in one error. Failing on the
-- first mismatch would hide the rest.

local function corpus_path()
  -- `tests/run.lua` is driven from `lua/`, but the load path it sets also
  -- allows a repo-root cwd. Locate the corpus from this file instead of from
  -- the working directory.
  local source = debug.getinfo(1, 'S').source:gsub('^@', '')
  local dir = source:match('^(.*)/[^/]*$') or '.'
  return dir .. '/../../harness/vectors/mpp-protocol/expires-rfc3339-corpus.json'
end

t.test('expires.parse_rfc3339 matches the cross-SDK RFC 3339 corpus (date-time slice)', function()
  local expires = require('pay_kit.protocols.mpp.expires')
  local json = require('pay_kit.util.json')

  local path = corpus_path()
  local handle = io.open(path, 'r')
  t.assert_true(handle ~= nil, 'conformance corpus unreadable at ' .. path)
  local body = handle:read('*a')
  handle:close()

  local corpus = json.decode(body)
  local admitted = 0
  local divergences = {}

  for i = 1, #corpus.scenarios do
    local scenario = corpus.scenarios[i]
    if scenario.applies_to == 'date-time' then
      admitted = admitted + 1
      -- `"tests": {"parse": true}` is ACCEPT; `{"parse": {"success": false, …}}`
      -- is REJECT. Identical to the encoding the other vector files in the same
      -- directory use.
      local expect_accept = scenario.tests.parse == true
      local ok, value = pcall(expires.parse_rfc3339, scenario.input)
      -- A crash on hostile input is a result, and it is a REJECT.
      local accepted = ok and value ~= nil
      if accepted ~= expect_accept then
        divergences[#divergences + 1] = string.format(
          '%s: input %q -- corpus expects %s, parse_rfc3339 reports %s',
          scenario.name, scenario.input,
          expect_accept and 'ACCEPT' or 'REJECT',
          accepted and 'ACCEPT' or 'REJECT'
        )
      end
    end
  end

  t.assert_true(admitted > 0, 'corpus admitted zero date-time scenarios')
  t.assert_true(admitted < #corpus.scenarios, 'date-time filter admitted every scenario')

  if #divergences > 0 then
    error(string.format(
      '%d of %d date-time vectors diverge from the cross-SDK corpus:\n  %s',
      #divergences, admitted, table.concat(divergences, '\n  ')
    ))
  end
end)
