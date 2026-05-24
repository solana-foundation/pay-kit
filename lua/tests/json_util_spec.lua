-- Exhaustive coverage for mpp.util.json (encoder + parser branches).
local json = require('mpp.util.json')
local helpers = require('tests.test_helper')

local function assert_throws(fn, pattern)
  local ok, err = pcall(fn)
  if ok then error('expected to raise') end
  if pattern and not tostring(err):match(pattern) then
    error('unexpected error: ' .. tostring(err))
  end
end

helpers.test('json.encode: nil and null sentinel', function()
  helpers.assert_equal(json.encode(nil), 'null')
  helpers.assert_equal(json.encode(json.null), 'null')
end)

helpers.test('json.encode: booleans', function()
  helpers.assert_equal(json.encode(true), 'true')
  helpers.assert_equal(json.encode(false), 'false')
end)

helpers.test('json.encode: numbers', function()
  helpers.assert_equal(json.encode(42), '42')
  helpers.assert_equal(json.encode(-1.5), '-1.5')
end)

helpers.test('json.encode: rejects NaN', function()
  assert_throws(function() json.encode(0/0) end, 'non%-finite')
end)

helpers.test('json.encode: rejects +inf and -inf', function()
  assert_throws(function() json.encode(math.huge) end, 'non%-finite')
  assert_throws(function() json.encode(-math.huge) end, 'non%-finite')
end)

helpers.test('json.encode: strings escape control chars and quotes', function()
  helpers.assert_equal(json.encode('a"b\\c'), '"a\\"b\\\\c"')
  helpers.assert_equal(json.encode('\b\f\n\r\t'), '"\\b\\f\\n\\r\\t"')
  -- A raw control char (0x01) becomes .
  helpers.assert_equal(json.encode(string.char(1)), '"\\u0001"')
end)

helpers.test('json.encode: array', function()
  helpers.assert_equal(json.encode({1, 2, 3}), '[1,2,3]')
  helpers.assert_equal(json.encode({}), '[]')
end)

helpers.test('json.encode: object with sorted keys', function()
  -- Sorted order: a then z.
  helpers.assert_equal(json.encode({z = 1, a = 2}), '{"a":2,"z":1}')
end)

helpers.test('json.encode: nested', function()
  helpers.assert_equal(json.encode({x = {1, 2}}), '{"x":[1,2]}')
end)

helpers.test('json.encode: unsupported type errors', function()
  assert_throws(function() json.encode(function() end) end, 'unsupported JSON type')
end)

helpers.test('json.decode: primitives', function()
  helpers.assert_equal(json.decode('null'), json.null)
  helpers.assert_equal(json.decode('true'), true)
  helpers.assert_equal(json.decode('false'), false)
  helpers.assert_equal(json.decode('42'), 42)
end)

helpers.test('json.decode: negative number', function()
  helpers.assert_equal(json.decode('-3.14'), -3.14)
end)

helpers.test('json.decode: invalid number errors', function()
  assert_throws(function() json.decode('1.2.3') end, 'invalid number')
end)

helpers.test('json.decode: string with all escapes', function()
  local s = json.decode('"a\\"b\\\\c\\/\\b\\f\\n\\r\\t"')
  helpers.assert_equal(s, 'a"b\\c/\b\f\n\r\t')
end)

helpers.test('json.decode: unicode escape ASCII', function()
  helpers.assert_equal(json.decode('"\\u0041"'), 'A')
end)

helpers.test('json.decode: unicode escape 2-byte UTF-8', function()
  -- U+00A9 (©) encodes as C2 A9.
  helpers.assert_equal(json.decode('"\\u00A9"'), string.char(0xC2, 0xA9))
end)

helpers.test('json.decode: unicode escape 3-byte UTF-8', function()
  -- U+20AC (€) encodes as E2 82 AC.
  helpers.assert_equal(json.decode('"\\u20AC"'), string.char(0xE2, 0x82, 0xAC))
end)

helpers.test('json.decode: invalid unicode escape errors', function()
  assert_throws(function() json.decode('"\\uZZZZ"') end, 'invalid unicode')
end)

helpers.test('json.decode: invalid escape character errors', function()
  assert_throws(function() json.decode('"\\q"') end, 'invalid escape')
end)

helpers.test('json.decode: unterminated string errors', function()
  assert_throws(function() json.decode('"abc') end, 'unterminated')
end)

helpers.test('json.decode: empty array', function()
  local arr = json.decode('[]')
  helpers.assert_equal(#arr, 0)
end)

helpers.test('json.decode: array with elements', function()
  local arr = json.decode('[1, 2, "x"]')
  helpers.assert_equal(arr[1], 1)
  helpers.assert_equal(arr[2], 2)
  helpers.assert_equal(arr[3], 'x')
end)

helpers.test('json.decode: array missing comma errors', function()
  assert_throws(function() json.decode('[1 2]') end, 'expected , or %]')
end)

helpers.test('json.decode: empty object', function()
  local obj = json.decode('{}')
  -- Lua doesn't distinguish empty array vs empty object — both are empty tables.
  helpers.assert_true(type(obj) == 'table')
end)

helpers.test('json.decode: object with entries', function()
  local obj = json.decode('{"a": 1, "b": "two"}')
  helpers.assert_equal(obj.a, 1)
  helpers.assert_equal(obj.b, 'two')
end)

helpers.test('json.decode: object missing comma errors', function()
  assert_throws(function() json.decode('{"a":1 "b":2}') end, 'expected , or }')
end)

helpers.test('json.decode: trailing input errors', function()
  assert_throws(function() json.decode('null trailing') end, 'unexpected trailing input')
end)

helpers.test('json.decode: unexpected token errors', function()
  assert_throws(function() json.decode('@') end, 'unexpected token')
end)

helpers.test('json.decode: whitespace handling', function()
  local obj = json.decode('  {\n  "a"\t:\r1\n}  ')
  helpers.assert_equal(obj.a, 1)
end)
