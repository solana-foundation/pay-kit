-- Every pay_kit module on disk ships in both rockspecs: a module only the
-- dev rockspec lists installs from it but not from the release, and its
-- `require` then fails at runtime.

local function listed(path)
  local f = assert(io.open(path, 'r'))
  local text = f:read('*a')
  f:close()
  local modules = {}
  for name, file in text:gmatch("%['(pay_kit[%w_%.]*)'%]%s*=%s*'([^']+)'") do
    modules[name] = file
  end
  return modules
end

local function on_disk()
  local modules = {}
  local find = assert(io.popen("find pay_kit -name '*.lua' | sort"))
  for file in find:lines() do
    local name = file:gsub('%.lua$', ''):gsub('/', '.'):gsub('%.init$', '')
    modules[name] = file
  end
  find:close()
  return modules
end

local helper = require('tests.test_helper')

for _, rockspec in ipairs({ 'pay-kit-dev-1.rockspec', 'pay-kit-0.1.0-1.rockspec' }) do
  helper.test(rockspec .. ' lists every pay_kit module', function()
    local modules = listed(rockspec)
    for name, file in pairs(on_disk()) do
      helper.assert_equal(modules[name], file, name .. ' is missing from ' .. rockspec)
    end
  end)
end
