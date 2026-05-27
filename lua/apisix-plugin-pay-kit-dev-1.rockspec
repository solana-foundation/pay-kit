package = 'apisix-plugin-pay-kit'
version = 'dev-1'
source = {
  url = 'git+https://github.com/solana-foundation/pay-kit.git',
}
description = {
  summary = 'Apache APISIX plugin that gates routes via PayKit (x402 + MPP).',
  detailed = [[
    Single-file APISIX plugin shim over the pay-kit core library.
    Priority 2520 sits just above APISIX's bundled jwt-auth (2510)
    so payment gates the paid tier on top of identity authentication.
  ]],
  homepage = 'https://github.com/solana-foundation/pay-kit',
  license = 'MIT',
}
dependencies = {
  'lua >= 5.1',
  'pay-kit >= dev-1',
}
build = {
  type = 'builtin',
  modules = {
    -- APISIX loads `apisix.plugins.<name>`. With
    --   lua_package_path './lua/plugins/?.lua;./lua/?.lua;;'
    -- it resolves to lua/plugins/apisix/plugins/pay-kit.lua.
    ['apisix.plugins.pay-kit'] = 'plugins/apisix/plugins/pay-kit.lua',
  },
}
