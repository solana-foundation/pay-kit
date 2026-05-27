package = 'kong-plugin-pay-kit'
version = 'dev-1'
source = {
  url = 'git+https://github.com/solana-foundation/pay-kit.git',
}
description = {
  summary = 'Kong plugin that gates routes via PayKit (x402 + MPP).',
  detailed = [[
    Thin Kong 3.x plugin envelope over the pay-kit core library.
    handler.lua + schema.lua + init.lua. PRIORITY = 1010 sits
    just below OpenID Connect (1050) and well above rate-limiting
    (910) so unpaid traffic never burns the rate-limit bucket.
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
    -- Kong's plugin loader looks for `kong.plugins.<name>.*` on
    -- lua_package_path. With the layout below, set
    --   lua_package_path './lua/plugins/?.lua;./lua/?.lua;;'
    -- and Kong's `require('kong.plugins.pay-kit.handler')` resolves
    -- to lua/plugins/kong/plugins/pay-kit/handler.lua.
    ['kong.plugins.pay-kit.handler'] = 'plugins/kong/plugins/pay-kit/handler.lua',
    ['kong.plugins.pay-kit.schema']  = 'plugins/kong/plugins/pay-kit/schema.lua',
    ['kong.plugins.pay-kit.init']    = 'plugins/kong/plugins/pay-kit/init.lua',
  },
}
