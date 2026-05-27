package = 'kong-plugin-pay-kit'
version = 'dev-1'
source = {
  url = 'git+https://github.com/solana-foundation/pay-kit.git',
}
description = {
  summary = 'Kong plugin that gates routes via PayKit (x402 + MPP).',
  detailed = [[
    Thin Kong 3.x plugin envelope over the lua-resty-pay-kit library.
    handler.lua + schema.lua + bootstrap.lua. PRIORITY = 1010 sits
    just below OpenID Connect (1050) and well above rate-limiting
    (910) so unpaid traffic never burns the rate-limit bucket.
  ]],
  homepage = 'https://github.com/solana-foundation/pay-kit',
  license = 'MIT',
}
dependencies = {
  'lua >= 5.1',
  'lua-resty-pay-kit >= dev-1',
}
build = {
  type = 'builtin',
  modules = {
    ['kong.plugins.pay-kit.handler']   = 'kong/plugins/pay-kit/handler.lua',
    ['kong.plugins.pay-kit.schema']    = 'kong/plugins/pay-kit/schema.lua',
    ['kong.plugins.pay-kit.bootstrap'] = 'kong/plugins/pay-kit/bootstrap.lua',
  },
}
