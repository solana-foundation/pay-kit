package.path = table.concat({
  './?.lua',
  './?/init.lua',
  './lua/?.lua',
  './lua/?/init.lua',
  package.path,
}, ';')

require('tests.network_check_spec')
require('tests.core_spec')
require('tests.server_spec')
require('tests.solana_verify_spec')
require('tests.html_spec')
require('tests.cross_route_replay_spec')
require('tests.rpc_spec')
require('tests.charge_handler_spec')

require('tests.test_helper').run()
