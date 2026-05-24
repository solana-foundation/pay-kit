package.path = table.concat({
  './?.lua',
  './?/init.lua',
  './lua/?.lua',
  './lua/?/init.lua',
  package.path,
}, ';')

require('tests.network_check_spec')
require('tests.core_spec')
require('tests.json_canonical_rfc8785_spec')
require('tests.expires_rfc3339_spec')
require('tests.server_spec')
require('tests.solana_verify_spec')
require('tests.html_spec')
require('tests.cross_route_replay_spec')
require('tests.rpc_spec')
require('tests.charge_handler_spec')
require('tests.library_coverage_spec')
require('tests.util_base58_spec')
require('tests.util_base64_std_spec')
require('tests.methods_solana_transaction_spec')
require('tests.methods_solana_instructions_spec')
require('tests.methods_solana_ata_spec')
require('tests.methods_solana_signer_spec')
require('tests.methods_solana_verifier_spec')
require('tests.solana_rpc_transport_spec')
require('tests.solana_rpc_transport_resty_spec')
require('tests.error_codes_spec')
require('tests.store_shared_dict_spec')
require('tests.intents_charge_spec')
require('tests.json_util_spec')

require('tests.test_helper').run()
