--[[
PayKit error string constants.

Lua's error model is "return (nil, err_string)" not exception classes,
so the lib exports the canonical error strings as constants. Apps test
against `pay_kit.errors.X` instead of fragile string-matching.

Mirrors the design's "Errors are strings with a `pay_kit:` prefix"
rule. Constants are frozen at module load time (`return setmetatable`
trick is overkill for Lua; the table is not meant to be mutated, and
unit tests assert that callers never reassign).
]]

local M = {}

M.PAYMENT_REQUIRED              = 'pay_kit: payment required'
M.INVALID_PROOF                 = 'pay_kit: invalid proof'
M.CHALLENGE_EXPIRED             = 'pay_kit: challenge expired'
M.SCHEME_NOT_SUPPORTED          = 'pay_kit: scheme not supported'
M.MIXED_DENOMINATIONS           = 'pay_kit: mixed denominations in gate'
M.X402_INCOMPATIBLE_WITH_FEES   = 'pay_kit: x402 incompatible with multi-recipient gates'
M.DEMO_SIGNER_ON_MAINNET        = 'pay_kit: demo signer cannot be used on solana_mainnet'
M.CONFIGURE_ALREADY_CALLED      = 'pay_kit: configure() can only be called once per worker'
M.GATE_NOT_FOUND                = 'pay_kit: gate not found'
M.GATE_REGISTRATION_FROZEN      = 'pay_kit: gate registry is frozen after configure()'
M.OPERATOR_SIGNER_MISSING       = 'pay_kit: operator.signer is required for this scheme'
M.NOT_IMPLEMENTED               = 'pay_kit: not implemented'
M.SIGNATURE_CONSUMED            = 'pay_kit: signature already consumed'
M.WRONG_NETWORK                 = 'pay_kit: wrong network'
M.CHARGE_REQUEST_MISMATCH       = 'pay_kit: charge request mismatch'
M.CHALLENGE_VERIFICATION_FAILED = 'pay_kit: challenge verification failed'
M.PAYMENT_IDENTIFIER_REQUIRED   = 'pay_kit: payment-identifier required'

return M
