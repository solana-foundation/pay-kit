--[[
Canonical structured error codes for the Lua MPP server.

Mirrors `python/src/solana_mpp/_errors.py`.
Every server-side rejection raises through `raise(code, message)`
which throws an `error({code = code, message = message})` table the
HTTP boundary then translates into a JSON 402 body carrying `code`,
`error`, and `message`. The three fields are kept distinct for
backward compatibility:

  - `error`   short human description of the failure
  - `message` longer human-readable detail (matches `error` today)
  - `code`    machine-readable code from this module

The Lua codebase used to mix two error shapes: `error('string')` in
the PR A server core and `error({code = '...', message = '...'})` in
the PR B Solana stack. Standardizing on the table shape lets every
HTTP boundary (harness adapter, simple-server, Kong plugin) surface
the same code field without per-callsite glue.

Code set (matches Python and the cross-SDK fault matrix at audit v2):

  charge_request_mismatch     the credential's amount, currency, or
                              recipient does not match the route's
                              expected charge request
  challenge_route_mismatch    the credential's method, intent, or
                              realm does not match this server (cross
                              route replay)
  challenge_verification_failed  HMAC id mismatch or signature does
                                 not validate against the secret
  challenge_expired           the challenge's expires timestamp has
                              passed
  payment_invalid             the on-chain transaction shape failed
                              one of the verifier's structural checks
                              (mint, amount, ATA, memo, fee payer,
                              compute budget, etc.)
  wrong_network               the transaction's recent_blockhash
                              belongs to a different network than the
                              server is configured for
  signature_consumed          the replay store has already recorded
                              this signature for the configured key
                              prefix
]]

local M = {}

M.CHARGE_REQUEST_MISMATCH = 'charge_request_mismatch'
M.CHALLENGE_ROUTE_MISMATCH = 'challenge_route_mismatch'
M.CHALLENGE_VERIFICATION_FAILED = 'challenge_verification_failed'
M.CHALLENGE_EXPIRED = 'challenge_expired'
M.PAYMENT_INVALID = 'payment_invalid'
M.WRONG_NETWORK = 'wrong_network'
M.SIGNATURE_CONSUMED = 'signature_consumed'

-- Set of canonical codes; used by the response builder to assert that no
-- failure path falls through with a missing or unrecognized code. The lookup
-- table doubles as a runtime allowlist.
M.ALL = {
  [M.CHARGE_REQUEST_MISMATCH] = true,
  [M.CHALLENGE_ROUTE_MISMATCH] = true,
  [M.CHALLENGE_VERIFICATION_FAILED] = true,
  [M.CHALLENGE_EXPIRED] = true,
  [M.PAYMENT_INVALID] = true,
  [M.WRONG_NETWORK] = true,
  [M.SIGNATURE_CONSUMED] = true,
}

--- Raise a structured error with the given canonical code and message.
--- Raises a table-shaped error so callers that pcall the SDK pick up the
--- code through `err.code`; bare string consumers continue to work via
--- `tostring(err)` (Lua converts the table through its `__tostring`).
function M.raise(code, message)
  if M.ALL[code] == nil then
    -- Defensive: surface programming mistakes (typo in a callsite,
    -- forgotten code constant) immediately rather than letting an
    -- unknown code reach the response builder. The error itself is
    -- raised as a string so the test harness sees the developer
    -- mistake plainly.
    error('invalid error code: ' .. tostring(code))
  end
  error({ code = code, message = tostring(message or '') })
end

--- Project an error value (any of: table, string, raised lua error) into a
--- response-builder shape: `{code, error, message}`. Tables that already
--- carry `code` keep it; bare strings get the generic
--- CHALLENGE_VERIFICATION_FAILED fallback so the response is never
--- missing a code field.
function M.to_response(err)
  if type(err) == 'table' and err.code ~= nil and M.ALL[err.code] then
    return {
      code = err.code,
      error = err.message or '',
      message = err.message or '',
    }
  end
  local message
  if type(err) == 'table' and err.message ~= nil then
    message = err.message
  else
    message = tostring(err or '')
  end
  return {
    code = M.CHALLENGE_VERIFICATION_FAILED,
    error = message,
    message = message,
  }
end

return M
