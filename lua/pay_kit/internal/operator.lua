--[[
Operator value object.

Bundles the three things a merchant brings to the protocol:
- recipient: where settled funds land. Default `pay_to` for every gate.
- signer:    Ed25519 keypair used for x402 facilitator challenges and
             (if fee_payer=true) Solana network fee payment.
- fee_payer: whether the operator's signer also pays Solana fees on
             settlement transactions.

Nil-as-no-opinion: setting a field to nil leaves the default in place.
This composes cleanly with os.getenv() reads since unset env vars
return nil.

Mirrors the Ruby gem's PayKit::Operator (ruby/lib/pay_kit/operator.rb)
and the design's "Operator" section in issue #140.
]]

local signer_mod = require('pay_kit.signer')

local M = {}
local Operator = {}
Operator.__index = Operator

-- Internal: validate a signer duck-type (must respond to pubkey,
-- sign, fee_payer). Returns (true) or (false, err).
local function valid_signer(s)
  if type(s) ~= 'table' then return false, 'must be a table' end
  if type(s.pubkey) ~= 'function' then return false, 'missing :pubkey()' end
  if type(s.sign) ~= 'function' then return false, 'missing :sign()' end
  if type(s.fee_payer) ~= 'function' then return false, 'missing :fee_payer()' end
  return true
end

-- Build an Operator. All fields are optional; unset / nil leaves the
-- defaults in place. Returns (operator, nil) on success, (nil, err)
-- on a non-nil-but-invalid input.
function M.new(opts)
  opts = opts or {}
  if opts.recipient ~= nil and type(opts.recipient) ~= 'string' then
    return nil, 'pay_kit: operator.recipient must be a string'
  end
  local sgn = opts.signer
  if sgn ~= nil then
    local ok, why = valid_signer(sgn)
    if not ok then
      return nil, 'pay_kit: operator.signer is not a signer (' .. why .. ')'
    end
  end
  if opts.fee_payer ~= nil and type(opts.fee_payer) ~= 'boolean' then
    return nil, 'pay_kit: operator.fee_payer must be true or false (got ' ..
      type(opts.fee_payer) .. ')'
  end

  return setmetatable({
    _recipient = opts.recipient,
    _signer    = sgn or signer_mod.demo(),
    _fee_payer = (opts.fee_payer == nil) and true or opts.fee_payer,
  }, Operator)
end

-- Resolved recipient. Falls back to the signer's pubkey when the
-- caller did not set one explicitly. The signer always has a pubkey,
-- so this is a safe default.
function Operator:effective_recipient()
  return self._recipient or self._signer:pubkey()
end

-- Explicit recipient as set, ignoring the signer-pubkey fallback.
-- Used by callers that need to distinguish "default" from "explicit".
function Operator:recipient()
  return self._recipient
end

function Operator:signer()
  return self._signer
end

function Operator:fee_payer()
  return self._fee_payer
end

-- Snapshot for logging / debugging. Stable shape across SDKs.
function Operator:to_summary()
  return {
    recipient     = self._recipient,
    signer_pubkey = self._signer:pubkey(),
    signer_demo   = self._signer:demo(),
    fee_payer     = self._fee_payer,
  }
end

return M
