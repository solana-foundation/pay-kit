--[[
Solana transaction codec for legacy and v0 (versioned) messages.

Mirrors `ruby/lib/mpp/methods/solana/transaction.rb`. Parses the wire
bytes a Solana JSON-RPC `sendTransaction` payload carries, exposes the
header / account-keys / blockhash / instructions table the verifier and
the signer iterate over, and can re-serialize the parsed envelope back
to bytes so the cosign path can overwrite one signature in place.

The codec speaks the same compact-u16 LEB128-like length prefix
Solana uses for signature counts, account-key counts, instruction
counts, and the inner per-instruction account / data lengths.
]]

local base58 = require('mpp.util.base58')
local base64_std = require('mpp.util.base64_std')

local M = {}

-- Cursor over a raw byte string. Implementation-private; consumers go through
-- the M.parse / M.from_base64 functions.
local Cursor = {}
Cursor.__index = Cursor

local function new_cursor(raw)
  return setmetatable({ raw = raw, offset = 1 }, Cursor)
end

function Cursor:remaining()
  return self.raw:sub(self.offset)
end

function Cursor:peek()
  if self.offset > #self.raw then
    error('unexpected end of transaction')
  end
  return self.raw:byte(self.offset)
end

function Cursor:byte()
  if self.offset > #self.raw then
    error('unexpected end of transaction')
  end
  local value = self.raw:byte(self.offset)
  self.offset = self.offset + 1
  return value
end

function Cursor:bytes(count)
  if self.offset + count - 1 > #self.raw then
    error('unexpected end of transaction')
  end
  local value = self.raw:sub(self.offset, self.offset + count - 1)
  self.offset = self.offset + count
  return value
end

function Cursor:compact_u16()
  local value = 0
  local shift = 0
  while true do
    local byte = self:byte()
    value = value + (byte % 128) * (2 ^ shift)
    if byte < 128 then
      break
    end
    shift = shift + 7
    if shift > 21 then
      error('compact-u16 is too long')
    end
  end
  return value
end

--- Encode a length as a compact-u16 byte string. Public because the cosign
--- re-serialization path rebuilds the signature-count prefix.
function M.compact_u16(value)
  local bytes = {}
  while true do
    local byte = value % 128
    value = math.floor(value / 128)
    if value > 0 then
      byte = byte + 128
    end
    bytes[#bytes + 1] = string.char(byte)
    if value == 0 then
      break
    end
  end
  return table.concat(bytes)
end

-- Parse one v0 address-table lookup entry.
local function parse_lookup(cursor)
  cursor:bytes(32) -- table account; verified by the verifier through transaction.account_keys
  local writable_count = cursor:compact_u16()
  local writable = {}
  for _ = 1, writable_count do
    writable[#writable + 1] = cursor:byte()
  end
  local readonly_count = cursor:compact_u16()
  local readonly = {}
  for _ = 1, readonly_count do
    readonly[#readonly + 1] = cursor:byte()
  end
  return { writable = writable, readonly = readonly }
end

-- Parse a compiled instruction. The data length is a compact-u16 that
-- precedes the data bytes; the data itself is opaque to the codec.
local function parse_instruction(cursor)
  local program_id_index = cursor:byte()
  local accounts_count = cursor:compact_u16()
  local accounts = {}
  for _ = 1, accounts_count do
    accounts[#accounts + 1] = cursor:byte()
  end
  local data_length = cursor:compact_u16()
  local data = cursor:bytes(data_length)
  return {
    program_id_index = program_id_index,
    accounts = accounts,
    data = data,
  }
end

-- Parse a Solana transaction message. Both legacy (no version byte) and v0
-- (leading 0x80 prefix) are accepted; v0 transactions additionally carry
-- a list of address-table-lookup entries the verifier inspects via
-- `message.address_table_lookups`.
local function parse_message(raw)
  local cursor = new_cursor(raw)
  local version = 'legacy'
  local first = cursor:peek()
  if first >= 128 then
    local version_byte = first - 128
    if version_byte ~= 0 then
      error('unsupported transaction version: ' .. tostring(version_byte))
    end
    version = 0
    cursor:byte()
  end
  local header = {
    required_signatures = cursor:byte(),
    readonly_signed = cursor:byte(),
    readonly_unsigned = cursor:byte(),
  }
  local account_count = cursor:compact_u16()
  local account_keys = {}
  for _ = 1, account_count do
    account_keys[#account_keys + 1] = base58.encode(cursor:bytes(32))
  end
  local recent_blockhash = base58.encode(cursor:bytes(32))
  local instruction_count = cursor:compact_u16()
  local instructions = {}
  for _ = 1, instruction_count do
    instructions[#instructions + 1] = parse_instruction(cursor)
  end
  local lookups = {}
  if version == 0 then
    local lookup_count = cursor:compact_u16()
    for _ = 1, lookup_count do
      lookups[#lookups + 1] = parse_lookup(cursor)
    end
  end
  return {
    raw = raw,
    version = version,
    header = header,
    account_keys = account_keys,
    recent_blockhash = recent_blockhash,
    instructions = instructions,
    address_table_lookups = lookups,
  }
end

--- Parse a Solana transaction from raw wire bytes. Returns the parsed
--- envelope: signatures, message, message_offset, version.
function M.from_bytes(raw)
  local cursor = new_cursor(raw)
  local signature_count = cursor:compact_u16()
  local signatures = {}
  for _ = 1, signature_count do
    signatures[#signatures + 1] = cursor:bytes(64)
  end
  local message_offset = cursor.offset
  local message = parse_message(cursor:remaining())
  return {
    signatures = signatures,
    message = message,
    message_offset = message_offset,
    version = message.version,
  }
end

--- Parse a Solana transaction from a standard padded base64 string.
function M.from_base64(value)
  local ok, raw_or_err = pcall(base64_std.decode, value)
  if not ok then
    error('invalid transaction payload: ' .. tostring(raw_or_err))
  end
  return M.from_bytes(raw_or_err)
end

--- Re-serialize a parsed transaction back to wire bytes. Uses the parsed
--- message.raw verbatim so signing-payload alignment never drifts.
function M.to_bytes(tx)
  local parts = { M.compact_u16(#tx.signatures) }
  for i = 1, #tx.signatures do
    parts[#parts + 1] = tx.signatures[i]
  end
  parts[#parts + 1] = tx.message.raw
  return table.concat(parts)
end

--- Re-serialize a parsed transaction back to a standard padded base64 string.
function M.to_base64(tx)
  return base64_std.encode(M.to_bytes(tx))
end

--- Replace the signature at the given index with new bytes. Errors if the
--- index is out of range or the signature length is not 64.
function M.replace_signature(tx, index, signature_bytes)
  if type(signature_bytes) ~= 'string' or #signature_bytes ~= 64 then
    error('signature must be exactly 64 bytes')
  end
  if index < 1 or index > #tx.signatures then
    error('signature index out of range')
  end
  tx.signatures[index] = signature_bytes
end

--- Locate the account-key index for a base58 pubkey or return nil. Used by
--- the signer to discover the fee-payer's slot in `signatures`.
function M.index_of_account(tx, pubkey)
  for i = 1, #tx.message.account_keys do
    if tx.message.account_keys[i] == pubkey then
      return i
    end
  end
  return nil
end

M.parse_message = parse_message

return M
