"""x402 ``batch-settlement`` (Solana) scheme: deposit once, pay per request with cumulative vouchers.

The client escrows funds in a payment-channels channel, then signs a
cumulative Ed25519 voucher per request; the server verifies it off-chain,
serves, and redeems the latest voucher on-chain later, in batches. Wire types
and parsers live in :mod:`.types`, failure codes in :mod:`.errors`, signed
encodings in :mod:`.signatures`.

Byte and field compatible with the Rust ``x402::protocol::schemes::batch_settlement``
for client-signed vouchers; the server-signed mode (``voucherSigner: "server"``)
follows the x402 PR #23 spec and is Python-to-Python only.
"""
