# examples/playground_api/constants.py
"""Example-specific constants.

Program ids and the USDC mint come straight from ``pay_kit._paycore`` at the
call sites; only knobs without an SDK equivalent live here. Mirrors the Go
example's ``constants.go``.
"""

from __future__ import annotations

from pay_kit._paycore.solana import SYSTEM_PROGRAM, TOKEN_PROGRAM, resolve_mint

# usdc_decimals is the USDC token decimal count. The SDK does not export a
# decimals constant (the umbrella surface, the paycore layer, and the MPP
# protocol adapter all default to 6 internally), so the example pins it locally.
USDC_DECIMALS = 6

# sol_fund_lamports is the faucet SOL amount (100 SOL).
SOL_FUND_LAMPORTS = 100_000_000_000

# usdc_fund_amount is the faucet USDC amount (100 USDC at 6 decimals).
USDC_FUND_AMOUNT = 100_000_000

# usdc_mainnet_mint is the canonical USDC mint. Surfpool clones mainnet state,
# so localnet charges and the faucet settle against the mainnet mint.
USDC_MAINNET_MINT = resolve_mint("USDC", "mainnet")

# system_program / token_program are re-exported from paycore so the faucet
# cheatcode payloads always agree with the SDK's wire values.
SYSTEM_PROGRAM_ID = SYSTEM_PROGRAM
TOKEN_PROGRAM_ID = TOKEN_PROGRAM
