package main

// Example-specific constants. Program ids and the USDC mint come straight
// from paycore at the call sites; only knobs without an SDK equivalent
// live here.

const (
	// usdcDecimals is the USDC token decimal count. The SDK does not
	// export a decimals constant (paykit, paycore, and protocols/mpp all
	// default to 6 internally), so the example pins it locally.
	usdcDecimals = 6

	// solFundLamports is the faucet SOL amount (100 SOL).
	solFundLamports = 100_000_000_000

	// usdcFundAmount is the faucet USDC amount (100 USDC at 6 decimals).
	usdcFundAmount = 100_000_000
)
