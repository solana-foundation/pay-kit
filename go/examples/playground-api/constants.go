package main

// Shared constants mirroring
// typescript/examples/playground-api/shared/constants.ts.

const (
	// usdcMint is the mainnet USDC mint. Surfpool clones it from the
	// datasource network, so the same mint works on the hosted localnet.
	usdcMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

	// usdcDecimals is the USDC token decimal count.
	usdcDecimals = 6

	// tokenProgram is the SPL Token program id.
	tokenProgram = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

	// systemProgram is the System program id.
	systemProgram = "11111111111111111111111111111111"

	// solFundLamports is the faucet SOL amount (100 SOL).
	solFundLamports = 100_000_000_000

	// usdcFundAmount is the faucet USDC amount (100 USDC at 6 decimals).
	usdcFundAmount = 100_000_000
)
