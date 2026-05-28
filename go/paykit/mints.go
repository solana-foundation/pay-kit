package paykit

import "github.com/solana-foundation/pay-kit/go/paycore"

// ResolveMint returns the on-chain mint pubkey for the given
// stablecoin + network. Mirrors the cross-language behavior already
// implemented in [paycore.ResolveMint]; surfacing it here means
// downstream callers only import [paykit].
//
// Surfpool / hosted localnet clones mainnet state, so the localnet
// label falls back to the mainnet row when no localnet-specific entry
// is set (caveat #1 from Ruby PR #142).
func ResolveMint(coin Stablecoin, network Network) string {
	return paycore.ResolveMint(string(coin), network.MintsLabel())
}

// TokenProgramFor returns the SPL token program owning the mint for
// the given stablecoin + network. PYUSD / USDG / CASH ride the
// Token-2022 program; the rest live on the legacy SPL token program.
func TokenProgramFor(coin Stablecoin, network Network) string {
	return paycore.DefaultTokenProgramForCurrency(string(coin), network.MintsLabel())
}
