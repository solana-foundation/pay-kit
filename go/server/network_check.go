package server

import (
	"fmt"
	"strings"

	"github.com/solana-foundation/pay-kit/go"
)

// SurfpoolBlockhashPrefix is the base58 prefix embedded in every blockhash
// returned by the Surfpool localnet implementation. Servers configured for
// any network OTHER than localnet use this prefix to detect wrong-RPC
// client mistakes.
const SurfpoolBlockhashPrefix = "SURFNETxSAFEHASH"

// LocalnetNetwork is the network slug for Solana's local validator. The
// only network for which a Surfpool-prefixed blockhash is valid.
const LocalnetNetwork = "localnet"

// CheckNetworkBlockhash is an asymmetric check: it rejects credentials
// whose signed blockhash carries the Surfpool prefix when the server is
// configured for any network other than `localnet`.
//
// Returns nil in every other case — a non-Surfpool blockhash is
// undetectable as wrong-cluster from the slug alone, so we let the
// downstream broadcast handle it.
func CheckNetworkBlockhash(network, blockhashB58 string) error {
	if !strings.HasPrefix(blockhashB58, SurfpoolBlockhashPrefix) {
		return nil
	}
	if network == LocalnetNetwork {
		return nil
	}
	_ = blockhashB58 // intentionally unused: blockhash detail is debug-grade,
	// not actionable for end users — keep the message terse.
	return mpp.NewError(mpp.ErrCodeWrongNetwork, fmt.Sprintf(
		"Signed against localnet but the server expects %s. "+
			"Switch your client RPC to %s and re-sign.",
		network, network,
	))
}
