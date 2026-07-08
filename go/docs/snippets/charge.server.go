//go:build ignore

// Server-side charge: gate a net/http route with the paykit umbrella.
//
// Mirrors go/examples/simple-server/main.go. See
// ../../../docs/snippets-convention.md for the snippet:start/end convention —
// only the marked region is shown; the rest keeps the file compilable.
package main

import (
	"fmt"
	"net/http"

	_ "github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	_ "github.com/solana-foundation/pay-kit/go/paykit/adapters/mpp"
	_ "github.com/solana-foundation/pay-kit/go/paykit/adapters/x402"
)

func main() {
	// snippet:start
	client, err := paykit.New(paykit.Config{
		Network: paykit.SolanaLocalnet,
		Accept:  []paykit.Protocol{paykit.X402, paykit.MPP},
		MPP: paykit.MPPConfig{
			Realm:                  "MyApp",
			ChallengeBindingSecret: []byte("local-dev-secret"),
		},
	})
	if err != nil {
		panic(err)
	}

	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.01"), Desc: "Stock quote"}

	// client.Require(gate) is func(http.Handler) http.Handler — it settles the
	// 402 (MPP or x402, the client's choice) before your handler runs.
	mux := http.NewServeMux()
	mux.Handle("${PATH}", client.Require(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pmt, _ := paykit.PaymentFrom(r.Context())
		fmt.Fprintf(w, `{"ok":true,"paid_via":%q}`, pmt.Protocol)
	})))
	// snippet:end

	http.ListenAndServe(":4567", mux)
}
