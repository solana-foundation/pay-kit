// Dual-protocol PayKit example using the umbrella package.
//
//	cd go/examples/simple-server
//	go run .
//
// Then in another terminal:
//
//	curl http://127.0.0.1:4567/paid                # 402 with x402 + mpp accepts
//	pay --sandbox --x402 curl http://127.0.0.1:4567/paid
//	pay --sandbox --mpp  curl http://127.0.0.1:4567/paid
package main

import (
	"encoding/json"
	"log"
	"net/http"

	_ "github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	_ "github.com/solana-foundation/pay-kit/go/paykit/adapters/mpp"
	_ "github.com/solana-foundation/pay-kit/go/paykit/adapters/x402"
)

func main() {
	preflight := false
	client, err := paykit.New(paykit.Config{
		Network:   paykit.SolanaLocalnet,
		Preflight: &preflight,
		MPP: paykit.MPPConfig{
			Realm:                  "Go example",
			ChallengeBindingSecret: []byte("local-dev-secret"),
		},
	})
	if err != nil {
		log.Fatalf("paykit.New: %v", err)
	}

	paidGate := paykit.Gate{
		Amount: paykit.MustParseUSD("0.10"),
		Desc:   "Premium daily report",
	}

	mux := http.NewServeMux()
	mux.Handle("/paid", client.Require(paidGate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "paid": true})
	})))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	addr := "127.0.0.1:4567"
	log.Printf("paykit example listening on http://%s/paid", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
