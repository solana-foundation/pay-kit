// Package paykit is the Go umbrella SDK for Solana payment protocols.
//
// One module, one surface, two protocols underneath (x402, MPP).
// Wrap any http.Handler with [Client.Require] and the middleware
// picks the protocol per request from the inbound headers.
//
// # Quick start
//
//	import (
//	    "github.com/solana-foundation/pay-kit/go/paykit"
//	    _ "github.com/solana-foundation/pay-kit/go/paykit/schemes/mpp"
//	    _ "github.com/solana-foundation/pay-kit/go/paykit/schemes/x402"
//	    _ "github.com/solana-foundation/pay-kit/go/paykit/signer"
//	)
//
//	preflight := false
//	client, err := paykit.New(paykit.Config{
//	    Network:   paykit.SolanaLocalnet,
//	    Preflight: &preflight,
//	    MPP: paykit.MPPConfig{
//	        Realm: "MyApp",
//	        ChallengeBindingSecret: []byte("local-dev-secret"),
//	    },
//	})
//	if err != nil { log.Fatal(err) }
//
//	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/paid"}
//	mux := http.NewServeMux()
//	mux.Handle("/paid", client.Require(gate)(http.HandlerFunc(
//	    func(w http.ResponseWriter, r *http.Request) {
//	        w.Write([]byte(`{"ok":true,"paid":true}`))
//	    },
//	)))
//
// # Layout
//
// The umbrella surface lives in this package. Subpackages:
//
//   - [paykit/signer] -- local Ed25519 signer factories
//     (Demo / Generate / FromBytes / FromJSON / FromHex / FromBase58
//     / FromFile / FromEnv + MustXxx variants).
//   - [paykit/kms] -- remote enclave signer factories (future).
//   - [paykit/schemes/x402] -- x402-exact (Solana) adapter.
//   - [paykit/schemes/mpp] -- MPP-charge adapter (wraps the legacy
//     server.Mpp handler).
//
// See https://github.com/solana-foundation/pay-kit/issues/137 for
// the design rationale, vocabulary, and acceptance criteria.
package paykit
