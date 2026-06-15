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
//	    _ "github.com/solana-foundation/pay-kit/go/protocols/mpp"
//	    _ "github.com/solana-foundation/pay-kit/go/protocols/x402"
//	    _ "github.com/solana-foundation/pay-kit/go/paycore/signer"
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
//   - [signer] -- local Ed25519 signer factories
//     (Demo / Generate / FromBytes / FromJSON / FromHex / FromBase58
//     / FromFile / FromEnv + MustXxx variants).
//   - [protocols/x402] -- x402-exact (Solana) adapter.
//   - [protocols/mpp] -- MPP-charge adapter (wraps the legacy
//     server.Mpp handler).
//
// # Framework-host quirks (issue #137 caveat #6)
//
// Each language's port has to absorb its host framework's friction
// points. Go's net/http stack is the most permissive of the bunch
// across the cross-language matrix:
//
//   - Header casing: net/http accepts mixed-case writes by default,
//     so the wire-level Payment-Required / WWW-Authenticate header
//     names round-trip unchanged. No Rack-3-style lowercase
//     enforcement is needed.
//   - Status pre-empting: there is no Go analogue of the PHP CLI
//     dev server's "WWW-Authenticate auto-401" quirk; whatever
//     [http.ResponseWriter.WriteHeader] receives is what the wire
//     emits.
//   - Exception pipeline: middleware short-circuits via direct
//     [http.ResponseWriter] writes + return; there is no Sinatra
//     "halt before handler" hook to thread around.
//
// See https://github.com/solana-foundation/pay-kit/issues/137 for
// the design rationale, vocabulary, and acceptance criteria.
package paykit
