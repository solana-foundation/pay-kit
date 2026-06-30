//go:build ignore

// Server-side usage (`upto`): charge for actual usage up to a ceiling.
//
// Mirrors the usage-gated route in go/examples/playground-api/x402.go. Not one
// of the playground's four primitives, so the playground extractor ignores it —
// the SDK docs read it directly. See ../../../docs/snippets-convention.md.
package main

import (
	"net/http"

	"github.com/solana-foundation/pay-kit/go/paykit"
)

func usageServer(client *paykit.Client) {
	// snippet:start
	// A usage gate advertises Amount as the authorized ceiling; the handler
	// reports actual consumption and the gate settles that, refunding the rest.
	gate := paykit.Gate{
		Amount: paykit.MustParseUSD("1.00"),
		Desc:   "Summarize, billed per token",
		Kind:   paykit.GateUsage, // x402 upto; usage gates are x402-only
	}

	mux := http.NewServeMux()
	mux.Handle("${PATH}", client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Meter actual usage in base units; the gate settles it (clamped to the
		// ceiling) after the handler returns.
		if charge, ok := paykit.ChargeFrom(r.Context()); ok {
			charge.Charge(50_000) // 0.05 USDC
		}
		w.Write([]byte(`{"summary":"..."}`))
	})))
	// snippet:end
	_ = mux
}
