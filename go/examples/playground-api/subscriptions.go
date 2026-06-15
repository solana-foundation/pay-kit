package main

// Subscriptions module. The Go SDK does not implement the subscription
// server method yet, so this module keeps the /api/v1/premium/feed route
// (nothing is silently dropped) and answers 501 with an explicit pointer at
// the gap. The endpoint catalog omits the subscription entry, so the
// playground UI renders its graceful empty state. See README.md.

import "net/http"

// registerSubscriptions mounts the documented subscription stub.
func registerSubscriptions(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/premium/feed", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "not_implemented",
			"detail": "The Go SDK does not ship the solana.subscription server method yet; " +
				"this route exists for parity with typescript/examples/playground-api and " +
				"will be gated once the Go subscription intent lands.",
		})
	})
}
