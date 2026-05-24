// Command payment-link-server runs the Go MPP payment-link example
// server backed by a Surfpool localnet RPC. It serves a single
// `/fortune` endpoint protected with the Solana MPP charge intent in
// HTML mode, exposes the generated service worker and an L6 canonical
// 402 JSON body for API clients, and pre-funds the recipient token
// account via Surfpool cheatcodes so a fresh localnet can settle a
// charge without a separate fixture step.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/errorcodes"
	"github.com/solana-foundation/pay-kit/go/protocol/core"
	"github.com/solana-foundation/pay-kit/go/server"
)

const csp = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src *; worker-src 'self'"

// rpcCall fires a single Surfpool JSON-RPC cheatcode (best-effort).
// Errors are surfaced to stderr but do not abort the example server;
// Surfpool will reject malformed cheatcodes with a 4xx that callers
// see on the next protected request.
func rpcCall(rpcURL, method string, params any) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		log.Printf("rpcCall: marshal %s: %v", method, err)
		return
	}
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("rpcCall: post %s: %v", method, err)
		return
	}
	_ = resp.Body.Close()
}

func main() {
	recipient := "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
	mint := "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	tokenProgram := "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

	// No fee payer — test mode client pays its own fees.
	m, err := server.New(server.Config{
		Recipient: recipient,
		SecretKey: "test-secret-key-do-not-use-in-production-1234567890abcdef",
		Network:   "localnet",
		RPCURL:    os.Getenv("RPC_URL"),
		Currency:  mint,
		Decimals:  6,
		HTML:      true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Fund recipient via surfpool cheatcodes so their token account exists.
	rpcURL := m.RPCURL()
	rpcCall(rpcURL, "surfnet_setAccount", []any{
		recipient, map[string]any{"lamports": 1_000_000_000, "data": "", "executable": false, "owner": "11111111111111111111111111111111", "rentEpoch": 0},
	})
	rpcCall(rpcURL, "surfnet_setTokenAccount", []any{
		recipient, mint, map[string]any{"amount": 0, "state": "initialized"}, tokenProgram,
	})

	http.HandleFunc("/fortune", func(w http.ResponseWriter, r *http.Request) {
		// Authenticated — verify credential on-chain.
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Payment ") {
			credential, err := core.ParseAuthorization(auth)
			if err != nil {
				log.Printf("parse_authorization: %v", err)
			} else {
				receipt, err := m.VerifyCredential(r.Context(), credential)
				if err != nil {
					log.Printf("verify_credential: %v", err)
				} else {
					receiptHeader, err := mpp.FormatReceipt(receipt)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set(mpp.PaymentReceiptHeader, receiptHeader)
					_ = json.NewEncoder(w).Encode(map[string]string{"fortune": "A smooth long journey!"})
					return
				}
			}
			// Fall through to re-issue challenge on failure.
		}

		// Service worker.
		if server.IsServiceWorkerRequest(r) {
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Service-Worker-Allowed", "/")
			fmt.Fprint(w, server.ServiceWorkerJS())
			return
		}

		challenge, err := m.ChargeWithOptions(r.Context(), "0.01", server.ChargeOptions{
			Description: "Open a fortune cookie",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		wwwAuth, err := core.FormatWWWAuthenticate(mpp.PaymentChallenge(challenge))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("WWW-Authenticate", wwwAuth)

		// Browser — HTML payment page.
		if server.AcceptsHTML(r) {
			html, err := m.ChallengeToHTML(challenge)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", csp)
			w.WriteHeader(http.StatusPaymentRequired)
			fmt.Fprint(w, html)
			return
		}

		// API client — canonical L6 problem+json 402 body.
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(errorcodes.NewPaymentRequiredBody(
			errorcodes.PaymentInvalid,
			"Payment required",
		))
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	log.Println("payment-link-server listening on :3002")
	log.Fatal(http.ListenAndServe(":3002", nil))
}
