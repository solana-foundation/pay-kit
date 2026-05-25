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
	"github.com/solana-foundation/pay-kit/go/protocol/core"
	"github.com/solana-foundation/pay-kit/go/server"
)

const csp = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src *; worker-src 'self'"

func rpcCall(rpcURL, method string, params interface{}) {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	http.Post(rpcURL, "application/json", bytes.NewReader(body))
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
	rpcCall(rpcURL, "surfnet_setAccount", []interface{}{
		recipient, map[string]interface{}{"lamports": 1_000_000_000, "data": "", "executable": false, "owner": "11111111111111111111111111111111", "rentEpoch": 0},
	})
	rpcCall(rpcURL, "surfnet_setTokenAccount", []interface{}{
		recipient, mint, map[string]interface{}{"amount": 0, "state": "initialized"}, tokenProgram,
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
					json.NewEncoder(w).Encode(map[string]string{"fortune": "A smooth long journey!"})
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
		wwwAuth, _ := core.FormatWWWAuthenticate(mpp.PaymentChallenge(challenge))
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

		// API client — JSON 402.
		w.WriteHeader(http.StatusPaymentRequired)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	log.Println("payment-link-server listening on :3002")
	log.Fatal(http.ListenAndServe(":3002", nil))
}
