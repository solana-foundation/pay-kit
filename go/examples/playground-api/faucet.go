package main

// SOL + USDC airdrops via the surfnet cheatcodes.

import (
	"encoding/json"
	"net/http"

	"github.com/solana-foundation/pay-kit/go/paycore"
)

// registerFaucet mounts the faucet status and airdrop endpoints.
func registerFaucet(mux *http.ServeMux, a *app) {
	mux.HandleFunc("GET /api/v1/faucet/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"solAmount":  "100 SOL",
			"usdcAmount": "100 USDC",
			"usdcMint":   paycore.USDCMainnetMint,
		})
	})

	mux.HandleFunc("POST /api/v1/faucet/airdrop", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Address string `json:"address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Address == "" {
			writeJSONError(w, http.StatusBadRequest, "Missing `address` in request body")
			return
		}
		_, err := rpcCall(r.Context(), a.rpcURL, "surfnet_setAccount", []any{
			body.Address,
			map[string]any{
				"lamports":   solFundLamports,
				"data":       "",
				"executable": false,
				"owner":      paycore.SystemProgram,
				"rentEpoch":  0,
			},
		})
		if err == nil {
			_, err = rpcCall(r.Context(), a.rpcURL, "surfnet_setTokenAccount", []any{
				body.Address,
				paycore.USDCMainnetMint,
				map[string]any{"amount": usdcFundAmount, "state": "initialized"},
				paycore.TokenProgram,
			})
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":   "Airdrop failed",
				"details": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"sol":  "100 SOL",
			"usdc": "100 USDC",
		})
	})
}
