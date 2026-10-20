package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fixtureMint mirrors harness/src/conformance/fixture-rpc.ts FixtureMint.
type fixtureMint struct {
	Owner    string `json:"owner"`
	Decimals uint8  `json:"decimals"`
}

// rpcFixtures mirrors the harness VectorRpcFixtures.
type rpcFixtures struct {
	RecentBlockhash string                 `json:"recentBlockhash"`
	Mints           map[string]fixtureMint `json:"mints"`
}

// startFixtureRPC is the Go-test twin of the harness fixture JSON-RPC: it
// serves getLatestBlockhash, getAccountInfo (82-byte mint layout) and
// getMinimumBalanceForRentExemption from a vector's rpcFixtures, so the
// runner reads chain state through the SDK exactly as under the driver.
func startFixtureRPC(t *testing.T, fixtures rpcFixtures) string {
	t.Helper()
	blockhash := fixtures.RecentBlockhash
	if blockhash == "" {
		blockhash = "11111111111111111111111111111111"
	}
	context := map[string]any{"apiVersion": "2.0.0", "slot": 100}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		switch req.Method {
		case "getLatestBlockhash":
			resp["result"] = map[string]any{"context": context, "value": map[string]any{"blockhash": blockhash, "lastValidBlockHeight": 1000}}
		case "getAccountInfo":
			var address string
			if len(req.Params) > 0 {
				_ = json.Unmarshal(req.Params[0], &address)
			}
			var value any
			if mint, ok := fixtures.Mints[address]; ok {
				data := make([]byte, 82)
				data[44] = mint.Decimals
				data[45] = 1
				value = map[string]any{
					"data":       []string{base64.StdEncoding.EncodeToString(data), "base64"},
					"executable": false,
					"lamports":   1461600,
					"owner":      mint.Owner,
					"rentEpoch":  0,
					"space":      82,
				}
			}
			resp["result"] = map[string]any{"context": context, "value": value}
		case "getMinimumBalanceForRentExemption":
			resp["result"] = 2039280
		default:
			resp["error"] = map[string]any{"code": -32601, "message": "method " + req.Method + " is not served by the conformance fixture RPC"}
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)
	return server.URL
}
