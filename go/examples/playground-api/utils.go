package main

// Shared helpers: ANSI color helpers, the surfnet JSON-RPC cheatcode
// caller, and the settlement / receipt log lines.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

const ansiReset = "\x1b[0m"

func dim(s string) string     { return "\x1b[2m" + s + ansiReset }
func green(s string) string   { return "\x1b[32m" + s + ansiReset }
func cyan(s string) string    { return "\x1b[36m" + s + ansiReset }
func yellow(s string) string  { return "\x1b[33m" + s + ansiReset }
func magenta(s string) string { return "\x1b[35m" + s + ansiReset }
func bold(s string) string    { return "\x1b[1m" + s + ansiReset }

// rpcCall performs a JSON-RPC call against the surfnet endpoint and returns
// the raw result. Used for the surfnet_* cheatcodes the standard RPC client
// does not expose.
func rpcCall(ctx context.Context, rpcURL, method string, params []any) (json.RawMessage, error) {
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost, rpcURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	var body struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, err
	}
	if body.Error != nil {
		return nil, fmt.Errorf("%s: %s", method, body.Error.Message)
	}
	return body.Result, nil
}

// logTx prints a settlement-signature link for quick eyeball debugging.
func logTx(path, reference string) {
	studio := os.Getenv("STUDIO_PORT")
	if studio == "" {
		studio = "18488"
	}
	log.Printf("  %s %s  %s %s", green("ok"), path, dim("tx:"),
		cyan(fmt.Sprintf("http://localhost:%s/?t=%s", studio, reference)))
}

// logPayment prints the receipt reference from a Payment-Receipt response
// header, when present.
func logPayment(path string, header http.Header) {
	value := header.Get(core.PaymentReceiptHeader)
	if value == "" {
		return
	}
	receipt, err := core.ParseReceipt(value)
	if err != nil || receipt.Reference == "" {
		return
	}
	logTx(path, receipt.Reference)
}

// writeJSON writes v as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError writes the standard {"error": message} JSON error body.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
