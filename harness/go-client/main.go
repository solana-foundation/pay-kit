// Canonical harness test client (Go).
//
// Tests the full payment cycle against any MPP server:
//
//  1. GET /health → 200
//  2. GET /fortune → 402 + WWW-Authenticate
//  3. Fund test keypair via surfpool
//  4. Build credential using solana-mpp Go client
//  5. GET /fortune with Authorization → 200 + fortune
//
// Usage: SERVER_URL=http://localhost:3001 RPC_URL=http://localhost:8899 go run .
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	x402client "github.com/solana-foundation/pay-kit/go/protocols/x402/client"
)

const fixtureSettlementHeader = "x-fixture-settlement"

type adapterResult struct {
	// Type is the harness message discriminator; always "result" here.
	Type string `json:"type"`
	// Implementation identifies the SDK under test; always "go" here.
	Implementation string `json:"implementation"`
	// Role is the side this adapter exercises; always "client" here.
	Role string `json:"role"`
	// OK reports whether the paid request ended with a 2xx status.
	OK bool `json:"ok"`
	// Status is the final HTTP status code of the paid request.
	Status int `json:"status"`
	// ResponseHeaders holds the final response headers, names lower-cased
	// and multi-value headers joined with ", ".
	ResponseHeaders map[string]string `json:"responseHeaders"`
	// ResponseBody is the final response body, JSON-decoded when it parses,
	// otherwise the raw string.
	ResponseBody any `json:"responseBody"`
	// Settlement echoes the x-fixture-settlement header the fixture server
	// sets with its settlement outcome; omitted when absent.
	Settlement string `json:"settlement,omitempty"`
}

func main() {
	switch resolveProtocolMode(os.Getenv) {
	case "x402-upto":
		if err := runX402UptoAdapter(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
	case "x402":
		if err := runX402Adapter(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
	case "mpp":
		if err := runProcessAdapter(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
	default:
		runLegacyHarness()
	}
}

// resolveProtocolMode picks the adapter protocol. The harness matrix injects
// BOTH MPP_HARNESS_TARGET_URL and X402_HARNESS_TARGET_URL on every client
// run, so the namespace probe alone is ambiguous: the explicit
// PAY_KIT_HARNESS_PROTOCOL hint set per scenario wins first. The probe order
// is only reached on manual runs that export a single TARGET_URL.
func resolveProtocolMode(getenv func(string) string) string {
	if mode := strings.ToLower(strings.TrimSpace(getenv("PAY_KIT_HARNESS_PROTOCOL"))); mode != "" {
		return mode
	}
	switch {
	case getenv("X402_HARNESS_TARGET_URL") != "":
		return "x402"
	case getenv("MPP_HARNESS_TARGET_URL") != "":
		return "mpp"
	default:
		return ""
	}
}

// runX402Adapter drives the x402 (exact) client against the target. It
// follows the x402 harness client contract: read the offer from the
// 402 challenge, select by preferred network + currency order, build and
// submit the Payment-Signature credential, then report the JSON result.
func runX402Adapter(stdout io.Writer) error {
	targetURL := os.Getenv("X402_HARNESS_TARGET_URL")
	rpcURL := os.Getenv("X402_HARNESS_RPC_URL")
	if rpcURL == "" {
		return fmt.Errorf("X402_HARNESS_RPC_URL is required")
	}
	signer, err := readPrivateKeyEnv("X402_HARNESS_CLIENT_SECRET_KEY")
	if err != nil {
		return err
	}
	transport := &x402client.PaymentTransport{
		Signer: signer,
		RPC:    rpc.New(rpcURL),
		Selection: x402client.ChallengeSelection{
			Network:    os.Getenv("X402_HARNESS_NETWORK"),
			Currencies: parseCurrencies(os.Getenv("X402_HARNESS_PREFER_CURRENCIES")),
		},
	}
	resp, err := (&http.Client{Transport: transport}).Get(targetURL)
	if err != nil {
		return fmt.Errorf("paid request: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	result := adapterResult{
		Type:            "result",
		Implementation:  "go",
		Role:            "client",
		OK:              resp.StatusCode >= 200 && resp.StatusCode < 300,
		Status:          resp.StatusCode,
		ResponseHeaders: responseHeaders(resp.Header),
		ResponseBody:    parseResponseBody(rawBody),
		Settlement:      resp.Header.Get(fixtureSettlementHeader),
	}
	return json.NewEncoder(stdout).Encode(result)
}

func runX402UptoAdapter(stdout io.Writer) error {
	targetURL := os.Getenv("X402_HARNESS_TARGET_URL")
	first, err := http.Get(targetURL)
	if err != nil {
		return fmt.Errorf("challenge request: %w", err)
	}
	defer first.Body.Close()
	firstBody, err := io.ReadAll(first.Body)
	if err != nil {
		return fmt.Errorf("read challenge body: %w", err)
	}
	requirements, ok := x402client.ParseUptoChallenge(first.Header, firstBody)
	if !ok {
		return fmt.Errorf("server did not return a supported x402 upto challenge")
	}

	signer, err := readPrivateKeyEnv("X402_HARNESS_CLIENT_SECRET_KEY")
	if err != nil {
		return err
	}
	header, err := x402client.BuildUptoHeader(
		context.Background(),
		signer,
		requirements,
		time.Now().Add(time.Hour).Unix(),
		fmt.Sprintf("go-upto-%d", time.Now().UnixNano()),
	)
	if err != nil {
		return fmt.Errorf("build upto payment header: %w", err)
	}
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Payment-Signature", header)
	if actual := os.Getenv("X402_HARNESS_ACTUAL_AMOUNT"); actual != "" {
		req.Header.Set("X402-HARNESS-ACTUAL-AMOUNT", actual)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("paid request: %w", err)
	}
	defer resp.Body.Close()
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	headers := responseHeaders(resp.Header)
	headers["payment-signature-sent"] = header
	settlementHeader := envOrDefault("X402_HARNESS_SETTLEMENT_HEADER", fixtureSettlementHeader)
	result := adapterResult{
		Type:            "result",
		Implementation:  "go",
		Role:            "client",
		OK:              resp.StatusCode >= 200 && resp.StatusCode < 300,
		Status:          resp.StatusCode,
		ResponseHeaders: headers,
		ResponseBody:    parseResponseBody(rawBody),
		Settlement:      resp.Header.Get(settlementHeader),
	}
	return json.NewEncoder(stdout).Encode(result)
}

// parseCurrencies splits the comma-separated client currency preference
// list. Empty input yields nil (cheapest-on-network selection).
func parseCurrencies(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runProcessAdapter(stdout io.Writer) error {
	targetURL := os.Getenv("MPP_HARNESS_TARGET_URL")
	rpcURL := os.Getenv("MPP_HARNESS_RPC_URL")
	if rpcURL == "" {
		return fmt.Errorf("MPP_HARNESS_RPC_URL is required")
	}

	signer, err := readPrivateKeyEnv("MPP_HARNESS_CLIENT_SECRET_KEY")
	if err != nil {
		return err
	}

	httpClient := client.NewClient(signer, rpc.New(rpcURL))
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		return fmt.Errorf("paid request: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	result := adapterResult{
		Type:            "result",
		Implementation:  "go",
		Role:            "client",
		OK:              resp.StatusCode >= 200 && resp.StatusCode < 300,
		Status:          resp.StatusCode,
		ResponseHeaders: responseHeaders(resp.Header),
		ResponseBody:    parseResponseBody(rawBody),
		Settlement:      resp.Header.Get(fixtureSettlementHeader),
	}
	return json.NewEncoder(stdout).Encode(result)
}

func readPrivateKeyEnv(name string) (solana.PrivateKey, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	var values []int
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if len(values) != 64 {
		return nil, fmt.Errorf("%s must contain 64 private key bytes, got %d", name, len(values))
	}
	key := make([]byte, len(values))
	for i, value := range values {
		if value < 0 || value > 255 {
			return nil, fmt.Errorf("%s byte %d is outside uint8 range", name, i)
		}
		key[i] = byte(value)
	}
	return solana.PrivateKey(key), nil
}

func responseHeaders(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		out[strings.ToLower(key)] = strings.Join(values, ", ")
	}
	return out
}

func parseResponseBody(raw []byte) any {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err == nil {
		return decoded
	}
	return string(raw)
}

func runLegacyHarness() {
	serverURL := envOrDefault("SERVER_URL", "http://localhost:3001")
	fortunePath := envOrDefault("FORTUNE_PATH", "/fortune")
	rpcURL := envOrDefault("RPC_URL", "http://localhost:8899")

	fmt.Printf("Harness test: Go client → %s\n", serverURL)
	fmt.Printf("RPC: %s\n", rpcURL)

	ctx := context.Background()
	httpClient := &http.Client{}
	rpcClient := rpc.New(rpcURL)

	// ── Test 1: Health ──
	fmt.Print("  health ... ")
	resp := mustGet(httpClient, serverURL+"/health")
	mustClose(resp.Body)
	assert(resp.StatusCode == 200, "health should return 200, got %d", resp.StatusCode)
	fmt.Println("OK")

	// ── Test 2: Challenge ──
	fmt.Print("  challenge ... ")
	resp = mustGet(httpClient, serverURL+fortunePath)
	mustClose(resp.Body)
	assert(resp.StatusCode == 402, "fortune without auth should return 402, got %d", resp.StatusCode)
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert(wwwAuth != "", "missing WWW-Authenticate header")
	assert(strings.HasPrefix(wwwAuth, "Payment "), "should use Payment scheme")
	challenge, err := core.ParseWWWAuthenticate(wwwAuth)
	mustOK(err, "parse challenge")
	assert(string(challenge.Method) == "solana", "method should be solana, got %s", challenge.Method)
	assert(string(challenge.Intent) == "charge", "intent should be charge, got %s", challenge.Intent)
	fmt.Printf("OK (id=%s…)\n", challenge.ID[:12])

	// ── Test 3: Fund test keypair via surfpool ──
	fmt.Print("  fund ... ")
	wallet := solana.NewWallet()
	signer := wallet.PrivateKey
	pubkey := signer.PublicKey()
	pubkeyStr := pubkey.String()

	// Decode request to get currency info
	var request map[string]any
	mustOK(challenge.Request.Decode(&request), "decode request")
	currency, _ := request["currency"].(string)
	if currency == "" {
		currency = "sol"
	}
	isNativeSOL := strings.EqualFold(currency, "sol")

	methodDetails, _ := request["methodDetails"].(map[string]any)
	tokenProgram := "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	if tp, ok := methodDetails["tokenProgram"].(string); ok && tp != "" {
		tokenProgram = tp
	}
	recipient, _ := request["recipient"].(string)

	// Fund SOL
	rpcCall(httpClient, rpcURL, "surfnet_setAccount", []any{
		pubkeyStr,
		map[string]any{
			"lamports":   2_000_000_000,
			"data":       "",
			"executable": false,
			"owner":      "11111111111111111111111111111111",
			"rentEpoch":  0,
		},
	})

	if !isNativeSOL {
		amountStr, _ := request["amount"].(string)
		if amountStr == "" {
			amountStr = "0"
		}
		// Fund payer token account
		rpcCall(httpClient, rpcURL, "surfnet_setTokenAccount", []any{
			pubkeyStr, currency,
			map[string]any{"amount": mustParseInt(amountStr), "state": "initialized"},
			tokenProgram,
		})
		// Ensure recipient has token account
		rpcCall(httpClient, rpcURL, "surfnet_setTokenAccount", []any{
			recipient, currency,
			map[string]any{"amount": 0, "state": "initialized"},
			tokenProgram,
		})
	}
	fmt.Printf("OK (pubkey=%s…)\n", pubkeyStr[:8])

	// ── Test 4: Build credential ──
	fmt.Print("  credential ... ")
	authHeader, err := client.BuildCredentialHeader(ctx, signer, rpcClient, challenge)
	mustOK(err, "build credential header")
	assert(strings.HasPrefix(authHeader, "Payment "), "credential should start with Payment")
	fmt.Println("OK")

	// ── Test 5: Submit and get fortune ──
	fmt.Print("  payment ... ")
	req, err := http.NewRequest("GET", serverURL+fortunePath, nil)
	mustOK(err, "create request")
	req.Header.Set("Authorization", authHeader)
	resp, err = httpClient.Do(req)
	mustOK(err, "payment request")
	body, _ := io.ReadAll(resp.Body)
	mustClose(resp.Body)
	assert(resp.StatusCode == 200, "payment should return 200, got %d: %s", resp.StatusCode, string(body))
	var data map[string]any
	mustOK(json.Unmarshal(body, &data), "parse response JSON")
	_, hasFortune := data["fortune"]
	assert(hasFortune, "response should contain fortune")
	fortune, _ := data["fortune"].(string)
	fmt.Printf("OK → %s\n", fortune)

	fmt.Println("\n  ✓ All harness tests passed")
}

// envOrDefault reads an env var with a fallback default.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// mustGet performs an HTTP GET and panics on error.
func mustGet(c *http.Client, url string) *http.Response {
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: GET %s: %v\n", url, err)
		os.Exit(1)
	}
	return resp
}

// mustClose closes a body, ignoring errors.
func mustClose(body io.ReadCloser) {
	if body != nil {
		_, _ = io.ReadAll(body)
		body.Close()
	}
}

// mustOK panics if err is non-nil.
func mustOK(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", msg, err)
		os.Exit(1)
	}
}

// assert panics when a condition is false.
func assert(condition bool, format string, args ...any) {
	if !condition {
		fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
		os.Exit(1)
	}
}

// rpcCall sends a JSON-RPC request to surfpool.
func rpcCall(c *http.Client, rpcURL, method string, params any) {
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	mustOK(err, "marshal RPC payload")
	resp, err := c.Post(rpcURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: RPC %s: %v\n", method, err)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var result map[string]any
	mustOK(json.Unmarshal(body, &result), "parse RPC response")
	if errField, ok := result["error"]; ok {
		fmt.Fprintf(os.Stderr, "FAIL: RPC %s error: %v\n", method, errField)
		os.Exit(1)
	}
}

func mustParseInt(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
