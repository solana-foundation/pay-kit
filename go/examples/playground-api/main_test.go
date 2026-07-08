package main

// Offline smoke test for the playground API: boots the full route table
// against a stub JSON-RPC server (no network, no funded accounts) and checks
// every endpoint's unauthenticated behavior.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paykit"
)

// newStubRPC serves the JSON-RPC answers the playground needs at boot and
// challenge-build time.
func newStubRPC(t *testing.T, blockhash string) *httptest.Server {
	t.Helper()
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		var result any
		switch request.Method {
		case "getLatestBlockhash":
			result = map[string]any{
				"context": map[string]any{"slot": 1},
				"value": map[string]any{
					"blockhash":            blockhash,
					"lastValidBlockHeight": 100,
				},
			}
		case "getBalance":
			result = map[string]any{
				"context": map[string]any{"slot": 1},
				"value":   5_000_000_000,
			}
		case "sendTransaction":
			result = "stub-signature"
		default:
			result = "ok"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      request.ID,
			"result":  result,
		})
	}))
	t.Cleanup(stub.Close)
	return stub
}

// newTestServer boots the playground handler against the stub RPC.
func newTestServer(t *testing.T) (*httptest.Server, *app) {
	t.Helper()
	t.Setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")

	feePayer, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("generate fee payer: %v", err)
	}
	blockhash, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("generate blockhash: %v", err)
	}
	stub := newStubRPC(t, blockhash.PublicKey().String())

	a := &app{
		network:   "localnet",
		rpcURL:    stub.URL,
		recipient: feePayer.PublicKey().String(),
		secretKey: "playground-smoke-secret-0123456789ab",
		feePayer:  feePayer,
		rpcClient: rpc.New(stub.URL),
		repoRoot:  t.TempDir(), // empty root: no docs generated, no SPA dist
	}
	handler, shutdown, err := newApp(a)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(shutdown)
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)
	return httpServer, a
}

// doRequest performs a request and returns the response with its body read.
func doRequest(t *testing.T, method, url string, body string, header map[string]string) (*http.Response, string) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		request.Header.Set(k, v)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response, string(raw)
}

// decodeBody unmarshals a JSON response body.
func decodeBody(t *testing.T, body string, out any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), out); err != nil {
		t.Fatalf("unmarshal %q: %v", body, err)
	}
}

func TestPlaygroundEndpoints(t *testing.T) {
	httpServer, a := newTestServer(t)
	base := httpServer.URL

	t.Run("health", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/api/v1/health", "", nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %s", response.StatusCode, body)
		}
		var health struct {
			OK              bool     `json:"ok"`
			FeePayer        string   `json:"feePayer"`
			FeePayerBalance *float64 `json:"feePayerBalance"`
			Recipient       string   `json:"recipient"`
			Network         string   `json:"network"`
			RPCURL          string   `json:"rpcUrl"`
		}
		decodeBody(t, body, &health)
		if !health.OK || health.FeePayer != a.feePayer.PublicKey().String() ||
			health.Recipient != a.recipient || health.Network != "localnet" || health.RPCURL != a.rpcURL {
			t.Fatalf("health = %+v", health)
		}
		if health.FeePayerBalance == nil || *health.FeePayerBalance != 5 {
			t.Fatalf("feePayerBalance = %v, want 5", health.FeePayerBalance)
		}
	})

	t.Run("config catalog", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/api/v1/config", "", nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %s", response.StatusCode, body)
		}
		var config struct {
			Recipient string         `json:"recipient"`
			FeePayer  string         `json:"feePayer"`
			Endpoints []endpointInfo `json:"endpoints"`
		}
		decodeBody(t, body, &config)
		if config.Recipient != a.recipient {
			t.Fatalf("recipient = %q", config.Recipient)
		}
		ids := map[string]endpointInfo{}
		for _, e := range config.Endpoints {
			ids[e.ID] = e
		}
		for _, want := range []string{"quote", "fortune", "joke", "summarize", "sessions-stream"} {
			if _, ok := ids[want]; !ok {
				t.Fatalf("catalog missing %q: %s", want, body)
			}
		}
		if ids["sessions-stream"].Path != "/api/v1/stream" || ids["sessions-stream"].UnitPrice != "100" {
			t.Fatalf("stream catalog = %+v", ids["sessions-stream"])
		}
		if ids["quote"].Path != "/api/v1/quote/:symbol" || ids["summarize"].Primitive != "x402" {
			t.Fatalf("catalog = %+v / %+v", ids["quote"], ids["summarize"])
		}
		if _, ok := ids["premium-feed"]; ok {
			t.Fatal("catalog must omit the subscription entry (no Go subscription method)")
		}
	})

	t.Run("openapi discovery feeds the playground app", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/openapi.json", "", nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %s", response.StatusCode, body)
		}
		var doc openAPIDoc
		decodeBody(t, body, &doc)
		if doc.OpenAPI != "3.1.0" {
			t.Fatalf("openapi = %q", doc.OpenAPI)
		}
		quote := doc.Paths["/api/v1/quote/{symbol}"]["get"]
		if quote.Summary != "Stock quote" || len(quote.XPaymentInfo.Offers) != 2 {
			t.Fatalf("quote operation = %+v", quote)
		}
		if quote.Responses["200"].Description == "" || quote.Responses["402"].Description == "" {
			t.Fatalf("quote responses = %+v", quote.Responses)
		}
		quoteMethods := map[string]openAPIOffer{}
		for _, offer := range quote.XPaymentInfo.Offers {
			quoteMethods[offer.Method] = offer
		}
		for _, method := range []string{"x402", "mpp"} {
			offer, ok := quoteMethods[method]
			if !ok || offer.Intent != "charge" ||
				offer.PayTo != a.recipient || offer.Network != paykit.SolanaLocalnet.CAIP2() ||
				offer.FeePayer != a.feePayer.PublicKey().String() {
				t.Fatalf("quote %s offer = %+v", method, offer)
			}
		}
		if quoteMethods["x402"].Scheme != "exact" || quoteMethods["mpp"].Scheme != "charge" {
			t.Fatalf("quote offers = %+v", quote.XPaymentInfo.Offers)
		}
		fortuneMethods := map[string]openAPIOffer{}
		for _, offer := range doc.Paths["/api/v1/fortune"]["get"].XPaymentInfo.Offers {
			fortuneMethods[offer.Method] = offer
		}
		if fortuneMethods["x402"].Scheme != "exact" || fortuneMethods["x402"].Amount != "10000" ||
			fortuneMethods["mpp"].Scheme != "charge" || fortuneMethods["mpp"].Amount != "10000" {
			t.Fatalf("fortune offers = %+v", doc.Paths["/api/v1/fortune"]["get"].XPaymentInfo.Offers)
		}
		joke := doc.Paths["/api/v1/joke"]["get"].XPaymentInfo.Offers[0]
		if joke.Amount != "10000" || joke.Method != "mpp" || joke.Scheme != "charge" {
			t.Fatalf("joke offer = %+v", joke)
		}
		stream := doc.Paths["/api/v1/stream"]["get"].XPaymentInfo.Offers[0]
		if stream.Intent != "session" || stream.UnitPrice != "100" {
			t.Fatalf("stream offer = %+v", stream)
		}
		summarize := doc.Paths["/api/v1/summarize"]["post"].XPaymentInfo.Offers[0]
		if summarize.Method != "x402" || summarize.Intent != "charge" ||
			summarize.Scheme != "upto" || summarize.Amount != "100000" {
			t.Fatalf("summarize offer = %+v", summarize)
		}
	})

	t.Run("charge endpoints issue MPP challenges", func(t *testing.T) {
		for _, path := range []string{
			"/api/v1/stocks/quote/AAPL",
			"/api/v1/joke",
			"/api/v1/stocks/search?q=apple",
			"/api/v1/stocks/history/AAPL",
			"/api/v1/weather/tokyo",
			"/api/v1/marketplace/buy/sol-hoodie",
		} {
			response, body := doRequest(t, http.MethodGet, base+path, "", nil)
			if response.StatusCode != http.StatusPaymentRequired {
				t.Fatalf("%s status = %d: %s", path, response.StatusCode, body)
			}
			wwwAuth := response.Header.Get("WWW-Authenticate")
			if !strings.Contains(wwwAuth, "intent=\"charge\"") {
				t.Fatalf("%s WWW-Authenticate = %q", path, wwwAuth)
			}
			var challenge struct {
				Error   string `json:"error"`
				Accepts []struct {
					Protocol string `json:"protocol"`
				} `json:"accepts"`
			}
			decodeBody(t, body, &challenge)
			if challenge.Error != "payment_required" || len(challenge.Accepts) != 1 || challenge.Accepts[0].Protocol != "mpp" {
				t.Fatalf("%s challenge body = %s", path, body)
			}
		}
	})

	t.Run("fixed TS-reference endpoints issue dual protocol challenges", func(t *testing.T) {
		for _, path := range []string{"/api/v1/quote/SPCX", "/api/v1/fortune"} {
			response, body := doRequest(t, http.MethodGet, base+path, "", nil)
			if response.StatusCode != http.StatusPaymentRequired {
				t.Fatalf("%s status = %d: %s", path, response.StatusCode, body)
			}
			var challenge struct {
				Error   string `json:"error"`
				Accepts []struct {
					Protocol string `json:"protocol"`
					Scheme   string `json:"scheme"`
				} `json:"accepts"`
			}
			decodeBody(t, body, &challenge)
			seen := map[string]string{}
			for _, accept := range challenge.Accepts {
				seen[accept.Protocol] = accept.Scheme
			}
			if challenge.Error != "payment_required" || seen["x402"] != "exact" || seen["mpp"] != "charge" {
				t.Fatalf("%s challenge = %s", path, body)
			}
		}
	})

	t.Run("pre-gate validation runs before payment", func(t *testing.T) {
		for path, wantStatus := range map[string]int{
			"/api/v1/weather/atlantis":          http.StatusNotFound,
			"/api/v1/marketplace/buy/unknown":   http.StatusNotFound,
			"/api/v1/stocks/search":             http.StatusBadRequest,
			"/api/v1/marketplace/buy/sol-shirt": http.StatusNotFound,
		} {
			response, body := doRequest(t, http.MethodGet, base+path, "", nil)
			if response.StatusCode != wantStatus {
				t.Fatalf("%s status = %d, want %d: %s", path, response.StatusCode, wantStatus, body)
			}
		}
	})

	t.Run("summarize body validation runs before payment", func(t *testing.T) {
		response, body := doRequest(t, http.MethodPost, base+"/api/v1/summarize",
			strings.Repeat("x", summarizeMaxBodyBytes+1), nil)
		if response.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(body, "body-too-large") {
			t.Fatalf("status = %d body = %s", response.StatusCode, body)
		}
		if response.Header.Get("Payment-Required") != "" || response.Header.Get("WWW-Authenticate") != "" {
			t.Fatalf("body validation should run before payment headers: %+v", response.Header)
		}
	})

	t.Run("marketplace products are free", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/api/v1/marketplace/products", "", nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %s", response.StatusCode, body)
		}
		var list []struct {
			ID       string `json:"id"`
			PriceRaw string `json:"priceRaw"`
		}
		decodeBody(t, body, &list)
		if len(list) != 3 || list[0].ID != "sol-hoodie" || list[0].PriceRaw != "2000000" {
			t.Fatalf("products = %s", body)
		}
	})

	t.Run("fortune serves JSON, HTML, and service worker challenges", func(t *testing.T) {
		response, _ := doRequest(t, http.MethodGet, base+"/api/v1/fortune", "", nil)
		if response.StatusCode != http.StatusPaymentRequired ||
			!strings.Contains(response.Header.Get("Content-Type"), "json") {
			t.Fatalf("JSON challenge: status = %d type = %q", response.StatusCode, response.Header.Get("Content-Type"))
		}

		response, _ = doRequest(t, http.MethodGet, base+"/api/v1/fortune", "", map[string]string{"Accept": "text/html"})
		if response.StatusCode != http.StatusPaymentRequired ||
			!strings.Contains(response.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("HTML challenge: status = %d type = %q", response.StatusCode, response.Header.Get("Content-Type"))
		}

		response, body := doRequest(t, http.MethodGet, base+"/api/v1/fortune?__mpp_worker", "", nil)
		if response.StatusCode != http.StatusOK ||
			!strings.Contains(response.Header.Get("Content-Type"), "javascript") ||
			response.Header.Get("Service-Worker-Allowed") != "/" {
			t.Fatalf("service worker: status = %d type = %q sw-allowed = %q body = %.40s",
				response.StatusCode, response.Header.Get("Content-Type"),
				response.Header.Get("Service-Worker-Allowed"), body)
		}
	})

	t.Run("sessions issue session challenges", func(t *testing.T) {
		for _, route := range []struct {
			method string
			path   string
		}{
			{method: http.MethodGet, path: "/sessions/stream"},
			{method: http.MethodGet, path: "/api/v1/stream"},
			{method: http.MethodPost, path: "/sessions/compute"},
		} {
			response, body := doRequest(t, route.method, base+route.path, "", nil)
			if response.StatusCode != http.StatusPaymentRequired {
				t.Fatalf("%s %s status = %d: %s", route.method, route.path, response.StatusCode, body)
			}
			wwwAuth := response.Header.Get("WWW-Authenticate")
			if !strings.Contains(wwwAuth, "intent=\"session\"") {
				t.Fatalf("%s WWW-Authenticate = %q", route.path, wwwAuth)
			}
		}
	})

	t.Run("session side channel validates input", func(t *testing.T) {
		response, body := doRequest(t, http.MethodPost, base+"/__402/session/deliveries",
			`{"amount":"100"}`, nil)
		if response.StatusCode != http.StatusBadRequest || !strings.Contains(body, "sessionId") {
			t.Fatalf("deliveries: status = %d body = %s", response.StatusCode, body)
		}
		response, body = doRequest(t, http.MethodPost, base+"/__402/session/commit",
			`{"deliveryId":"d-1"}`, nil)
		if response.StatusCode != http.StatusBadRequest || !strings.Contains(body, "voucher") {
			t.Fatalf("commit: status = %d body = %s", response.StatusCode, body)
		}
	})

	t.Run("session receipt", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/sessions/receipt/unknown-channel", "", nil)
		if response.StatusCode != http.StatusNotFound || !strings.Contains(body, "channel-not-found") {
			t.Fatalf("status = %d body = %s", response.StatusCode, body)
		}
	})

	t.Run("premium feed is a documented stub", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/api/v1/premium/feed", "", nil)
		if response.StatusCode != http.StatusNotImplemented || !strings.Contains(body, "not_implemented") {
			t.Fatalf("status = %d body = %s", response.StatusCode, body)
		}
	})

	t.Run("faucet", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/api/v1/faucet/status", "", nil)
		if response.StatusCode != http.StatusOK || !strings.Contains(body, paycore.USDCMainnetMint) {
			t.Fatalf("status: %d body = %s", response.StatusCode, body)
		}
		response, body = doRequest(t, http.MethodPost, base+"/api/v1/faucet/airdrop", `{}`, nil)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("missing address: status = %d body = %s", response.StatusCode, body)
		}
		response, body = doRequest(t, http.MethodPost, base+"/api/v1/faucet/airdrop",
			`{"address":"`+a.recipient+`"}`, nil)
		if response.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
			t.Fatalf("airdrop: status = %d body = %s", response.StatusCode, body)
		}
	})

	t.Run("facilitator", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/facilitator/supported", "", nil)
		if response.StatusCode != http.StatusOK || !strings.Contains(body, `"scheme":"exact"`) {
			t.Fatalf("supported: status = %d body = %s", response.StatusCode, body)
		}

		_, body = doRequest(t, http.MethodPost, base+"/facilitator/verify", `{}`, nil)
		if !strings.Contains(body, `"isValid":false`) {
			t.Fatalf("verify missing payload: %s", body)
		}
		_, body = doRequest(t, http.MethodPost, base+"/facilitator/verify",
			`{"paymentPayload":{"payload":{"authorization":{"from":"payer-address"}}}}`, nil)
		if !strings.Contains(body, `"isValid":true`) || !strings.Contains(body, "payer-address") {
			t.Fatalf("verify: %s", body)
		}

		_, body = doRequest(t, http.MethodPost, base+"/facilitator/settle", `{}`, nil)
		if !strings.Contains(body, `"success":false`) {
			t.Fatalf("settle missing payload: %s", body)
		}
		_, body = doRequest(t, http.MethodPost, base+"/facilitator/settle",
			`{"paymentPayload":{"payload":{"transaction":"AAAA"}}}`, nil)
		if !strings.Contains(body, `"success":true`) || !strings.Contains(body, "stub-signature") {
			t.Fatalf("settle: %s", body)
		}
	})

	t.Run("x402 routes issue x402 challenges", func(t *testing.T) {
		for _, path := range []string{"/x402/joke", "/x402/fact"} {
			response, body := doRequest(t, http.MethodGet, base+path, "", nil)
			if response.StatusCode != http.StatusPaymentRequired {
				t.Fatalf("%s status = %d: %s", path, response.StatusCode, body)
			}
			var challenge struct {
				Accepts []struct {
					Protocol string `json:"protocol"`
					Scheme   string `json:"scheme"`
				} `json:"accepts"`
			}
			decodeBody(t, body, &challenge)
			if len(challenge.Accepts) != 1 || challenge.Accepts[0].Protocol != "x402" || challenge.Accepts[0].Scheme != "exact" {
				t.Fatalf("%s challenge = %s", path, body)
			}
		}
	})

	t.Run("x402 usage routes issue upto challenges", func(t *testing.T) {
		for method, path := range map[string]string{
			http.MethodPost: "/api/v1/summarize",
			http.MethodGet:  "/x402/usage",
		} {
			response, body := doRequest(t, method, base+path, "hello world", nil)
			if response.StatusCode != http.StatusPaymentRequired {
				t.Fatalf("%s %s status = %d: %s", method, path, response.StatusCode, body)
			}
			var challenge struct {
				Error   string `json:"error"`
				Accepts []struct {
					Protocol string `json:"protocol"`
					Scheme   string `json:"scheme"`
				} `json:"accepts"`
			}
			decodeBody(t, body, &challenge)
			if challenge.Error != "payment_required" ||
				len(challenge.Accepts) != 1 ||
				challenge.Accepts[0].Protocol != "x402" ||
				challenge.Accepts[0].Scheme != "upto" {
				t.Fatalf("%s %s challenge = %s", method, path, body)
			}
		}
	})

	t.Run("docs", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/api/v1/docs", "", nil)
		if response.StatusCode != http.StatusOK || !strings.Contains(body, `"go":false`) {
			t.Fatalf("docs index: status = %d body = %s", response.StatusCode, body)
		}
		response, body = doRequest(t, http.MethodGet, base+"/api/v1/docs/cobol/tree", "", nil)
		if response.StatusCode != http.StatusNotFound || !strings.Contains(body, "unknown_lang") {
			t.Fatalf("unknown lang: status = %d body = %s", response.StatusCode, body)
		}
		response, body = doRequest(t, http.MethodGet, base+"/api/v1/docs/go/tree", "", nil)
		if response.StatusCode != http.StatusNotFound || !strings.Contains(body, "not_generated") {
			t.Fatalf("not generated: status = %d body = %s", response.StatusCode, body)
		}
		response, body = doRequest(t, http.MethodGet,
			base+"/api/v1/docs/go/file?path=../../../go.mod", "", nil)
		if response.StatusCode != http.StatusBadRequest || !strings.Contains(body, "unsafe_path") {
			t.Fatalf("path escape: status = %d body = %s", response.StatusCode, body)
		}
		response, body = doRequest(t, http.MethodGet,
			base+"/api/v1/docs/go/file?path=notes.txt", "", nil)
		if response.StatusCode != http.StatusBadRequest || !strings.Contains(body, "not_markdown") {
			t.Fatalf("non markdown: status = %d body = %s", response.StatusCode, body)
		}
	})

	t.Run("CORS exposes the payment headers", func(t *testing.T) {
		response, _ := doRequest(t, http.MethodGet, base+"/api/v1/health", "", nil)
		exposed := response.Header.Get("Access-Control-Expose-Headers")
		for _, header := range []string{
			"www-authenticate",
			"payment-required",
			"payment-response",
			"payment-receipt",
			"x-payment-required",
			"x-payment-response",
			"x-payment-settlement-signature",
		} {
			if !strings.Contains(exposed, header) {
				t.Fatalf("expose headers = %q missing %q", exposed, header)
			}
		}
		request, err := http.NewRequest(http.MethodOptions, base+"/api/v1/fortune", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		request.Header.Set("Access-Control-Request-Headers", "authorization")
		preflight, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("OPTIONS: %v", err)
		}
		preflight.Body.Close()
		if preflight.StatusCode != http.StatusNoContent ||
			preflight.Header.Get("Access-Control-Allow-Headers") != "authorization" {
			t.Fatalf("preflight: status = %d allow-headers = %q",
				preflight.StatusCode, preflight.Header.Get("Access-Control-Allow-Headers"))
		}
	})

	t.Run("catch-all", func(t *testing.T) {
		response, body := doRequest(t, http.MethodGet, base+"/nonexistent", "", nil)
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d body = %s", response.StatusCode, body)
		}
	})
}

func TestSummarizeUsageClampsBilling(t *testing.T) {
	billed, tokens := summarizeUsage(4, 100_000)
	if billed != 100 || tokens != 1 {
		t.Fatalf("small usage = %d/%d, want 100/1", billed, tokens)
	}

	billed, tokens = summarizeUsage(10_000_000, 100_000)
	if billed != 100_000 || tokens <= 1 {
		t.Fatalf("large usage = %d/%d, want clamped billed units", billed, tokens)
	}
}
