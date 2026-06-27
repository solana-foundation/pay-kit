package main

import "github.com/solana-foundation/pay-kit/go/paykit"

// OpenAPI discovery for the TypeScript playground web app.
//
// The current playground UI reads `/openapi.json` and adapts each operation's
// `x-payment-info.offers[]` into its sidebar catalog. The Go playground keeps a
// small hand-written document here because the Go paykit middleware does not
// introspect `http.ServeMux` routes the way the TypeScript Express example can.

// openAPIDoc is the minimal OpenAPI 3.1 document shape the playground consumes.
type openAPIDoc struct {
	OpenAPI string                                 `json:"openapi"`
	Info    map[string]string                      `json:"info"`
	Paths   map[string]map[string]openAPIOperation `json:"paths"`
}

// openAPIOperation describes one priced operation.
type openAPIOperation struct {
	Summary      string                     `json:"summary"`
	Responses    map[string]openAPIResponse `json:"responses"`
	XPaymentInfo openAPIPaymentInfo         `json:"x-payment-info"`
}

// openAPIResponse is the minimal response object required by OpenAPI.
type openAPIResponse struct {
	Description string `json:"description"`
}

// openAPIPaymentInfo carries the payment-discovery extension.
type openAPIPaymentInfo struct {
	Offers []openAPIOffer `json:"offers"`
}

// openAPIOffer is the subset of the payment-discovery offer shape read by the
// playground UI.
type openAPIOffer struct {
	Amount      string `json:"amount,omitempty"`
	Currency    string `json:"currency,omitempty"`
	Description string `json:"description,omitempty"`
	FeePayer    string `json:"feePayer,omitempty"`
	Intent      string `json:"intent,omitempty"`
	Method      string `json:"method,omitempty"`
	Network     string `json:"network,omitempty"`
	PayTo       string `json:"payTo,omitempty"`
	Scheme      string `json:"scheme,omitempty"`
	UnitPrice   string `json:"unitPrice,omitempty"`
}

// buildOpenAPIDoc returns the discovery document consumed by playground/app.
func buildOpenAPIDoc(a *app) openAPIDoc {
	return openAPIDoc{
		OpenAPI: "3.1.0",
		Info: map[string]string{
			"title":   "PayKit Playground (Go)",
			"version": "1.0.0",
		},
		Paths: map[string]map[string]openAPIOperation{
			"/api/v1/stocks/quote/{symbol}": {
				"get": pricedOperation("Stock quote", openAPIOffer{
					Amount:      "10000",
					Description: "0.01 USDC",
					Intent:      "charge",
					Method:      "mpp",
					Scheme:      "charge",
				}, a),
			},
			"/api/v1/stocks/history/{symbol}": {
				"get": pricedOperation("Stock history", openAPIOffer{
					Amount:      "50000",
					Description: "0.05 USDC",
					Intent:      "charge",
					Method:      "mpp",
					Scheme:      "charge",
				}, a),
			},
			"/api/v1/fortune": {
				"get": pricedOperation("Fortune cookie", openAPIOffer{
					Amount:      "10000",
					Description: "0.01 USDC",
					Intent:      "charge",
					Method:      "mpp",
					Scheme:      "charge",
				}, a),
			},
			"/sessions/stream": {
				"get": pricedOperation("Metered stream", openAPIOffer{
					Amount:      "1000000",
					Description: "up to 1.00 USDC",
					Intent:      "session",
					Method:      "mpp",
					Scheme:      "session",
					UnitPrice:   "100",
				}, a),
			},
			"/sessions/compute": {
				"post": pricedOperation("Pay-per-call compute", openAPIOffer{
					Amount:      "500000",
					Description: "up to 0.50 USDC",
					Intent:      "session",
					Method:      "mpp",
					Scheme:      "session",
					UnitPrice:   "5000",
				}, a),
			},
			"/x402/joke": {
				"get": pricedOperation("x402 joke", openAPIOffer{
					Amount:      "1000",
					Description: "0.001 USDC",
					Intent:      "charge",
					Method:      "x402",
					Scheme:      "exact",
				}, a),
			},
			"/x402/fact": {
				"get": pricedOperation("x402 fact", openAPIOffer{
					Amount:      "1000",
					Description: "0.001 USDC",
					Intent:      "charge",
					Method:      "x402",
					Scheme:      "exact",
				}, a),
			},
			"/x402/usage": {
				"get": pricedOperation("Usage-metered endpoint", openAPIOffer{
					Amount:      "1000000",
					Description: "up to 1.00 USDC",
					Intent:      "charge",
					Method:      "x402",
					Scheme:      "upto",
				}, a),
			},
		},
	}
}

func pricedOperation(summary string, offer openAPIOffer, a *app) openAPIOperation {
	offer.Currency = "USDC"
	offer.FeePayer = a.feePayer.PublicKey().String()
	offer.Network = a.network
	if network, err := paykit.ParseNetwork(a.network); err == nil {
		offer.Network = network.CAIP2()
	}
	offer.PayTo = a.recipient
	return openAPIOperation{
		Responses: map[string]openAPIResponse{
			"200": {Description: "Successful response"},
			"402": {Description: "Payment Required"},
		},
		Summary:      summary,
		XPaymentInfo: openAPIPaymentInfo{Offers: []openAPIOffer{offer}},
	}
}
