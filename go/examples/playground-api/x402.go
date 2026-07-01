package main

// The embedded facilitator endpoints plus two x402-gated demo routes.
//
// The Go x402 adapter only implements self-hosted mode (it verifies and
// settles in-process with the operator signer), so the /x402/joke and
// /x402/fact gates here settle locally instead of POSTing to the embedded
// facilitator. The facilitator endpoints are still served with the standard
// shapes for external x402 clients. See README.md.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/solana-foundation/pay-kit/go/paykit"
)

const (
	summarizeMaxBodyBytes       = 1 << 20
	summarizePricePerTokenUnits = 100
)

// jokes is the canned joke pool.
var jokes = []string{
	"Why do programmers prefer dark mode? Because light attracts bugs.",
	"There are 10 types of people: those who understand binary and those who don’t.",
	"A SQL query walks into a bar, sees two tables, and asks: \"Can I JOIN you?\"",
	"A photon checks into a hotel; the bellhop asks if it has any luggage. \"No, I’m traveling light.\"",
}

// facts is the canned fun-fact pool.
var facts = []string{
	"Honey never spoils. Archaeologists found 3000-year-old honey in Egyptian tombs.",
	"Octopuses have three hearts and blue blood.",
	"A group of flamingos is called a \"flamboyance\".",
	"Bananas are berries; strawberries are not.",
}

// registerX402 mounts the embedded facilitator and the x402-gated routes.
func registerX402(mux *http.ServeMux, a *app) error {
	// Embedded facilitator.
	mux.HandleFunc("GET /facilitator/supported", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"kinds": []map[string]any{
				{
					"scheme":  "exact",
					"network": "solana-devnet",
					"extra":   map[string]string{"feePayer": a.feePayer.PublicKey().String()},
				},
			},
		})
	})

	mux.HandleFunc("POST /facilitator/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PaymentPayload *struct {
				Payload *struct {
					Authorization *struct {
						From string `json:"from"`
					} `json:"authorization"`
				} `json:"payload"`
			} `json:"paymentPayload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
			body.PaymentPayload == nil || body.PaymentPayload.Payload == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"isValid":       false,
				"invalidReason": "Missing payload",
			})
			return
		}
		payer := "unknown"
		if auth := body.PaymentPayload.Payload.Authorization; auth != nil && auth.From != "" {
			payer = auth.From
		}
		writeJSON(w, http.StatusOK, map[string]any{"isValid": true, "payer": payer})
	})

	mux.HandleFunc("POST /facilitator/settle", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PaymentPayload *struct {
				Payload *struct {
					Transaction string `json:"transaction"`
				} `json:"payload"`
			} `json:"paymentPayload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
			body.PaymentPayload == nil || body.PaymentPayload.Payload == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"success":     false,
				"errorReason": "Missing payload",
			})
			return
		}
		transaction := body.PaymentPayload.Payload.Transaction
		if transaction == "" {
			writeJSON(w, http.StatusOK, map[string]any{
				"success":     true,
				"transaction": "local-facilitator-settled",
			})
			return
		}
		result, err := rpcCall(r.Context(), a.rpcURL, "sendTransaction", []any{
			transaction,
			map[string]any{"encoding": "base64", "skipPreflight": true},
		})
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"success":     false,
				"errorReason": err.Error(),
			})
			return
		}
		var signature string
		_ = json.Unmarshal(result, &signature)
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "transaction": signature})
	})

	// x402-gated routes: dedicated x402-only paykit clients, self-hosted
	// verification + settlement against the configured RPC.
	exactClient, err := newX402ExactClient(a)
	if err != nil {
		return err
	}
	usageClient, err := newX402UsageClient(a)
	if err != nil {
		return err
	}

	jokeGate := paykit.Gate{
		Amount: paykit.MustParseUSD("0.001"),
		Name:   "x402Joke",
		Desc:   "A random programmer joke",
	}
	mux.Handle("GET /x402/joke", exactClient.Require(jokeGate)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"joke":   jokes[rand.Intn(len(jokes))],
			"source": "x402",
		})
	})))

	factGate := paykit.Gate{
		Amount: paykit.MustParseUSD("0.001"),
		Name:   "x402Fact",
		Desc:   "A random fun fact",
	}
	mux.Handle("GET /x402/fact", exactClient.Require(factGate)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"fact":   facts[rand.Intn(len(facts))],
			"source": "x402",
		})
	})))

	summarizeGate := paykit.Gate{
		Amount: paykit.MustParseUSD("0.10"),
		Name:   "summarize",
		Desc:   "Summarize text, billed per token",
		Kind:   paykit.GateUsage,
	}
	summarizeHandler := usageClient.RequireUsage(summarizeGate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		charge, ok := paykit.ChargeFrom(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "no charge meter"})
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid-body")
			return
		}
		billedBaseUnits, tokens := summarizeUsage(len(body), charge.MaxBaseUnits())
		charge.Charge(billedBaseUnits)
		writeJSON(w, http.StatusOK, map[string]string{
			"billedBaseUnits": strconv.FormatUint(billedBaseUnits, 10),
			"summarizedBytes": strconv.FormatUint(uint64(len(body)), 10),
			"tokens":          strconv.FormatUint(tokens, 10),
		})
	}))
	mux.Handle("POST /api/v1/summarize", bufferRequestBody(summarizeMaxBodyBytes, summarizeHandler))

	// Usage-gated route: the client opens a payment channel depositing
	// the authorized ceiling; the handler meters the response and the
	// gate settles the actual amount after it returns.
	usageGate := paykit.Gate{
		Amount: paykit.MustParseUSD("1.00"),
		Name:   "x402Usage",
		Desc:   "Usage-metered endpoint",
		Kind:   paykit.GateUsage,
	}
	mux.Handle("GET /x402/usage", usageClient.RequireUsage(usageGate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		charge, ok := paykit.ChargeFrom(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "no charge meter"})
			return
		}
		// In a real app the handler measures actual usage (tokens, bytes,
		// compute cycles). Here we charge a fixed demo amount.
		charge.Charge(50_000) // 0.05 USDC
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"source":   "x402-upto",
			"maxUnits": charge.MaxBaseUnits(),
			"charged":  charge.SettledBaseUnits(),
		})
	})))

	return nil
}

func summarizeUsage(bodyLen int, maxBaseUnits uint64) (uint64, uint64) {
	tokens := uint64(bodyLen / 4)
	if tokens < 1 {
		tokens = 1
	}
	billedBaseUnits := tokens * summarizePricePerTokenUnits
	if billedBaseUnits > maxBaseUnits {
		billedBaseUnits = maxBaseUnits
	}
	return billedBaseUnits, tokens
}

func bufferRequestBody(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
		if err != nil {
			status := http.StatusBadRequest
			code := "invalid-body"
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				status = http.StatusRequestEntityTooLarge
				code = "body-too-large"
			}
			writeJSONError(w, status, code)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}
