package paykit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// ctxKey is the unexported context-attachment key for the verified
// payment. Per the log/slog convention -- struct{} key prevents
// cross-package collisions and accidental overwrites.
type ctxKey struct{}

// Require returns net/http middleware that gates the wrapped handler
// behind the given gate. On a missing or invalid credential the
// middleware short-circuits with a 402 JSON body listing every
// accept-able offer; on success the verified [Payment] is attached to
// the request context (see [PaymentFrom]).
func (c *Client) Require(gate Gate) func(http.Handler) http.Handler {
	return c.RequireFunc(func(_ *http.Request) (Gate, error) { return gate, nil })
}

// GateFunc is the dynamic-gate signature for [Client.RequireFunc].
type GateFunc func(r *http.Request) (Gate, error)

// RequireFunc is the dynamic-gate variant of [Client.Require]: the
// callback runs per request and returns a [Gate] derived from the
// request (URL params, headers, request body, etc.).
func (c *Client) RequireFunc(resolve GateFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gate, err := resolve(r)
			if err != nil {
				c.write402(w, r, &gate, &PaymentError{Code: "gate_resolution_failed", Err: err})
				return
			}
			if err := gate.Validate(); err != nil {
				c.write402(w, r, &gate, &PaymentError{Code: "invalid_gate", Err: err})
				return
			}
			adapter := c.pickAdapter(&gate, r)
			if adapter == nil {
				c.write402(w, r, &gate, &PaymentError{Code: "payment_required", Err: ErrPaymentRequired})
				return
			}
			pmt, err := adapter.VerifyAndSettle(&AdapterRequest{
				Method:        r.Method,
				Path:          r.URL.Path,
				Host:          r.Host,
				Authorization: r.Header.Get("Authorization"),
				PaymentSig:    r.Header.Get("Payment-Signature"),
				Gate:          &gate,
			})
			if err != nil {
				var perr *PaymentError
				if !errors.As(err, &perr) {
					perr = &PaymentError{Code: "invalid_proof", Err: err}
				}
				c.write402(w, r, &gate, perr)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, pmt)
			rw := &settlementWriter{ResponseWriter: w, headers: pmt.SettlementHeaders}
			next.ServeHTTP(rw, r.WithContext(ctx))
		})
	}
}

// PaymentFrom returns the verified payment attached to the request
// context, or (nil, false) when none is present. Comma-ok mirrors the
// stdlib `context.Value` shape.
func PaymentFrom(ctx context.Context) (*Payment, bool) {
	pmt, ok := ctx.Value(ctxKey{}).(*Payment)
	return pmt, ok
}

// IsPaid is the predicate form of [PaymentFrom]; always returns false
// when no payment is attached.
func IsPaid(ctx context.Context) bool {
	_, ok := PaymentFrom(ctx)
	return ok
}

// IsPaidFor reports whether the attached payment is for the given gate
// name (matched against [Gate.Name]).
func IsPaidFor(ctx context.Context, gate Gate) bool {
	pmt, ok := PaymentFrom(ctx)
	if !ok {
		return false
	}
	return gate.Name == "" || pmt.Gate == gate.Name
}

func (c *Client) pickAdapter(gate *Gate, r *http.Request) Adapter {
	accept := gate.Accept
	if len(accept) == 0 {
		accept = c.Config.Accept
	}
	auth := r.Header.Get("Authorization")
	sig := r.Header.Get("Payment-Signature")
	for _, s := range accept {
		switch s {
		case X402:
			if sig != "" && c.x402Adapter != nil {
				return c.x402Adapter
			}
		case MPP:
			if strings.HasPrefix(auth, "Payment ") && c.mppAdapter != nil {
				return c.mppAdapter
			}
		}
	}
	return nil
}

// paymentRequiredBody is the typed JSON shape of the 402 response body
// shared across the cross-language ports (error + resource + accepts).
type paymentRequiredBody struct {
	Error    string         `json:"error"`
	Resource string         `json:"resource"`
	Accepts  []AcceptsEntry `json:"accepts"`
}

// write402 assembles the per-protocol accepts entries and challenge
// headers, stamps them onto the [PaymentError], and dispatches to the
// configured error handler (DefaultErrorHandler unless overridden via
// [Client.SetErrorHandler]).
func (c *Client) write402(w http.ResponseWriter, r *http.Request, gate *Gate, perr *PaymentError) {
	accept := gate.Accept
	if len(accept) == 0 {
		accept = c.Config.Accept
	}
	accepts := []AcceptsEntry{}
	headers := map[string]string{}
	if c.x402Adapter != nil && containsProtocol(accept, X402) && !gate.HasFees() {
		accepts = append(accepts, c.x402Adapter.AcceptsEntry(gate))
		for k, v := range c.x402Adapter.ChallengeHeaders(gate) {
			headers[k] = v
		}
	}
	if c.mppAdapter != nil && containsProtocol(accept, MPP) {
		accepts = append(accepts, c.mppAdapter.AcceptsEntry(gate))
		for k, v := range c.mppAdapter.ChallengeHeaders(gate) {
			headers[k] = v
		}
	}
	perr.Gate = gate
	perr.Protocols = accept
	perr.status = http.StatusPaymentRequired
	perr.resource = r.URL.Path
	perr.accepts = accepts
	perr.headers = headers

	handler := c.errorHandler
	if handler == nil {
		handler = DefaultErrorHandler
	}
	handler(w, r, perr)
}

// DefaultErrorHandler renders the canonical 402 response: every
// challenge header the accepted protocols produced, plus a JSON body
// of `{error, resource, accepts[]}`. Custom handlers registered via
// [Client.SetErrorHandler] can delegate to it for the default cases:
//
//	client.SetErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
//	    if errors.Is(err, paykit.ErrChallengeExpired) {
//	        // custom body / status
//	        return
//	    }
//	    paykit.DefaultErrorHandler(w, r, err)
//	})
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	var perr *PaymentError
	if !errors.As(err, &perr) {
		http.Error(w, "payment required", http.StatusPaymentRequired)
		return
	}
	for k, v := range perr.headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	status := perr.status
	if status == 0 {
		status = http.StatusPaymentRequired
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(paymentRequiredBody{
		Error:    "payment_required",
		Resource: perr.resource,
		Accepts:  perr.accepts,
	})
}

func containsProtocol(list []Protocol, want Protocol) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ContextWithPaymentForTests attaches a *Payment to ctx through the
// package's private context key. Exported only for tests; production
// callers should rely on Client.Require / Client.RequireFunc.
func ContextWithPaymentForTests(ctx context.Context, pmt *Payment) context.Context {
	return context.WithValue(ctx, ctxKey{}, pmt)
}

// settlementWriter merges the adapter's settlement headers into the
// upstream 2xx response. ResponseWriter is wrapped because headers must
// be set before WriteHeader is called on the underlying writer.
type settlementWriter struct {
	http.ResponseWriter
	headers map[string]string
	wrote   bool
}

func (w *settlementWriter) WriteHeader(status int) {
	if !w.wrote {
		for k, v := range w.headers {
			w.Header().Set(k, v)
		}
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *settlementWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
