package paykit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
)

// VerifiedUsageOpen is an opaque, protocol-specific verified channel open
// carried from VerifyOpen to SettleActual. The concrete type is the
// protocol's internal verified-open handle (e.g. x402.UptoVerifiedOpen).
type VerifiedUsageOpen interface{}

// UsageSettlement carries the settlement result of a usage-gated request.
type UsageSettlement struct {
	Transaction string
	Headers     map[string]string
}

// Charge is the usage meter handed to a usage-gated handler. The handler
// reports the actual amount consumed (token base units) via Charge; the
// gate settles that amount — never above the authorized ceiling — after
// the handler returns. If the handler never calls Charge, the settled
// amount is 0. Mirrors the TypeScript Charge class and the Rust
// paid_upto_* Charge extractor.
type Charge struct {
	maxBaseUnits uint64
	amount       uint64
	set          bool
	mu           sync.Mutex
}

// NewCharge creates a Charge meter with the given authorized ceiling.
func NewCharge(maxBaseUnits uint64) *Charge {
	return &Charge{maxBaseUnits: maxBaseUnits}
}

// MaxBaseUnits returns the authorized maximum for this request, in base units.
func (c *Charge) MaxBaseUnits() uint64 { return c.maxBaseUnits }

// Charge records the actual amount consumed (base units). Values above the
// ceiling are clamped; negatives floor to 0. Mirrors the TypeScript
// Charge.charge clamp behavior.
func (c *Charge) Charge(baseUnits uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.amount = baseUnits
	if c.amount > c.maxBaseUnits {
		c.amount = c.maxBaseUnits
	}
	c.set = true
}

// SettledBaseUnits returns the amount to settle: the clamped charge, or 0
// if Charge was never called.
func (c *Charge) SettledBaseUnits() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.amount
}

// chargeKey is the context attachment key for the usage Charge meter.
type chargeKey struct{}

// ChargeFrom returns the usage Charge meter attached to the request context
// by RequireUsage, or (nil, false) when none is present.
func ChargeFrom(ctx context.Context) (*Charge, bool) {
	c, ok := ctx.Value(chargeKey{}).(*Charge)
	return c, ok
}

// UsageAdapter is the contract for usage-gated (upto) protocol engines.
// Unlike the fixed-gate Adapter, settlement happens AFTER the handler runs.
// The x402 upto engine implements this interface and registers via
// RegisterUsageAdapter in its init().
type UsageAdapter interface {
	// UsageChallengeHeaders returns the 402 challenge headers for a usage gate.
	UsageChallengeHeaders(gate *Gate) map[string]string
	// UsageAcceptsEntry returns the accepts[] entry for a usage gate.
	UsageAcceptsEntry(gate *Gate) AcceptsEntry
	// DetectUsage reports whether the request carries a usage credential.
	DetectUsage(req *AdapterRequest) bool
	// VerifyOpen validates the credential and opens the payment channel.
	// Returns the opaque verified open and a provisional Payment (with
	// empty Transaction — filled in after settlement).
	VerifyOpen(ctx context.Context, req *AdapterRequest) (VerifiedUsageOpen, *Payment, error)
	// SettleActual settles the metered amount against the verified open.
	// Returns the settlement headers and transaction signature.
	SettleActual(ctx context.Context, verified VerifiedUsageOpen, actual uint64) (*UsageSettlement, error)
}

// UsageBuilder is the constructor each protocol package registers for the
// usage adapter. paykit.New calls it once the Config is resolved.
type UsageBuilder func(cfg Config) (UsageAdapter, error)

var registeredUsageBuilder UsageBuilder

// RegisterUsageAdapter is called from a protocol package's init() to plug
// its usage adapter into the umbrella. The x402 package calls this to
// register the upto engine.
func RegisterUsageAdapter(b UsageBuilder) {
	registeredUsageBuilder = b
}

// RequireUsage returns net/http middleware that gates the wrapped handler
// behind a usage (upto) gate. On a missing or invalid credential the
// middleware short-circuits with a 402 challenge; on success the channel
// is opened before the handler runs, a Charge meter is attached to the
// request context (see ChargeFrom), and the actual amount is settled
// after the handler completes. Mirrors the TypeScript requireUsage.
func (c *Client) RequireUsage(gate Gate) func(http.Handler) http.Handler {
	return c.RequireUsageFunc(func(_ *http.Request) (Gate, error) { return gate, nil })
}

// RequireUsageFunc is the dynamic-gate variant of RequireUsage.
func (c *Client) RequireUsageFunc(resolve GateFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gate, err := resolve(r)
			if err != nil {
				c.write402(w, r, &gate, &PaymentError{Code: "gate_resolution_failed", Err: err})
				return
			}
			if gate.Kind == "" {
				gate.Kind = GateUsage
			}
			if err := gate.Validate(); err != nil {
				c.write402(w, r, &gate, &PaymentError{Code: "invalid_gate", Err: err})
				return
			}
			if gate.Kind != GateUsage {
				c.write402(w, r, &gate, &PaymentError{Code: "invalid_gate", Err: errors.New("RequireUsage requires a usage gate")})
				return
			}
			adapter := c.usageAdapter
			if adapter == nil {
				c.write402(w, r, &gate, &PaymentError{Code: "payment_required", Err: ErrPaymentRequired})
				return
			}
			req := &AdapterRequest{
				Method:           r.Method,
				Path:             r.URL.Path,
				Host:             r.Host,
				PaymentSig:       r.Header.Get("Payment-Signature"),
				PaymentSigLegacy: r.Header.Get("X-PAYMENT"),
				Gate:             &gate,
			}
			if !adapter.DetectUsage(req) {
				c.writeUsage402(w, r, &gate, adapter)
				return
			}
			verified, pmt, err := adapter.VerifyOpen(r.Context(), req)
			if err != nil {
				slog.Warn("paykit: usage verify_open failed", "error", err)
				var perr *PaymentError
				if !errors.As(err, &perr) {
					perr = &PaymentError{Code: "invalid_proof", Err: err}
				}
				c.writeUsage402(w, r, &gate, adapter, perr)
				return
			}
			maxBaseUnits := gateTotalBaseUnits(&gate)
			meter := NewCharge(maxBaseUnits)
			ctx := context.WithValue(r.Context(), ctxKey{}, pmt)
			ctx = context.WithValue(ctx, chargeKey{}, meter)
			uw := &usageSettlementWriter{
				ResponseWriter: w,
				adapter:        adapter,
				verified:       verified,
				meter:          meter,
				payment:        pmt,
			}
			next.ServeHTTP(uw, r.WithContext(ctx))
			uw.finalizeSettlement(r.Context())
		})
	}
}

// paymentRequiredUsageBody is the typed JSON shape of the usage 402 response.
type paymentRequiredUsageBody struct {
	Error    string         `json:"error"`
	Code     string         `json:"code,omitempty"`
	Detail   string         `json:"detail,omitempty"`
	Resource string         `json:"resource"`
	Accepts  []AcceptsEntry `json:"accepts"`
}

// DefaultUsageErrorHandler renders the canonical usage 402 response.
func DefaultUsageErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
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
	body := paymentRequiredUsageBody{
		Error:    "payment_required",
		Resource: perr.resource,
		Accepts:  perr.accepts,
	}
	if perr.Code != "" && perr.Code != "payment_required" {
		body.Code = perr.Code
		body.Detail = perr.Err.Error()
	}
	_ = json.NewEncoder(w).Encode(body)
}

// writeUsage402 assembles the usage-gate 402 challenge and dispatches to
// the configured error handler. The challenge carries the upto accepts
// entry and challenge headers from the usage adapter.
func (c *Client) writeUsage402(w http.ResponseWriter, r *http.Request, gate *Gate, adapter UsageAdapter, perrOpt ...*PaymentError) {
	accepts := []AcceptsEntry{}
	headers := map[string]string{}
	if entry := adapter.UsageAcceptsEntry(gate); entry != nil {
		accepts = append(accepts, entry)
	}
	for k, v := range adapter.UsageChallengeHeaders(gate) {
		headers[k] = v
	}
	var perr *PaymentError
	if len(perrOpt) > 0 && perrOpt[0] != nil {
		perr = perrOpt[0]
	} else {
		perr = &PaymentError{Code: "payment_required", Err: ErrPaymentRequired}
	}
	perr.Gate = gate
	perr.Protocols = []Protocol{X402}
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

// gateTotalBaseUnits converts the gate's total Price to base units at
// stablecoin decimals (6). This is the authorized ceiling for the usage gate.
func gateTotalBaseUnits(gate *Gate) uint64 {
	scaled := gate.Total().Amount().Shift(6)
	return scaled.Truncate(0).BigInt().Uint64()
}

// usageSettlementWriter wraps the ResponseWriter to defer settlement until
// the handler completes. On the first WriteHeader/Write call, it settles
// the metered amount via the usage adapter and merges the settlement
// headers before forwarding to the underlying writer. If settlement fails,
// it writes a 500 (the channel is already open; the resource was served).
type usageSettlementWriter struct {
	http.ResponseWriter
	adapter    UsageAdapter
	verified   VerifiedUsageOpen
	meter      *Charge
	payment    *Payment
	settled    bool
	settlement *UsageSettlement
	settleErr  error
	wrote      bool
}

func (w *usageSettlementWriter) settle(ctx context.Context) {
	if w.settled {
		return
	}
	w.settled = true
	result, err := w.adapter.SettleActual(ctx, w.verified, w.meter.SettledBaseUnits())
	if err != nil {
		w.settleErr = err
		return
	}
	w.settlement = result
	if result != nil {
		w.payment.Transaction = result.Transaction
		if w.payment.SettlementHeaders == nil {
			w.payment.SettlementHeaders = map[string]string{}
		}
		for k, v := range result.Headers {
			w.payment.SettlementHeaders[k] = v
		}
	}
}

func (w *usageSettlementWriter) WriteHeader(status int) {
	if !w.wrote {
		w.settle(context.Background())
		if w.settleErr == nil && w.settlement != nil {
			for k, v := range w.settlement.Headers {
				w.Header().Set(k, v)
			}
		}
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *usageSettlementWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

// finalizeSettlement runs settlement if the handler never wrote a response
// (e.g. it panicked or returned without writing). This ensures the channel
// is always settled even on degenerate handler paths.
func (w *usageSettlementWriter) finalizeSettlement(ctx context.Context) {
	if !w.settled {
		w.settle(ctx)
	}
}

// ContextWithChargeForTests attaches a *Charge to ctx through the
// package's private context key. Exported only for tests.
func ContextWithChargeForTests(ctx context.Context, c *Charge) context.Context {
	return context.WithValue(ctx, chargeKey{}, c)
}

// MarshalJSON renders the Charge for debug/logging. Not serialized on the wire.
func (c *Charge) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("Charge(max=%d, settled=%d)", c.maxBaseUnits, c.SettledBaseUnits()))
}
