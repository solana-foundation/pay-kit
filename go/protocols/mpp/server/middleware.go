package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/errorcodes"
)

type contextKey string

const receiptContextKey contextKey = "mpp-receipt"

func markAuthorizationBoundResponse(header http.Header) {
	header.Set("Cache-Control", "no-store")

	for _, value := range header.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(field), "Authorization") || strings.TrimSpace(field) == "*" {
				return
			}
		}
	}
	header.Add("Vary", "Authorization")
}

// ReceiptFromContext extracts the payment receipt from the request context.
func ReceiptFromContext(ctx context.Context) (core.Receipt, bool) {
	r, ok := ctx.Value(receiptContextKey).(core.Receipt)
	return r, ok
}

// IsSettlementInProgress reports whether err says the credential's payment
// may already be broadcast and is not yet resolved.
func IsSettlementInProgress(err error) bool {
	var sdkErr *core.Error
	return errors.As(err, &sdkErr) && sdkErr.Code == core.ErrCodeSettlementInProgress
}

// WriteSettlementInProgress answers a credential whose payment is still
// settling with 409 and no challenge: a client handed a fresh challenge
// could pay it while the original transaction lands and pay twice. The
// client retries the same credential instead.
func WriteSettlementInProgress(w http.ResponseWriter, err error) {
	body, _ := json.Marshal(map[string]any{
		"type":   "tag:paymentauth.org,2024:settlement-in-progress",
		"title":  "Settlement Already In Progress",
		"status": http.StatusConflict,
		"detail": err.Error(),
		"code":   string(core.ErrCodeSettlementInProgress),
	})
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusConflict)
	_, _ = w.Write(body)
}

// ChargeFunc returns the charge amount and options for a given request.
type ChargeFunc func(r *http.Request) (amount string, opts ChargeOptions, err error)

// PaymentMiddleware wraps an http.Handler to enforce MPP payments.
// Requests without a valid credential get a 402 challenge.
// Requests with a valid credential get the receipt injected into context.
func PaymentMiddleware(m *Mpp, chargeFn ChargeFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Serve the service worker JS when the query param is present.
			if IsServiceWorkerRequest(r) {
				w.Header().Set("Content-Type", "application/javascript")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(ServiceWorkerJS()))
				return
			}

			// Resolve the route's expected charge first so verification can be
			// route-aware: the credential's claimed amount is compared to this
			// route's expected amount, not just to itself.
			amount, opts, err := chargeFn(r)
			if err != nil {
				http.Error(w, "charge function error", http.StatusInternalServerError)
				return
			}

			challenge, err := m.ChargeWithOptions(r.Context(), amount, opts)
			if err != nil {
				http.Error(w, "failed to create challenge", http.StatusInternalServerError)
				return
			}

			// Check for a payment credential in the Authorization header.
			// verificationErr captures whichever verification step failed
			// so the 402 body can surface a canonical L6 code. A nil
			// verificationErr on the re-challenge path means the caller
			// never sent an Authorization header (or sent an empty one).
			var verificationErr error
			authHeader := r.Header.Get(core.AuthorizationHeader)
			if paymentToken, ok := core.ExtractPaymentScheme(authHeader); ok && paymentToken != "" {
				credential, err := core.ParseAuthorization(authHeader)
				if err != nil {
					verificationErr = core.WrapError(core.ErrCodeInvalidPayload, "parse authorization", err)
				} else {
					var expected core.ChargeRequest
					if decodeErr := challenge.Request.Decode(&expected); decodeErr != nil {
						verificationErr = core.WrapError(core.ErrCodeInvalidPayload, "decode challenge request", decodeErr)
					} else {
						receipt, verifyErr := m.VerifyCredentialWithExpected(r.Context(), credential, expected)
						if verifyErr == nil {
							receiptHeader, fmtErr := core.FormatReceipt(receipt)
							if fmtErr == nil {
								w.Header().Set(core.PaymentReceiptHeader, receiptHeader)
							}
							markAuthorizationBoundResponse(w.Header())
							ctx := context.WithValue(r.Context(), receiptContextKey, receipt)
							next.ServeHTTP(w, r.WithContext(ctx))
							return
						}
						if IsSettlementInProgress(verifyErr) {
							WriteSettlementInProgress(w, verifyErr)
							return
						}
						verificationErr = verifyErr
					}
				}
			}

			wwwAuth, err := core.FormatWWWAuthenticate(challenge)
			if err != nil {
				http.Error(w, "failed to format challenge", http.StatusInternalServerError)
				return
			}

			w.Header().Set(core.WWWAuthenticateHeader, wwwAuth)
			markAuthorizationBoundResponse(w.Header())

			if m.HTMLEnabled() && AcceptsHTML(r) {
				html, err := m.ChallengeToHTML(challenge)
				if err == nil {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusPaymentRequired)
					_, _ = w.Write([]byte(html))
					return
				}
				// Fall through to JSON on HTML error.
			}

			code := errorcodes.PaymentInvalid
			message := "Payment required"
			if verificationErr != nil {
				code = errorcodes.CanonicalFromError(verificationErr)
				message = verificationErr.Error()
			}
			body, err := json.Marshal(errorcodes.NewPaymentRequiredBody(code, message))
			if err != nil {
				http.Error(w, "failed to marshal challenge body", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusPaymentRequired)
			_, _ = w.Write(body)
		})
	}
}
