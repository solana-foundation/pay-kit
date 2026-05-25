package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/errorcodes"
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
func ReceiptFromContext(ctx context.Context) (mpp.Receipt, bool) {
	r, ok := ctx.Value(receiptContextKey).(mpp.Receipt)
	return r, ok
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
			authHeader := r.Header.Get(mpp.AuthorizationHeader)
			if paymentToken, ok := mpp.ExtractPaymentScheme(authHeader); ok && paymentToken != "" {
				credential, err := mpp.ParseAuthorization(authHeader)
				if err != nil {
					verificationErr = mpp.WrapError(mpp.ErrCodeInvalidPayload, "parse authorization", err)
				} else {
					var expected mpp.ChargeRequest
					if decodeErr := challenge.Request.Decode(&expected); decodeErr != nil {
						verificationErr = mpp.WrapError(mpp.ErrCodeInvalidPayload, "decode challenge request", decodeErr)
					} else {
						receipt, verifyErr := m.VerifyCredentialWithExpected(r.Context(), credential, expected)
						if verifyErr == nil {
							receiptHeader, fmtErr := mpp.FormatReceipt(receipt)
							if fmtErr == nil {
								w.Header().Set(mpp.PaymentReceiptHeader, receiptHeader)
							}
							markAuthorizationBoundResponse(w.Header())
							ctx := context.WithValue(r.Context(), receiptContextKey, receipt)
							next.ServeHTTP(w, r.WithContext(ctx))
							return
						}
						verificationErr = verifyErr
					}
				}
			}

			wwwAuth, err := mpp.FormatWWWAuthenticate(challenge)
			if err != nil {
				http.Error(w, "failed to format challenge", http.StatusInternalServerError)
				return
			}

			w.Header().Set(mpp.WWWAuthenticateHeader, wwwAuth)
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
