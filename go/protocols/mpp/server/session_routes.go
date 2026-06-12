package server

// Metering side channel and HTTP middleware for the session method.
//
// The reserve/commit side channel is an extension beyond the draft MPP
// spec: SessionFetch-style clients POST to /__402/session/deliveries to
// reserve capacity for a metered delivery and to /__402/session/commit to
// commit it with a signed voucher. Hosts mount the two handlers on those
// paths themselves.

import (
	"context"
	"encoding/json"
	"net/http"

	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/errorcodes"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// SessionRoutes carries the metering side-channel handlers built by
// Session.Routes. Both share the session's channel store, so deliveries see
// channels opened through VerifyCredential.
type SessionRoutes struct {
	// Deliveries reserves capacity for a metered delivery. Mount at
	// POST /__402/session/deliveries.
	Deliveries http.HandlerFunc

	// Commit commits a reserved delivery with a signed voucher. Mount at
	// POST /__402/session/commit.
	Commit http.HandlerFunc
}

// sessionDeliveryRequestBody is the JSON body of a delivery reservation.
type sessionDeliveryRequestBody struct {
	// SessionID is the channel/session id that will pay for the delivery.
	SessionID string `json:"sessionId"`

	// Amount owed for the delivery: a decimal u64 string in token base units.
	Amount string `json:"amount"`

	// DeliveryID is an optional idempotency key; when empty the server
	// derives "<sessionId>:<sequence>".
	DeliveryID string `json:"deliveryId,omitempty"`

	// CommitURL is an optional commit endpoint hint echoed back to the
	// client in the metering directive.
	CommitURL string `json:"commitUrl,omitempty"`

	// ExpiresAt is an optional delivery expiry (Unix seconds); zero defaults
	// to intents.DefaultSessionExpiresAt.
	ExpiresAt int64 `json:"expiresAt,omitempty"`

	// Proof is an optional opaque proof echoed back to the client in the
	// metering directive.
	Proof string `json:"proof,omitempty"`
}

// sessionCommitRequestBody is the JSON body of a side-channel commit.
type sessionCommitRequestBody struct {
	// DeliveryID names the reserved delivery being committed. Required.
	DeliveryID string `json:"deliveryId"`

	// Voucher is the signed voucher whose cumulative (a lifetime total, not
	// a per-request delta) settles the delivery. Required; nil is rejected.
	Voucher *intents.SignedVoucher `json:"voucher"`
}

// Routes builds the metering side-channel handlers for this session.
func (s *Session) Routes() SessionRoutes {
	return SessionRoutes{
		Deliveries: func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeSessionRouteError(w, http.StatusMethodNotAllowed, "POST required")
				return
			}
			var body sessionDeliveryRequestBody
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeSessionRouteError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			if body.SessionID == "" {
				writeSessionRouteError(w, http.StatusBadRequest, "sessionId required")
				return
			}
			amount, err := parseSessionU64(body.Amount, "amount")
			if err != nil {
				writeSessionRouteError(w, http.StatusBadRequest, err.Error())
				return
			}
			if amount == 0 {
				writeSessionRouteError(w, http.StatusBadRequest, "amount must be positive")
				return
			}
			directive, err := s.core.BeginDelivery(r.Context(), DeliveryRequest{
				SessionID:  body.SessionID,
				Amount:     amount,
				DeliveryID: body.DeliveryID,
				CommitURL:  body.CommitURL,
				Proof:      body.Proof,
				ExpiresAt:  body.ExpiresAt,
			})
			if err != nil {
				writeSessionRouteError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.touch(body.SessionID)
			writeSessionRouteJSON(w, http.StatusOK, directive)
		},
		Commit: func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeSessionRouteError(w, http.StatusMethodNotAllowed, "POST required")
				return
			}
			var body sessionCommitRequestBody
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeSessionRouteError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			if body.DeliveryID == "" {
				writeSessionRouteError(w, http.StatusBadRequest, "deliveryId required")
				return
			}
			if body.Voucher == nil {
				writeSessionRouteError(w, http.StatusBadRequest, "voucher required")
				return
			}
			receipt, err := s.core.ProcessCommit(r.Context(), &intents.CommitPayload{
				DeliveryID: body.DeliveryID,
				Voucher:    *body.Voucher,
			})
			if err != nil {
				writeSessionRouteError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.touch(receipt.SessionID)
			writeSessionRouteJSON(w, http.StatusOK, receipt)
		},
	}
}

// writeSessionRouteJSON writes a JSON response body with the given status.
func writeSessionRouteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeSessionRouteError writes the {"error": message} failure body the
// side-channel clients expect.
func writeSessionRouteError(w http.ResponseWriter, status int, message string) {
	writeSessionRouteJSON(w, status, map[string]string{"error": message})
}

// SessionChallengeFunc returns the per-request challenge options for a route
// gated by SessionMiddleware. A nil function uses zero options (the server
// cap, no description).
type SessionChallengeFunc func(r *http.Request) (SessionChallengeOptions, error)

// SessionMiddleware wraps an http.Handler to enforce MPP session payments.
//
// Requests without a valid credential receive a 402 with a session challenge
// in WWW-Authenticate. Requests with a valid credential have the action
// applied (open / voucher / commit / topUp / close), the receipt exposed in
// Payment-Receipt and the request context, and are passed through. The
// challenge (and its recentBlockhash prefetch) is only built when a 402 is
// actually issued, so the verify path never fetches a blockhash.
func SessionMiddleware(s *Session, challengeFn SessionChallengeFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var verificationErr error
			authHeader := r.Header.Get(core.AuthorizationHeader)
			if paymentToken, ok := core.ExtractPaymentScheme(authHeader); ok && paymentToken != "" {
				credential, err := core.ParseAuthorization(authHeader)
				if err != nil {
					verificationErr = core.WrapError(core.ErrCodeInvalidPayload, "parse authorization", err)
				} else {
					receipt, verifyErr := s.VerifyCredential(r.Context(), credential)
					if verifyErr == nil {
						if receiptHeader, fmtErr := core.FormatReceipt(receipt); fmtErr == nil {
							w.Header().Set(core.PaymentReceiptHeader, receiptHeader)
						}
						markAuthorizationBoundResponse(w.Header())
						ctx := context.WithValue(r.Context(), receiptContextKey, receipt)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
					verificationErr = verifyErr
				}
			}

			options := SessionChallengeOptions{}
			if challengeFn != nil {
				var err error
				options, err = challengeFn(r)
				if err != nil {
					http.Error(w, "challenge function error", http.StatusInternalServerError)
					return
				}
			}
			challenge, err := s.Challenge(r.Context(), options)
			if err != nil {
				http.Error(w, "failed to create challenge", http.StatusInternalServerError)
				return
			}
			wwwAuth, err := core.FormatWWWAuthenticate(challenge)
			if err != nil {
				http.Error(w, "failed to format challenge", http.StatusInternalServerError)
				return
			}
			w.Header().Set(core.WWWAuthenticateHeader, wwwAuth)
			markAuthorizationBoundResponse(w.Header())

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
