package client

import (
	"bytes"
	"io"
	"net/http"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/internal/utils"
)

// PaymentTransport wraps an http.RoundTripper and transparently handles
// HTTP 402 challenges by building a payment credential and retrying.
type PaymentTransport struct {
	Base    http.RoundTripper
	Signer  utils.Signer
	RPC     utils.RPCClient
	Options *BuildOptions
}

func (t *PaymentTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *PaymentTransport) buildOptions() BuildOptions {
	if t.Options != nil {
		return *t.Options
	}
	return BuildOptions{}
}

// RoundTrip implements http.RoundTripper. If the server responds with 402 and
// a valid WWW-Authenticate challenge, it builds a payment credential and
// retries the request with an Authorization header.
func (t *PaymentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Buffer the request body if present so we can replay it.
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	resp, err := t.base().RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusPaymentRequired {
		return resp, nil
	}

	challenges := mpp.ParseWWWAuthenticateAll(resp.Header.Values(mpp.WWWAuthenticateHeader))
	if len(challenges) == 0 {
		return resp, nil
	}

	challenge, ok := selectChargeChallenge(challenges)
	if !ok {
		return resp, nil
	}

	// req.Context() is documented to never return nil for a server-prepared
	// or client-built request, so propagate it directly. Never substitute
	// context.Background() here, which would break cancellation/deadline.
	authHeader, err := BuildCredentialHeaderWithOptions(req.Context(), t.Signer, t.RPC, challenge, t.buildOptions())
	if err != nil {
		// Cannot build credential: return the original 402 response so the
		// caller still sees the server's challenge headers. The credential
		// build failure is recoverable from the caller's perspective.
		return resp, nil //nolint:nilerr // intentional fallback to original 402
	}

	// Drain and close the first response body before retrying.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// Clone the request for retry.
	retry := req.Clone(req.Context())
	retry.Header.Set(mpp.AuthorizationHeader, authHeader)
	if bodyBytes != nil {
		retry.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		retry.ContentLength = int64(len(bodyBytes))
	}

	return t.base().RoundTrip(retry)
}

func selectChargeChallenge(challenges []mpp.PaymentChallenge) (mpp.PaymentChallenge, bool) {
	for _, challenge := range challenges {
		if isSupportedChargeChallenge(challenge) {
			return challenge, true
		}
	}
	return mpp.PaymentChallenge{}, false
}

func isSupportedChargeChallenge(challenge mpp.PaymentChallenge) bool {
	return challenge.Method == mpp.NewMethodName("solana") && challenge.Intent.IsCharge()
}

// NewClient creates an *http.Client with automatic 402 payment handling.
func NewClient(signer utils.Signer, rpc utils.RPCClient, opts ...func(*PaymentTransport)) *http.Client {
	transport := &PaymentTransport{
		Signer: signer,
		RPC:    rpc,
	}
	for _, opt := range opts {
		opt(transport)
	}
	return &http.Client{Transport: transport}
}
