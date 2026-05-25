package client

import (
	"bytes"
	"context"
	"io"
	"net/http"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/internal/solanautil"
)

// PaymentTransport wraps an http.RoundTripper and transparently handles
// HTTP 402 challenges by building a payment credential and retrying.
type PaymentTransport struct {
	Base    http.RoundTripper
	Signer  solanautil.Signer
	RPC     solanautil.RPCClient
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
		req.Body.Close()
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

	challenge := challenges[0]

	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	authHeader, err := BuildCredentialHeaderWithOptions(ctx, t.Signer, t.RPC, challenge, t.buildOptions())
	if err != nil {
		// Cannot build credential — return original 402.
		return resp, nil
	}

	// Drain and close the first response body before retrying.
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Clone the request for retry.
	retry := req.Clone(req.Context())
	retry.Header.Set(mpp.AuthorizationHeader, authHeader)
	if bodyBytes != nil {
		retry.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		retry.ContentLength = int64(len(bodyBytes))
	}

	return t.base().RoundTrip(retry)
}

// NewClient creates an *http.Client with automatic 402 payment handling.
func NewClient(signer solanautil.Signer, rpc solanautil.RPCClient, opts ...func(*PaymentTransport)) *http.Client {
	transport := &PaymentTransport{
		Signer: signer,
		RPC:    rpc,
	}
	for _, opt := range opts {
		opt(transport)
	}
	return &http.Client{Transport: transport}
}
