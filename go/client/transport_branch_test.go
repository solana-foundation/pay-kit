package client

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	mpp "github.com/solana-foundation/mpp-sdk/go"
	"github.com/solana-foundation/mpp-sdk/go/internal/testutil"
)

// errReader fails on Read to exercise the body-buffering error branch.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, errors.New("read failed") }
func (errReader) Close() error               { return nil }

func TestTransportBodyReadError(t *testing.T) {
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		Signer: testutil.NewPrivateKey(),
		RPC:    testutil.NewFakeRPC(),
	}
	req, _ := http.NewRequest("POST", "http://example.com", errReader{})
	if _, err := transport.RoundTrip(req); err == nil {
		t.Fatal("expected body read error")
	}
}

func TestTransportBaseRoundTripError(t *testing.T) {
	transport := &PaymentTransport{
		Base: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("network down")
		}),
		Signer: testutil.NewPrivateKey(),
		RPC:    testutil.NewFakeRPC(),
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	if _, err := transport.RoundTrip(req); err == nil {
		t.Fatal("expected network error")
	}
}

func TestTransportBaseDefaultsToHTTPDefaultTransport(t *testing.T) {
	pt := &PaymentTransport{}
	if pt.base() == nil {
		t.Fatal("expected default base transport")
	}
}

func TestTransportBuildOptionsCustom(t *testing.T) {
	custom := &BuildOptions{ComputeUnitLimit: 500_000, ComputeUnitPrice: 42}
	pt := &PaymentTransport{Options: custom}
	got := pt.buildOptions()
	if got.ComputeUnitLimit != 500_000 || got.ComputeUnitPrice != 42 {
		t.Fatalf("unexpected options: %+v", got)
	}
}

func TestTransport402EmptyChallengesReturnsOriginal(t *testing.T) {
	transport := &PaymentTransport{
		Base: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusPaymentRequired,
				Body:       io.NopCloser(strings.NewReader("nope")),
				Header:     http.Header{},
			}, nil
		}),
		Signer: testutil.NewPrivateKey(),
		RPC:    testutil.NewFakeRPC(),
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", resp.StatusCode)
	}
}

func TestTransportBuildCredentialErrorReturnsOriginal402(t *testing.T) {
	// Craft a 402 whose challenge is parseable but whose request causes
	// BuildCredentialHeaderWithOptions to fail (invalid amount), exercising the
	// "Cannot build credential" fallback that returns the original 402.
	badRequest, _ := mpp.NewBase64URLJSONValue(map[string]any{
		"amount":    "not-a-number",
		"currency":  "sol",
		"recipient": testutil.NewPrivateKey().PublicKey().String(),
		"methodDetails": map[string]any{
			"network":         "localnet",
			"recentBlockhash": testutil.NewFakeRPC().Blockhash.String(),
		},
	})
	bad := mpp.NewChallengeWithSecret("secret", "realm", "solana", "charge", badRequest)
	wwwAuth, err := mpp.FormatWWWAuthenticate(bad)
	if err != nil {
		t.Fatalf("format challenge: %v", err)
	}
	transport := &PaymentTransport{
		Base: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusPaymentRequired,
				Body:       io.NopCloser(strings.NewReader("payment required")),
				Header:     http.Header{mpp.WWWAuthenticateHeader: {wwwAuth}},
			}, nil
		}),
		Signer: testutil.NewPrivateKey(),
		RPC:    testutil.NewFakeRPC(),
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected original 402, got %d", resp.StatusCode)
	}
}

// req.Context() never returns nil per Go stdlib; this branch is defensive and
// effectively unreachable through public API. Documented as unreachable.

func TestNewClientWithOption(t *testing.T) {
	signer := testutil.NewPrivateKey()
	rpc := testutil.NewFakeRPC()
	c := NewClient(signer, rpc, func(pt *PaymentTransport) {
		pt.Options = &BuildOptions{ComputeUnitLimit: 333}
	})
	pt := c.Transport.(*PaymentTransport)
	if pt.Options == nil || pt.Options.ComputeUnitLimit != 333 {
		t.Fatal("expected option to be applied")
	}
}
