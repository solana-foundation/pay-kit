package client

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
)

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func (errReadCloser) Close() error {
	return nil
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestChallenge() mpp.PaymentChallenge {
	return newTestChallengeFor("solana", "charge")
}

func newTestChallengeFor(method string, intent string) mpp.PaymentChallenge {
	fakeRPC := testutil.NewFakeRPC()
	request, _ := mpp.NewBase64URLJSONValue(map[string]any{
		"amount":    "1000",
		"currency":  "sol",
		"recipient": testutil.NewPrivateKey().PublicKey().String(),
		"methodDetails": map[string]any{
			"network":         "localnet",
			"recentBlockhash": fakeRPC.Blockhash.String(),
		},
	})
	return mpp.NewChallengeWithSecret(
		"secret",
		"realm",
		mpp.NewMethodName(method),
		mpp.NewIntentName(intent),
		request,
	)
}

func TestTransportPassthroughNon402(t *testing.T) {
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestTransport402RetryWithAuthorization(t *testing.T) {
	challenge := newTestChallenge()
	wwwAuth, err := mpp.FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format challenge: %v", err)
	}

	calls := 0
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{
					StatusCode: http.StatusPaymentRequired,
					Body:       io.NopCloser(strings.NewReader("payment required")),
					Header:     http.Header{"Www-Authenticate": {wwwAuth}},
				}, nil
			}
			auth := req.Header.Get(mpp.AuthorizationHeader)
			if auth == "" {
				t.Fatal("expected Authorization header on retry")
			}
			if !strings.HasPrefix(auth, mpp.PaymentScheme+" ") {
				t.Fatalf("expected Payment scheme, got %q", auth)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("paid")),
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after retry, got %d", resp.StatusCode)
	}
	if calls != 2 {
		t.Fatalf("expected 2 round trips, got %d", calls)
	}
}

func TestTransport402RetryWithMergedWWWAuthenticate(t *testing.T) {
	challenge := newTestChallenge()
	wwwAuth, err := mpp.FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format challenge: %v", err)
	}

	calls := 0
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{
					StatusCode: http.StatusPaymentRequired,
					Body:       io.NopCloser(strings.NewReader("payment required")),
					Header: http.Header{
						"Www-Authenticate": {`Bearer realm="api"`, wwwAuth},
					},
				}, nil
			}
			if req.Header.Get(mpp.AuthorizationHeader) == "" {
				t.Fatal("expected Authorization header on retry")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("paid")),
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after retry, got %d", resp.StatusCode)
	}
	if calls != 2 {
		t.Fatalf("expected 2 round trips, got %d", calls)
	}
}

func TestTransportInvalidWWWAuthenticateReturnsOriginal402(t *testing.T) {
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusPaymentRequired,
				Body:       io.NopCloser(strings.NewReader("bad")),
				Header:     http.Header{mpp.WWWAuthenticateHeader: {"Bearer realm=test"}},
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

func TestTransportPOSTBodyReplay(t *testing.T) {
	challenge := newTestChallenge()
	wwwAuth, err := mpp.FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format challenge: %v", err)
	}

	bodyContent := "request-body-data"
	calls := 0
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.Body != nil {
				body, _ := io.ReadAll(req.Body)
				if string(body) != bodyContent {
					t.Fatalf("call %d: expected body %q, got %q", calls, bodyContent, string(body))
				}
			} else if calls == 2 {
				t.Fatal("expected body on retry")
			}
			if calls == 1 {
				return &http.Response{
					StatusCode: http.StatusPaymentRequired,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     http.Header{"Www-Authenticate": {wwwAuth}},
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     http.Header{},
			}, nil
		}),
		Signer: testutil.NewPrivateKey(),
		RPC:    testutil.NewFakeRPC(),
	}

	req, _ := http.NewRequest("POST", "http://example.com", bytes.NewReader([]byte(bodyContent)))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
}

func TestNewClient(t *testing.T) {
	signer := testutil.NewPrivateKey()
	rpc := testutil.NewFakeRPC()
	c := NewClient(signer, rpc)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	pt, ok := c.Transport.(*PaymentTransport)
	if !ok {
		t.Fatal("expected PaymentTransport")
	}
	if pt.Signer == nil || pt.RPC == nil {
		t.Fatal("expected signer and rpc to be set")
	}
}

func TestBuildCredentialDirect(t *testing.T) {
	fakeRPC := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	challenge := newTestChallenge()
	header, err := BuildCredentialHeader(t.Context(), signer, fakeRPC, challenge)
	if err != nil {
		t.Fatalf("BuildCredentialHeader failed: %v", err)
	}
	t.Logf("header: %s", header[:50])
}

func TestTransport402Debug(t *testing.T) {
	challenge := newTestChallenge()
	wwwAuth, _ := mpp.FormatWWWAuthenticate(challenge)
	parsed, err := mpp.ParseWWWAuthenticate(wwwAuth)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	fakeRPC := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()

	header, err := BuildCredentialHeader(t.Context(), signer, fakeRPC, parsed)
	if err != nil {
		t.Fatalf("BuildCredentialHeader after roundtrip: %v", err)
	}
	t.Logf("OK: %s...", header[:40])
}

func TestTransport402SelectsSolanaChargeChallenge(t *testing.T) {
	unsupportedChallenge := newTestChallengeFor("card", "charge")
	unsupportedWWWAuth, err := mpp.FormatWWWAuthenticate(unsupportedChallenge)
	if err != nil {
		t.Fatalf("format unsupported challenge: %v", err)
	}
	challenge := newTestChallenge()
	wwwAuth, err := mpp.FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format challenge: %v", err)
	}

	calls := 0
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{
					StatusCode: http.StatusPaymentRequired,
					Body:       io.NopCloser(strings.NewReader("payment required")),
					Header:     http.Header{"Www-Authenticate": {unsupportedWWWAuth, wwwAuth}},
				}, nil
			}
			auth := req.Header.Get(mpp.AuthorizationHeader)
			if auth == "" {
				t.Fatal("expected Authorization header on retry")
			}
			credential, err := mpp.ParseAuthorization(auth)
			if err != nil {
				t.Fatalf("parse retry authorization: %v", err)
			}
			if credential.Challenge.Method != "solana" {
				t.Fatalf("expected solana challenge, got %q", credential.Challenge.Method)
			}
			if !credential.Challenge.Intent.IsCharge() {
				t.Fatalf("expected charge intent, got %q", credential.Challenge.Intent)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("paid")),
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after retry, got %d", resp.StatusCode)
	}
	if calls != 2 {
		t.Fatalf("expected 2 round trips, got %d", calls)
	}
}

func TestTransport402KeepsOriginalResponseWithoutSupportedChargeChallenge(t *testing.T) {
	unsupportedChallenge := newTestChallengeFor("card", "charge")
	unsupportedWWWAuth, err := mpp.FormatWWWAuthenticate(unsupportedChallenge)
	if err != nil {
		t.Fatalf("format unsupported challenge: %v", err)
	}

	calls := 0
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusPaymentRequired,
				Body:       io.NopCloser(strings.NewReader("payment required")),
				Header:     http.Header{"Www-Authenticate": {unsupportedWWWAuth}},
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
	if calls != 1 {
		t.Fatalf("expected 1 round trip, got %d", calls)
	}
}

func TestTransportDefaults(t *testing.T) {
	transport := &PaymentTransport{}
	if transport.base() != http.DefaultTransport {
		t.Fatal("expected default transport")
	}
	if got := transport.buildOptions(); got != (BuildOptions{}) {
		t.Fatalf("expected empty build options, got %#v", got)
	}

	opts := &BuildOptions{ComputeUnitLimit: 400_000, ComputeUnitPrice: 10}
	transport.Options = opts
	if got := transport.buildOptions(); got != *opts {
		t.Fatalf("expected configured build options, got %#v", got)
	}
}

func TestTransportReturnsBodyReadError(t *testing.T) {
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatal("base transport should not be called when request body cannot be buffered")
			return nil, nil
		}),
	}

	req, _ := http.NewRequest("POST", "http://example.com", nil)
	req.Body = errReadCloser{}
	_, err := transport.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("expected body read error, got %v", err)
	}
}

func TestTransportReturnsBaseError(t *testing.T) {
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("network failed")
		}),
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	_, err := transport.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "network failed") {
		t.Fatalf("expected base transport error, got %v", err)
	}
}

func TestTransportBuildCredentialFailureReturnsOriginal402(t *testing.T) {
	request, err := mpp.NewBase64URLJSONValue(map[string]any{
		"amount":    "not-a-number",
		"currency":  "sol",
		"recipient": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("request encode failed: %v", err)
	}
	challenge := mpp.NewChallengeWithSecret("secret", "realm", "solana", "charge", request)
	wwwAuth, err := mpp.FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format challenge: %v", err)
	}

	calls := 0
	transport := &PaymentTransport{
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusPaymentRequired,
				Body:       io.NopCloser(strings.NewReader("payment required")),
				Header:     http.Header{"Www-Authenticate": {wwwAuth}},
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
	if calls != 1 {
		t.Fatalf("expected no retry when credential build fails, got %d calls", calls)
	}
}
