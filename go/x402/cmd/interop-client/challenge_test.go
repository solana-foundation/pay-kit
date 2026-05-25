package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gagliardetto/solana-go"
)

func TestSelectSVMRequirementFromPaymentRequiredHeader(t *testing.T) {
	requirement := map[string]any{
		"scheme":  "exact",
		"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		"amount":  "1000",
	}
	envelope, err := json.Marshal(map[string]any{
		"x402Version": 2,
		"accepts":     []map[string]any{requirement},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected := selectSVMRequirement(
		map[string]string{"PAYMENT-REQUIRED": base64.StdEncoding.EncodeToString(envelope)},
		"",
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"exact",
	)

	if selected == nil {
		t.Fatal("expected selected requirement")
	}
	if selected.Asset != requirement["asset"] {
		t.Fatalf("unexpected asset: %s", selected.Asset)
	}
}

func TestSelectSVMRequirementFromBody(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": "eip155:8453",
				"asset":   "0x0000000000000000000000000000000000000000",
				"amount":  "1000",
			},
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected := selectSVMRequirement(
		map[string]string{},
		string(body),
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"exact",
	)

	if selected == nil {
		t.Fatal("expected selected requirement")
	}
	if selected.Network != "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" {
		t.Fatalf("unexpected network: %s", selected.Network)
	}
}

func TestSelectSVMRequirementIgnoresUnsupportedScheme(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "upto",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected := selectSVMRequirement(
		map[string]string{},
		string(body),
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"exact",
	)

	if selected != nil {
		t.Fatalf("expected no selected requirement, got %+v", selected)
	}
}

func TestSelectSVMRequirementSupportsRequestedUptoScheme(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "upto",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected := selectSVMRequirement(
		map[string]string{},
		string(body),
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"upto",
	)

	if selected == nil {
		t.Fatal("expected selected upto requirement")
	}
	if selected.Scheme != "upto" {
		t.Fatalf("unexpected scheme: %s", selected.Scheme)
	}
}

func TestSelectSVMChallengeHonorsPreferredCurrencyOrder(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000",
			},
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected, _ := selectSVMChallengeWithPreferences(
		map[string]string{},
		string(body),
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"exact",
		[]string{"PYUSD", "USDC"},
	)

	if selected == nil {
		t.Fatal("expected selected requirement")
	}
	if selected.Asset != "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM" {
		t.Fatalf("expected PYUSD mint, got %s", selected.Asset)
	}
}

func TestSelectSVMChallengeReturnsNilWhenPreferredCurrenciesDoNotMatch(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected, _ := selectSVMChallengeWithPreferences(
		map[string]string{},
		string(body),
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"exact",
		[]string{"PYUSD"},
	)

	if selected != nil {
		t.Fatalf("expected no selected requirement, got %+v", selected)
	}
}

func TestSelectSVMChallengeChecksBodyWhenHeaderPreferencesDoNotMatch(t *testing.T) {
	headerEnvelope, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"resource": map[string]any{"uri": "/body"},
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected, resource := selectSVMChallengeWithPreferences(
		map[string]string{"PAYMENT-REQUIRED": base64.StdEncoding.EncodeToString(headerEnvelope)},
		string(body),
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"exact",
		[]string{"PYUSD"},
	)

	if selected == nil {
		t.Fatal("expected selected requirement from body")
	}
	if selected.Asset != "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM" {
		t.Fatalf("expected body PYUSD mint, got %s", selected.Asset)
	}
	if resource["uri"] != "/body" {
		t.Fatalf("expected body resource, got %#v", resource)
	}
}

func TestSelectSVMChallengeWithoutPreferencesPicksCheapestAmount(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000000",
			},
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "So11111111111111111111111111111111111111112",
				"amount":  "5000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected, _ := selectSVMChallengeWithPreferences(
		map[string]string{},
		string(body),
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"exact",
		nil,
	)

	if selected == nil {
		t.Fatal("expected selected requirement")
	}
	if selected.Asset != "So11111111111111111111111111111111111111112" {
		t.Fatalf("expected cheapest offer, got %s", selected.Asset)
	}
}

func TestSelectSVMChallengeSkipsIncompleteAndMalformedCandidates(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "",
				"amount":  "1",
			},
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "So11111111111111111111111111111111111111112",
				"amount":  "not-int",
			},
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected, _ := selectSVMChallengeWithPreferences(
		map[string]string{},
		string(body),
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"exact",
		nil,
	)

	if selected == nil {
		t.Fatal("expected selected requirement")
	}
	if selected.Asset != "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" {
		t.Fatalf("expected valid cheapest candidate, got %+v", selected)
	}
}

func TestSelectSVMChallengeUsesCurrencyPreferencesFromEnv(t *testing.T) {
	t.Setenv("X402_INTEROP_PREFER_CURRENCIES", " PYUSD, USDC ,,")
	body, err := json.Marshal(map[string]any{
		"resource": map[string]any{"uri": "/protected"},
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000",
			},
			{
				"scheme":  "exact",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
				"amount":  "2000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected, resource := selectSVMChallenge(
		map[string]string{},
		string(body),
		"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"exact",
	)

	if selected == nil {
		t.Fatal("expected selected requirement")
	}
	if selected.Asset != "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM" {
		t.Fatalf("expected PYUSD preference to win, got %s", selected.Asset)
	}
	if resource["uri"] != "/protected" {
		t.Fatalf("expected resource to be returned, got %+v", resource)
	}
}

func TestPaymentRequiredLoadersRejectMalformedInputs(t *testing.T) {
	if envelope := loadPaymentRequiredHeader(map[string]string{"payment-required": "not base64"}); envelope != nil {
		t.Fatalf("expected invalid base64 header to return nil")
	}
	encodedInvalidJSON := base64.StdEncoding.EncodeToString([]byte("{"))
	if envelope := loadPaymentRequiredHeader(map[string]string{"payment-required": encodedInvalidJSON}); envelope != nil {
		t.Fatalf("expected invalid JSON header to return nil")
	}
	if envelope := loadPaymentRequiredBody("{"); envelope != nil {
		t.Fatalf("expected invalid JSON body to return nil")
	}
	if envelope := loadPaymentRequiredBody(""); envelope != nil {
		t.Fatalf("expected empty body to return nil")
	}
}

func TestResolveStablecoinMintCanonicalAliases(t *testing.T) {
	tests := map[string]struct {
		currency string
		network  string
		want     string
	}{
		"devnet USD alias": {
			currency: " usd ",
			network:  "devnet",
			want:     "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		},
		"mainnet PYUSD": {
			currency: "PYUSD",
			network:  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
			want:     "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
		},
		"localnet USDG": {
			currency: "USDG",
			network:  "localnet",
			want:     "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
		},
		"USDT": {
			currency: "USDT",
			network:  "devnet",
			want:     "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
		},
		"CASH": {
			currency: "CASH",
			network:  "devnet",
			want:     "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH",
		},
		"mint passthrough": {
			currency: " So11111111111111111111111111111111111111112 ",
			network:  "devnet",
			want:     "So11111111111111111111111111111111111111112",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := resolveStablecoinMint(test.currency, test.network); got != test.want {
				t.Fatalf("resolveStablecoinMint() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRequirementExtraParsersValidateTypes(t *testing.T) {
	requirement := paymentRequirement{
		Extra: map[string]any{
			"decimalsFloat": float64(6),
			"decimalsText":  "9",
			"tokenProgram":  solana.TokenProgramID.String(),
			"badInteger":    "not-int",
			"badString":     12,
			"emptyString":   "",
		},
	}

	if got, err := intFromRequirement(requirement, "decimalsFloat"); err != nil || got != 6 {
		t.Fatalf("float integer = %d, %v", got, err)
	}
	if got, err := intFromRequirement(requirement, "decimalsText"); err != nil || got != 9 {
		t.Fatalf("string integer = %d, %v", got, err)
	}
	if _, err := intFromRequirement(requirement, "missing"); err == nil {
		t.Fatal("expected missing integer error")
	}
	if _, err := intFromRequirement(requirement, "badInteger"); err == nil {
		t.Fatal("expected invalid integer error")
	}
	if _, err := intFromRequirement(paymentRequirement{Extra: map[string]any{"bad": true}}, "bad"); err == nil {
		t.Fatal("expected invalid integer type error")
	}
	if got, err := stringFromExtra(requirement, "tokenProgram"); err != nil || got != solana.TokenProgramID.String() {
		t.Fatalf("string extra = %q, %v", got, err)
	}
	if _, err := stringFromExtra(requirement, "missing"); err == nil {
		t.Fatal("expected missing string error")
	}
	if _, err := stringFromExtra(requirement, "badString"); err == nil {
		t.Fatal("expected invalid string type error")
	}
	if _, err := stringFromExtra(requirement, "emptyString"); err == nil {
		t.Fatal("expected empty string error")
	}
}

func TestKeypairFromJSONSecretValidatesShape(t *testing.T) {
	privateKey, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal([]byte(privateKey))
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := keypairFromJSONSecret(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.PublicKey().Equals(privateKey.PublicKey()) {
		t.Fatalf("decoded key does not match original")
	}
	if _, err := keypairFromJSONSecret("{"); err == nil {
		t.Fatal("expected JSON decode error")
	}
	if _, err := keypairFromJSONSecret("[1,2,3]"); err == nil {
		t.Fatal("expected length validation error")
	}
}

func TestLatestBlockhashHandlesJSONRPCResponses(t *testing.T) {
	originalHTTPClient := httpClient
	defer func() {
		httpClient = originalHTTPClient
	}()

	blockhash := solana.Hash{}.String()
	httpClient = &http.Client{Transport: clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		rawBody, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(rawBody), `"method":"getLatestBlockhash"`) {
			t.Fatalf("unexpected RPC body: %s", string(rawBody))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"` + blockhash + `"}}}`)),
		}, nil
	})}

	got, err := latestBlockhash("http://rpc.test")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != blockhash {
		t.Fatalf("latestBlockhash = %s, want %s", got, blockhash)
	}

	httpClient = &http.Client{Transport: clientRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"error":{"message":"nope"}}`)),
		}, nil
	})}
	if _, err := latestBlockhash("http://rpc.test"); err == nil {
		t.Fatal("expected RPC error")
	}

	httpClient = &http.Client{Transport: clientRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`bad gateway`)),
		}, nil
	})}
	if _, err := latestBlockhash("http://rpc.test"); err == nil {
		t.Fatal("expected HTTP error")
	}

	httpClient = &http.Client{Transport: clientRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{`)),
		}, nil
	})}
	if _, err := latestBlockhash("http://rpc.test"); err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestLatestBlockhashReturnsTransportErrors(t *testing.T) {
	originalHTTPClient := httpClient
	defer func() {
		httpClient = originalHTTPClient
	}()

	httpClient = &http.Client{Transport: clientRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("rpc unavailable")
	})}
	if _, err := latestBlockhash("http://rpc.test"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestTransferCheckedInstructionRejectsMalformedRequirement(t *testing.T) {
	signer := solana.NewWallet().PublicKey()
	base := paymentRequirement{
		Asset:  "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		Amount: "1000",
		PayTo:  solana.NewWallet().PublicKey().String(),
	}

	tests := map[string]paymentRequirement{
		"amount": func() paymentRequirement {
			requirement := base
			requirement.Amount = "not-int"
			return requirement
		}(),
		"asset": func() paymentRequirement {
			requirement := base
			requirement.Asset = "not-base58"
			return requirement
		}(),
		"payTo": func() paymentRequirement {
			requirement := base
			requirement.PayTo = "not-base58"
			return requirement
		}(),
	}

	for name, requirement := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := transferCheckedInstruction(requirement, signer, 6, solana.TokenProgramID); err == nil {
				t.Fatal("expected malformed requirement to be rejected")
			}
		})
	}
}

func TestReadResponseAndParseResponseBody(t *testing.T) {
	response := &http.Response{
		Header: http.Header{
			"X-Test": []string{"first", "second"},
		},
		Body: io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}

	headers, body, err := readResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if headers["X-Test"] != "first" {
		t.Fatalf("expected first header value, got %q", headers["X-Test"])
	}
	if body != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", body)
	}
	parsed, ok := parseResponseBody(body).(map[string]any)
	if !ok || parsed["ok"] != true {
		t.Fatalf("expected JSON body to parse, got %#v", parsed)
	}
	if got := parseResponseBody("not json"); got != "not json" {
		t.Fatalf("expected invalid JSON body passthrough, got %#v", got)
	}
	t.Setenv("X402_TEST_DEFAULT", "configured")
	if got := readEnvWithDefault("X402_TEST_DEFAULT", "fallback"); got != "configured" {
		t.Fatalf("readEnvWithDefault configured = %q", got)
	}
	if got := readEnvWithDefault("X402_TEST_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("readEnvWithDefault fallback = %q", got)
	}
}

func TestMainReportsUnimplementedChallengeResult(t *testing.T) {
	originalHTTPClient := httpClient
	defer func() {
		httpClient = originalHTTPClient
	}()
	httpClient = &http.Client{Transport: clientRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusPaymentRequired,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"accepts":[{"scheme":"upto","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","asset":"4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU","amount":"1000"}]}`)),
		}, nil
	})}

	t.Setenv("X402_INTEROP_TARGET_URL", "http://interop.test/protected")
	t.Setenv("X402_INTEROP_SCHEME", "upto")

	output := captureStdoutForTest(t, main)
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["implementation"] != "go" || payload["role"] != "client" || payload["ok"] != false {
		t.Fatalf("unexpected result payload: %#v", payload)
	}
	body := payload["responseBody"].(map[string]any)
	if body["error"] != "go_upto_client_not_implemented" {
		t.Fatalf("unexpected error domain: %#v", body)
	}
}

func TestMainPanicsWhenTargetURLMissing(t *testing.T) {
	mustPanicClient(t, main)
}

func TestMainPanicsWhenChallengeRequestFails(t *testing.T) {
	originalHTTPClient := httpClient
	defer func() {
		httpClient = originalHTTPClient
	}()
	httpClient = &http.Client{Transport: clientRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})}

	t.Setenv("X402_INTEROP_TARGET_URL", "http://interop.test/protected")

	mustPanicClient(t, main)
}

func TestMainReportsExactPaymentBuildFailure(t *testing.T) {
	requirement := map[string]any{
		"scheme":  "exact",
		"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		"amount":  "1000",
		"payTo":   solana.NewWallet().PublicKey().String(),
		"extra": map[string]any{
			"decimals":     6,
			"feePayer":     solana.NewWallet().PublicKey().String(),
			"tokenProgram": solana.TokenProgramID.String(),
		},
	}
	challenge, err := json.Marshal(paymentEnvelope{
		Accepts: []paymentRequirement{{
			Scheme:  requirement["scheme"].(string),
			Network: requirement["network"].(string),
			Asset:   requirement["asset"].(string),
			Amount:  requirement["amount"].(string),
			PayTo:   requirement["payTo"].(string),
			Extra:   requirement["extra"].(map[string]any),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	originalHTTPClient := httpClient
	defer func() {
		httpClient = originalHTTPClient
	}()
	httpClient = &http.Client{Transport: clientRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusPaymentRequired,
			Header: http.Header{
				"PAYMENT-REQUIRED": []string{base64.StdEncoding.EncodeToString(challenge)},
				"content-type":     []string{"application/json"},
			},
			Body: io.NopCloser(strings.NewReader(`{"error":"payment_required"}`)),
		}, nil
	})}

	t.Setenv("X402_INTEROP_TARGET_URL", "http://interop.test/protected")
	t.Setenv("X402_INTEROP_CLIENT_SECRET_KEY", "{")
	t.Setenv("X402_INTEROP_RPC_URL", "http://rpc.test")

	output := captureStdoutForTest(t, main)
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["ok"] != false || payload["status"] != float64(http.StatusPaymentRequired) {
		t.Fatalf("unexpected payment failure result: %#v", payload)
	}
	body := payload["responseBody"].(map[string]any)
	if body["error"] != "go_exact_client_payment_failed" {
		t.Fatalf("unexpected payment failure body: %#v", body)
	}
}

func TestMainPaysExactChallengeAndReportsSettlement(t *testing.T) {
	client, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	encodedClientKey, err := json.Marshal([]byte(client))
	if err != nil {
		t.Fatal(err)
	}
	feePayer := solana.NewWallet().PublicKey()
	payTo := solana.NewWallet().PublicKey()
	challenge, err := json.Marshal(paymentEnvelope{
		Accepts: []paymentRequirement{
			{
				Scheme:  "exact",
				Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				Asset:   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				Amount:  "1000",
				PayTo:   payTo.String(),
				Extra: map[string]any{
					"decimals":        float64(6),
					"feePayer":        feePayer.String(),
					"tokenProgram":    solana.TokenProgramID.String(),
					"recentBlockhash": solana.Hash{}.String(),
					"memo":            "unit-main-success",
				},
			},
		},
		Resource: map[string]any{"uri": "/protected"},
	})
	if err != nil {
		t.Fatal(err)
	}

	originalHTTPClient := httpClient
	defer func() {
		httpClient = originalHTTPClient
	}()
	requests := 0
	httpClient = &http.Client{Transport: clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return &http.Response{
				StatusCode: http.StatusPaymentRequired,
				Header: http.Header{
					"PAYMENT-REQUIRED": []string{base64.StdEncoding.EncodeToString(challenge)},
					"content-type":     []string{"application/json"},
				},
				Body: io.NopCloser(strings.NewReader(`{"error":"payment_required"}`)),
			}, nil
		}
		if got := request.Header.Get("PAYMENT-SIGNATURE"); got == "" {
			t.Fatal("expected PAYMENT-SIGNATURE on paid retry")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"x-fixture-settlement": []string{"unit-settlement"},
				"content-type":         []string{"application/json"},
			},
			Body: io.NopCloser(strings.NewReader(`{"ok":true,"paid":true}`)),
		}, nil
	})}

	t.Setenv("X402_INTEROP_TARGET_URL", "http://interop.test/protected")
	t.Setenv("X402_INTEROP_CLIENT_SECRET_KEY", string(encodedClientKey))
	t.Setenv("X402_INTEROP_RPC_URL", "http://rpc.test")

	output := captureStdoutForTest(t, main)
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["ok"] != true || payload["status"] != float64(http.StatusOK) || payload["settlement"] != "unit-settlement" {
		t.Fatalf("unexpected paid result: %#v", payload)
	}
	if requests != 2 {
		t.Fatalf("expected challenge request plus paid retry, got %d", requests)
	}
}

func TestBuildExactPaymentSignatureEnvelope(t *testing.T) {
	client, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	feePayer, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	payTo, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	requirement := paymentRequirement{
		Scheme:            "exact",
		Network:           "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Asset:             "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		Amount:            "1000",
		PayTo:             payTo.PublicKey().String(),
		MaxTimeoutSeconds: 60,
		Extra: map[string]any{
			"feePayer":        feePayer.PublicKey().String(),
			"decimals":        float64(6),
			"tokenProgram":    solana.TokenProgramID.String(),
			"recentBlockhash": solana.Hash{}.String(),
			"memo":            "unit-test",
		},
	}
	resource := map[string]any{
		"url":         "/protected",
		"description": "test",
	}

	header, err := buildExactPaymentSignature(requirement, resource, client, "http://127.0.0.1:8899")
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var envelope paymentSignatureEnvelope
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.X402Version != 2 {
		t.Fatalf("unexpected x402Version: %d", envelope.X402Version)
	}
	if envelope.Accepted.MaxTimeoutSeconds != requirement.MaxTimeoutSeconds {
		t.Fatalf("accepted did not preserve maxTimeoutSeconds")
	}
	if envelope.Payload["transaction"] == "" {
		t.Fatalf("expected transaction payload")
	}

	tx := new(solana.Transaction)
	if err := tx.UnmarshalBase64(envelope.Payload["transaction"]); err != nil {
		t.Fatal(err)
	}
	if !tx.Message.IsVersioned() {
		t.Fatalf("expected v0 transaction")
	}

	signerIndex := -1
	feePayerIndex := -1
	for index, key := range tx.Message.AccountKeys {
		if key.Equals(client.PublicKey()) {
			signerIndex = index
		}
		if key.Equals(feePayer.PublicKey()) {
			feePayerIndex = index
		}
	}
	if signerIndex < 0 {
		t.Fatalf("client signer missing from transaction")
	}
	if feePayerIndex < 0 {
		t.Fatalf("fee payer missing from transaction")
	}
	if tx.Signatures[feePayerIndex] != (solana.Signature{}) {
		t.Fatalf("fee payer signature should remain default")
	}
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !tx.Signatures[signerIndex].Verify(client.PublicKey(), message) {
		t.Fatalf("client signature did not verify")
	}
}

func TestBuildExactPaymentSignatureFetchesRecentBlockhashWhenMissing(t *testing.T) {
	originalHTTPClient := httpClient
	defer func() {
		httpClient = originalHTTPClient
	}()
	blockhash := solana.Hash{}.String()
	httpClient = &http.Client{Transport: clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		rawBody, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(rawBody), `"method":"getLatestBlockhash"`) {
			t.Fatalf("unexpected RPC body: %s", string(rawBody))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"` + blockhash + `"}}}`)),
		}, nil
	})}
	client, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	requirement := paymentRequirement{
		Scheme:  "exact",
		Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Asset:   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		Amount:  "1000",
		PayTo:   solana.NewWallet().PublicKey().String(),
		Extra: map[string]any{
			"feePayer":     solana.NewWallet().PublicKey().String(),
			"decimals":     float64(6),
			"tokenProgram": solana.TokenProgramID.String(),
			"memo":         "unit-fetch-blockhash",
		},
	}

	header, err := buildExactPaymentSignature(requirement, nil, client, "http://rpc.test")
	if err != nil {
		t.Fatal(err)
	}
	if header == "" {
		t.Fatal("expected payment signature")
	}
}

func TestBuildExactPaymentSignatureRejectsInvalidRequirements(t *testing.T) {
	client, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	requirement := paymentRequirement{
		Scheme: "exact",
		Asset:  "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		Amount: "1000",
		PayTo:  solana.NewWallet().PublicKey().String(),
		Extra: map[string]any{
			"feePayer":        solana.NewWallet().PublicKey().String(),
			"decimals":        float64(6),
			"tokenProgram":    solana.TokenProgramID.String(),
			"recentBlockhash": solana.Hash{}.String(),
			"memo":            "unit-test",
		},
	}

	tests := map[string]func(paymentRequirement) paymentRequirement{
		"scheme": func(value paymentRequirement) paymentRequirement {
			value.Scheme = "upto"
			return value
		},
		"missing decimals": func(value paymentRequirement) paymentRequirement {
			value.Extra = cloneClientExtra(value.Extra)
			delete(value.Extra, "decimals")
			return value
		},
		"invalid token program": func(value paymentRequirement) paymentRequirement {
			value.Extra = cloneClientExtra(value.Extra)
			value.Extra["tokenProgram"] = "not-base58"
			return value
		},
		"invalid fee payer": func(value paymentRequirement) paymentRequirement {
			value.Extra = cloneClientExtra(value.Extra)
			value.Extra["feePayer"] = "not-base58"
			return value
		},
		"invalid blockhash": func(value paymentRequirement) paymentRequirement {
			value.Extra = cloneClientExtra(value.Extra)
			value.Extra["recentBlockhash"] = "not-base58"
			return value
		},
		"invalid amount": func(value paymentRequirement) paymentRequirement {
			value.Amount = "not-int"
			return value
		},
		"invalid payTo": func(value paymentRequirement) paymentRequirement {
			value.PayTo = "not-base58"
			return value
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := buildExactPaymentSignature(mutate(requirement), nil, client, "http://127.0.0.1:8899"); err == nil {
				t.Fatal("expected invalid requirement to be rejected")
			}
		})
	}
}

func TestBuildExactPaymentSignatureGeneratesUniqueDefaultMemos(t *testing.T) {
	client, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	feePayer, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	payTo, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	requirement := paymentRequirement{
		Scheme:  "exact",
		Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Asset:   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		Amount:  "1000",
		PayTo:   payTo.PublicKey().String(),
		Extra: map[string]any{
			"feePayer":        feePayer.PublicKey().String(),
			"decimals":        float64(6),
			"tokenProgram":    solana.TokenProgramID.String(),
			"recentBlockhash": solana.Hash{}.String(),
		},
	}

	firstHeader, err := buildExactPaymentSignature(requirement, nil, client, "http://127.0.0.1:8899")
	if err != nil {
		t.Fatal(err)
	}
	secondHeader, err := buildExactPaymentSignature(requirement, nil, client, "http://127.0.0.1:8899")
	if err != nil {
		t.Fatal(err)
	}

	firstMemo := memoFromPaymentHeaderForTest(t, firstHeader)
	secondMemo := memoFromPaymentHeaderForTest(t, secondHeader)
	if firstHeader == secondHeader {
		t.Fatal("expected unique payment headers")
	}
	if firstMemo == secondMemo {
		t.Fatalf("expected unique default memos, got %q", firstMemo)
	}
	if len(firstMemo) != 32 || len(secondMemo) != 32 {
		t.Fatalf("expected 32 byte hex memos, got %d and %d", len(firstMemo), len(secondMemo))
	}
	if strings.Trim(firstMemo+secondMemo, "0123456789abcdef") != "" {
		t.Fatalf("expected lowercase hex memos, got %q and %q", firstMemo, secondMemo)
	}
}

func TestBuildExactPaymentSignatureRejectsMemoAboveReferenceLimit(t *testing.T) {
	client, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	feePayer, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	payTo, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	requirement := paymentRequirement{
		Scheme:  "exact",
		Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Asset:   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		Amount:  "1000",
		PayTo:   payTo.PublicKey().String(),
		Extra: map[string]any{
			"feePayer":        feePayer.PublicKey().String(),
			"decimals":        float64(6),
			"tokenProgram":    solana.TokenProgramID.String(),
			"recentBlockhash": solana.Hash{}.String(),
			"memo":            strings.Repeat("x", maxMemoBytes+1),
		},
	}

	_, err = buildExactPaymentSignature(requirement, nil, client, "http://127.0.0.1:8899")
	if err == nil {
		t.Fatal("expected memo length error")
	}
	if err.Error() != "extra.memo exceeds maximum 256 bytes" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func memoFromPaymentHeaderForTest(t *testing.T, header string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var envelope paymentSignatureEnvelope
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		t.Fatal(err)
	}
	tx := new(solana.Transaction)
	if err := tx.UnmarshalBase64(envelope.Payload["transaction"]); err != nil {
		t.Fatal(err)
	}
	for _, instruction := range tx.Message.Instructions {
		program, err := tx.Message.Program(instruction.ProgramIDIndex)
		if err != nil {
			t.Fatal(err)
		}
		if program.Equals(memoProgramID) {
			return string(instruction.Data)
		}
	}
	t.Fatal("memo instruction missing")
	return ""
}

type clientRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn clientRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func cloneClientExtra(extra map[string]any) map[string]any {
	cloned := make(map[string]any, len(extra))
	for key, value := range extra {
		cloned[key] = value
	}
	return cloned
}

func captureStdoutForTest(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = original
	}()

	fn()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}

func mustPanicClient(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}

// --- Greptile PR #18 follow-up: cross-envelope preference / fallback parity ---
//
// These three tests pin the cross-envelope behavior Greptile flagged as
// "absent regression coverage". They exercise the boundary between header and
// body envelopes — both with and without a currency preference — so future
// refactors can't silently regress the fallback path.

// TestSelectSVMChallengeFallsBackToBodyWhenHeaderPreferenceMisses verifies
// that when the PAYMENT-REQUIRED header offers only USDC but the body offers
// PYUSD and the caller prefers ["PYUSD"], the client falls through the header
// envelope and selects the PYUSD entry from the body envelope.
func TestSelectSVMChallengeFallsBackToBodyWhenHeaderPreferenceMisses(t *testing.T) {
	network := "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	headerEnvelope, err := json.Marshal(map[string]any{
		"resource": map[string]any{"uri": "/header"},
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": network,
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", // devnet USDC
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"resource": map[string]any{"uri": "/body"},
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": network,
				"asset":   "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM", // devnet PYUSD
				"amount":  "2000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected, resource := selectSVMChallengeWithPreferences(
		map[string]string{"PAYMENT-REQUIRED": base64.StdEncoding.EncodeToString(headerEnvelope)},
		string(body),
		network,
		"exact",
		[]string{"PYUSD"},
	)

	if selected == nil {
		t.Fatal("expected fallback selection from body envelope")
	}
	if selected.Asset != "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM" {
		t.Fatalf("expected body PYUSD mint, got %s", selected.Asset)
	}
	if resource["uri"] != "/body" {
		t.Fatalf("expected body resource attribution, got %#v", resource)
	}
}

// TestSelectSVMChallengeReturnsNilWhenNoEnvelopeMatchesPreference verifies
// that a strict preference list with no match across any envelope returns nil
// rather than silently downgrading to "any" selection. This locks the caller's
// opt-in: if you said "I only accept BOGUS", you get nothing, not USDC.
func TestSelectSVMChallengeReturnsNilWhenNoEnvelopeMatchesPreference(t *testing.T) {
	network := "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	headerEnvelope, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": network,
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", // USDC
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": network,
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", // USDC
				"amount":  "1500",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected, resource := selectSVMChallengeWithPreferences(
		map[string]string{"PAYMENT-REQUIRED": base64.StdEncoding.EncodeToString(headerEnvelope)},
		string(body),
		network,
		"exact",
		[]string{"BOGUS"},
	)

	if selected != nil {
		t.Fatalf("expected nil selection for unmet preference, got %+v", selected)
	}
	if resource != nil {
		t.Fatalf("expected nil resource for unmet preference, got %#v", resource)
	}
}

// TestSelectSVMChallengePicksCheapestAcrossEnvelopesWhenNoPreference verifies
// that, when no preference is supplied, the selector aggregates valid
// candidates across the header and body envelopes and picks the globally
// cheapest amount — not merely the cheapest within the first envelope it sees.
// Header: 2000 USDC. Body: 1000 PYUSD. Expected: 1000 PYUSD with body's
// resource block.
func TestSelectSVMChallengePicksCheapestAcrossEnvelopesWhenNoPreference(t *testing.T) {
	network := "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	headerEnvelope, err := json.Marshal(map[string]any{
		"resource": map[string]any{"uri": "/header"},
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": network,
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", // USDC
				"amount":  "2000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"resource": map[string]any{"uri": "/body"},
		"accepts": []map[string]any{
			{
				"scheme":  "exact",
				"network": network,
				"asset":   "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM", // PYUSD
				"amount":  "1000",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	selected, resource := selectSVMChallengeWithPreferences(
		map[string]string{"PAYMENT-REQUIRED": base64.StdEncoding.EncodeToString(headerEnvelope)},
		string(body),
		network,
		"exact",
		nil,
	)

	if selected == nil {
		t.Fatal("expected cross-envelope cheapest selection")
	}
	if selected.Asset != "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM" {
		t.Fatalf("expected body PYUSD (cheapest), got %s @ %s", selected.Asset, selected.Amount)
	}
	if selected.Amount != "1000" {
		t.Fatalf("expected amount 1000, got %s", selected.Amount)
	}
	if resource["uri"] != "/body" {
		t.Fatalf("expected body resource attribution, got %#v", resource)
	}
}
