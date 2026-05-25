package main

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	solana "github.com/gagliardetto/solana-go"
)

func TestReadPrivateKeyEnvParsesJSONByteArray(t *testing.T) {
	privateKey, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("new private key: %v", err)
	}
	values := make([]int, len(privateKey))
	for i, value := range []byte(privateKey) {
		values[i] = int(value)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	t.Setenv("MPP_INTEROP_CLIENT_SECRET_KEY", string(raw))

	got, err := readPrivateKeyEnv("MPP_INTEROP_CLIENT_SECRET_KEY")
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if got.PublicKey() != privateKey.PublicKey() {
		t.Fatalf("expected public key %s, got %s", privateKey.PublicKey(), got.PublicKey())
	}
}

func TestReadPrivateKeyEnvRejectsInvalidLength(t *testing.T) {
	t.Setenv("MPP_INTEROP_CLIENT_SECRET_KEY", "[1,2,3]")

	_, err := readPrivateKeyEnv("MPP_INTEROP_CLIENT_SECRET_KEY")
	if err == nil {
		t.Fatal("expected invalid private key length to fail")
	}
}

func TestResponseHeadersLowercaseAndJoinValues(t *testing.T) {
	headers := http.Header{}
	headers.Add("X-Fixture-Settlement", "abc")
	headers.Add("Vary", "Authorization")
	headers.Add("Vary", "Accept")

	got := responseHeaders(headers)
	if got[fixtureSettlementHeader] != "abc" {
		t.Fatalf("expected settlement header, got %#v", got)
	}
	if got["vary"] != "Authorization, Accept" {
		t.Fatalf("expected joined vary header, got %q", got["vary"])
	}
}

func TestParseResponseBodyKeepsJSONObjects(t *testing.T) {
	body := parseResponseBody([]byte(`{"ok":true,"paid":true}`))
	object, ok := body.(map[string]any)
	if !ok {
		t.Fatalf("expected JSON object, got %T", body)
	}
	if object["ok"] != true || object["paid"] != true {
		t.Fatalf("unexpected response body: %#v", object)
	}
}

func TestParseResponseBodyKeepsPlainText(t *testing.T) {
	body := parseResponseBody([]byte("paid"))
	if body != "paid" {
		t.Fatalf("expected plain body, got %#v", body)
	}
}

func TestRunProcessAdapterRequiresRPCURL(t *testing.T) {
	t.Setenv("MPP_INTEROP_TARGET_URL", "http://127.0.0.1/protected")

	if err := runProcessAdapter(io.Discard); err == nil {
		t.Fatal("expected missing RPC URL to fail")
	}
}
