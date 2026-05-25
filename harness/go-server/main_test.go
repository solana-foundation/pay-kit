package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	t.Setenv("MPP_INTEROP_FEE_PAYER_SECRET_KEY", string(raw))

	got, err := readPrivateKeyEnv("MPP_INTEROP_FEE_PAYER_SECRET_KEY")
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if got.PublicKey() != privateKey.PublicKey() {
		t.Fatalf("expected public key %s, got %s", privateKey.PublicKey(), got.PublicKey())
	}
}

func TestReadPrivateKeyEnvRejectsInvalidLength(t *testing.T) {
	t.Setenv("MPP_INTEROP_FEE_PAYER_SECRET_KEY", "[1,2,3]")

	if _, err := readPrivateKeyEnv("MPP_INTEROP_FEE_PAYER_SECRET_KEY"); err == nil {
		t.Fatal("expected invalid private key length to fail")
	}
}

func TestReadEnvironmentAppliesDefaults(t *testing.T) {
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
	t.Setenv("MPP_INTEROP_RPC_URL", "http://127.0.0.1:8899")
	t.Setenv("MPP_INTEROP_PAY_TO", "pay-to")
	t.Setenv("MPP_INTEROP_FEE_PAYER_SECRET_KEY", string(raw))

	env, err := readEnvironment()
	if err != nil {
		t.Fatalf("read interop env: %v", err)
	}
	if env.Network != "localnet" {
		t.Fatalf("expected default network, got %q", env.Network)
	}
	if env.Mint != "USDC" {
		t.Fatalf("expected default mint, got %q", env.Mint)
	}
	if env.Price != "0.001" {
		t.Fatalf("expected default price, got %q", env.Price)
	}
	if env.ResourcePath != "/protected" {
		t.Fatalf("expected default resource path, got %q", env.ResourcePath)
	}
	if env.SettlementHeader != "x-fixture-settlement" {
		t.Fatalf("expected default settlement header, got %q", env.SettlementHeader)
	}
}

func TestReadEnvironmentParsesReplaySource(t *testing.T) {
	privateKey, _ := solana.NewRandomPrivateKey()
	values := make([]int, len(privateKey))
	for i, value := range []byte(privateKey) {
		values[i] = int(value)
	}
	raw, _ := json.Marshal(values)
	t.Setenv("MPP_INTEROP_RPC_URL", "http://127.0.0.1:8899")
	t.Setenv("MPP_INTEROP_PAY_TO", "pay-to")
	t.Setenv("MPP_INTEROP_FEE_PAYER_SECRET_KEY", string(raw))
	t.Setenv("MPP_INTEROP_REPLAY_SOURCE_PATH", "/replay")
	t.Setenv("MPP_INTEROP_REPLAY_SOURCE_PRICE", "0.002")

	env, err := readEnvironment()
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	if env.ReplaySource == nil || env.ReplaySource.ResourcePath != "/replay" || env.ReplaySource.Price != "0.002" {
		t.Fatalf("unexpected replay source: %#v", env.ReplaySource)
	}
}

func TestReadSplitsParsesJSON(t *testing.T) {
	t.Setenv("MPP_INTEROP_SPLITS", `[{"recipient":"r","amount":"10","memo":"m"}]`)
	splits, err := readSplits()
	if err != nil {
		t.Fatalf("read splits: %v", err)
	}
	if len(splits) != 1 || splits[0].Recipient != "r" || splits[0].Amount != "10" || splits[0].Memo != "m" {
		t.Fatalf("unexpected splits: %#v", splits)
	}
}

func TestReadSplitsRejectsInvalidJSON(t *testing.T) {
	t.Setenv("MPP_INTEROP_SPLITS", "not-json")
	if _, err := readSplits(); err == nil {
		t.Fatal("expected invalid splits json to fail")
	}
}

func TestWriteJSONSetsStatusAndContentType(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusAccepted, map[string]bool{"ok": true})

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", recorder.Code)
	}
	if recorder.Header().Get("content-type") != "application/json" {
		t.Fatalf("expected JSON content type")
	}
	if recorder.Body.String() != "{\"ok\":true}\n" {
		t.Fatalf("unexpected body %q", recorder.Body.String())
	}
}

func TestPriceForPathFallsBackToDefault(t *testing.T) {
	env := interopEnvironment{Price: "0.005"}
	if got := priceForPath("/anything", env); got != "0.005" {
		t.Fatalf("expected default price, got %q", got)
	}
}

func TestPriceForPathUsesReplaySource(t *testing.T) {
	env := interopEnvironment{
		Price:        "0.001",
		ReplaySource: &replaySource{Price: "0.002", ResourcePath: "/replay"},
	}
	if got := priceForPath("/replay", env); got != "0.002" {
		t.Fatalf("expected replay price, got %q", got)
	}
}
