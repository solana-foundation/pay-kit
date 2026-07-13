package main

import (
	"encoding/json"
	"testing"

	solana "github.com/solana-foundation/solana-go/v2"
)

func TestPrivateKeyFromJSONRejectsMismatchedSeedAndPublicKey(t *testing.T) {
	privateKey, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("new private key: %v", err)
	}
	invalid := append([]byte(nil), privateKey...)
	invalid[len(invalid)-1] ^= 0xff
	raw, err := json.Marshal(invalid)
	if err != nil {
		t.Fatalf("marshal invalid private key: %v", err)
	}

	if _, err := privateKeyFromJSON(string(raw)); err == nil {
		t.Fatal("expected mismatched seed/public key to fail as configuration")
	}
}
