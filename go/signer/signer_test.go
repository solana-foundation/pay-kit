package signer_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/solana-foundation/pay-kit/go/signer"
)

// testSecret returns a fresh valid 64-byte Ed25519 secret key as the
// source-of-truth for round-trip tests. The Signer interface no longer
// exposes SecretKey(), so tests carry the raw bytes themselves and
// feed each constructor the same secret in its native encoding.
func testSecret(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestDemoStable(t *testing.T) {
	a, b := signer.Demo(), signer.Demo()
	if a.Pubkey() != b.Pubkey() {
		t.Error("demo pubkey unstable")
	}
	if !a.IsDemo() {
		t.Error("demo flag false")
	}
}

func TestDemoMatchesCrossLangPubkey(t *testing.T) {
	want := "ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq"
	if string(signer.Demo().Pubkey()) != want {
		t.Errorf("demo pubkey: got %s want %s", signer.Demo().Pubkey(), want)
	}
}

func TestGenerateProducesValidSignature(t *testing.T) {
	s := signer.Generate()
	sig, err := s.Sign(context.Background(), []byte("hello"))
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Errorf("sign: len=%d err=%v", len(sig), err)
	}
	if s.IsDemo() {
		t.Error("generated signer should not be demo")
	}
}

func TestFromBytesRejectsWrongLength(t *testing.T) {
	if _, err := signer.FromBytes(make([]byte, 32)); err == nil {
		t.Error("expected wrong-length error")
	}
}

func TestFromBytesRoundTrip(t *testing.T) {
	sk := testSecret(t)
	ref, err := signer.FromBytes(sk)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := signer.FromBytes(sk)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Pubkey() != ref.Pubkey() {
		t.Errorf("pubkey: got %s want %s", rebuilt.Pubkey(), ref.Pubkey())
	}
}

func TestFromJSONRoundTrip(t *testing.T) {
	sk := testSecret(t)
	ref, err := signer.FromBytes(sk)
	if err != nil {
		t.Fatal(err)
	}
	arr := make([]int, len(sk))
	for i, b := range sk {
		arr[i] = int(b)
	}
	jsonStr, _ := json.Marshal(arr)
	rebuilt, err := signer.FromJSON(string(jsonStr))
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Pubkey() != ref.Pubkey() {
		t.Errorf("pubkey mismatch")
	}
}

func TestFromJSONRejectsEmpty(t *testing.T) {
	if _, err := signer.FromJSON(""); err == nil {
		t.Error("expected empty error")
	}
}

func TestFromJSONRejectsOutOfRangeByte(t *testing.T) {
	if _, err := signer.FromJSON("[1,2,999,4]"); err == nil {
		t.Error("expected range error")
	}
}

func TestFromHexRoundTrip(t *testing.T) {
	sk := testSecret(t)
	ref, err := signer.FromBytes(sk)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := signer.FromHex(hex.EncodeToString(sk))
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Pubkey() != ref.Pubkey() {
		t.Errorf("hex round-trip pubkey mismatch")
	}
}

func TestFromHexRejectsBadChars(t *testing.T) {
	// 128 chars but non-hex
	bad := make([]byte, 128)
	for i := range bad {
		bad[i] = 'z'
	}
	if _, err := signer.FromHex(string(bad)); err == nil {
		t.Error("expected hex decode error")
	}
}

func TestFromHexRejectsWrongLength(t *testing.T) {
	if _, err := signer.FromHex("abc"); err == nil {
		t.Error("expected length error")
	}
}

func TestFromBase58RejectsEmpty(t *testing.T) {
	if _, err := signer.FromBase58(""); err == nil {
		t.Error("expected empty error")
	}
}

func TestFromFileMissingPath(t *testing.T) {
	if _, err := signer.FromFile("/tmp/missing-paykit-signer-xyz.json"); err == nil {
		t.Error("expected missing-file error")
	}
}

func TestFromFileEmptyPath(t *testing.T) {
	if _, err := signer.FromFile(""); err == nil {
		t.Error("expected empty-path error")
	}
}

func TestFromFileRoundTrip(t *testing.T) {
	sk := testSecret(t)
	ref, err := signer.FromBytes(sk)
	if err != nil {
		t.Fatal(err)
	}
	arr := make([]int, len(sk))
	for i, b := range sk {
		arr[i] = int(b)
	}
	jsonStr, _ := json.Marshal(arr)
	dir := t.TempDir()
	path := filepath.Join(dir, "keypair.json")
	if err := os.WriteFile(path, jsonStr, 0o600); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := signer.FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Pubkey() != ref.Pubkey() {
		t.Errorf("file load pubkey mismatch")
	}
}

func TestFromEnvUnsetReturnsNil(t *testing.T) {
	const name = "PAY_KIT_TEST_UNSET_VARX"
	_ = os.Unsetenv(name)
	s, err := signer.FromEnv(name)
	if err != nil {
		t.Fatal(err)
	}
	if s != nil {
		t.Error("expected nil for unset")
	}
}

func TestFromEnvEmptyVarReturnsNil(t *testing.T) {
	const name = "PAY_KIT_TEST_EMPTY_VAR"
	t.Setenv(name, "   ")
	s, err := signer.FromEnv(name)
	if err != nil {
		t.Fatal(err)
	}
	if s != nil {
		t.Error("expected nil for whitespace")
	}
}

func TestFromEnvRejectsEmptyName(t *testing.T) {
	if _, err := signer.FromEnv(""); err == nil {
		t.Error("expected empty-name error")
	}
}

func TestFromEnvAutoDetectsJSON(t *testing.T) {
	sk := testSecret(t)
	ref, err := signer.FromBytes(sk)
	if err != nil {
		t.Fatal(err)
	}
	arr := make([]int, len(sk))
	for i, b := range sk {
		arr[i] = int(b)
	}
	jsonStr, _ := json.Marshal(arr)
	const name = "PAY_KIT_TEST_SIGNER_JSON"
	t.Setenv(name, string(jsonStr))
	rebuilt, err := signer.FromEnv(name)
	if err != nil || rebuilt == nil {
		t.Fatal(err)
	}
	if rebuilt.Pubkey() != ref.Pubkey() {
		t.Errorf("env JSON pubkey mismatch")
	}
}

func TestFromEnvAutoDetectsHex(t *testing.T) {
	sk := testSecret(t)
	ref, err := signer.FromBytes(sk)
	if err != nil {
		t.Fatal(err)
	}
	const name = "PAY_KIT_TEST_SIGNER_HEX"
	t.Setenv(name, hex.EncodeToString(sk))
	rebuilt, err := signer.FromEnv(name)
	if err != nil || rebuilt == nil {
		t.Fatal(err)
	}
	if rebuilt.Pubkey() != ref.Pubkey() {
		t.Errorf("env hex pubkey mismatch")
	}
}

func TestMustFromEnvOrDemoFallsBackToDemoWhenUnset(t *testing.T) {
	_ = os.Unsetenv("PAY_KIT_TEST_X_UNSET")
	s := signer.MustFromEnvOrDemo("PAY_KIT_TEST_X_UNSET")
	if !s.IsDemo() {
		t.Error("expected demo fallback")
	}
}

func TestMustFromEnvOrDemoPanicsOnMalformed(t *testing.T) {
	const name = "PAY_KIT_TEST_X_BAD"
	t.Setenv(name, "this-is-not-valid-anything-format")
	defer func() {
		if recover() == nil {
			t.Error("expected panic on malformed env")
		}
	}()
	_ = signer.MustFromEnvOrDemo(name)
}

func TestMustFromBytesPanicsOnWrongLength(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	_ = signer.MustFromBytes([]byte{1, 2, 3})
}

func TestMustFromJSONPanicsOnEmpty(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	_ = signer.MustFromJSON("")
}

func TestMustFromHexPanicsOnWrongLength(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	_ = signer.MustFromHex("abc")
}

func TestMustFromBase58PanicsOnEmpty(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	_ = signer.MustFromBase58("")
}

func TestMustFromFilePanicsOnMissing(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	_ = signer.MustFromFile("/tmp/definitely-missing-xyz.json")
}

func TestInvalidKeyErrorString(t *testing.T) {
	e := &signer.InvalidKeyError{Source: "hex", Reason: "too short"}
	if got := e.Error(); got == "" || !contains(got, "hex") || !contains(got, "too short") {
		t.Errorf("InvalidKeyError.Error() = %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
