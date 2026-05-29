// Package signer provides local, in-process Ed25519 signer factories
// that satisfy [paykit.Signer]. Remote-enclave (KMS) backends are future work, not part of v1.
//
// Every constructor returns a [paykit.Signer] and (for the fallible
// ones) a non-nil [*InvalidKeyError] on parse failure. The Must*
// variants panic on error for boot-time var-block use.
package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paykit"
)

// InvalidKeyError is returned by the fallible factories when the input
// cannot be parsed into a 64-byte Ed25519 secret key.
type InvalidKeyError struct {
	Source string
	Reason string
}

func (e *InvalidKeyError) Error() string {
	return fmt.Sprintf("signer: invalid %s: %s", e.Source, e.Reason)
}

// localSigner is the concrete value behind every local factory.
type localSigner struct {
	priv   ed25519.PrivateKey
	pub    paykit.Address
	isDemo bool
}

func (s *localSigner) Pubkey() paykit.Address { return s.pub }
func (s *localSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}
func (s *localSigner) IsDemo() bool { return s.isDemo }

// demoSecret is the 64-byte secret of the package-shipped demo
// keypair, identical to Ruby's PayKit::Signer::Demo and PHP's
// PayKit\Signer\Demo. Pubkey: ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq.
var demoSecret = func() []byte {
	raw, _ := hex.DecodeString(
		"1a3d75c009e81833598769b62f0953f40bd655aae353aa1a37813a7259a0c333" +
			"8ad17f233629caa6c7a661eeb53ffeb92d10ae66fac61ebfe8ec93a729b2971a",
	)
	return raw
}()

// Demo returns the package-shipped demo keypair. paykit.New emits a
// slog.Warn whenever the demo signer is in use, and returns
// paykit.ErrDemoSignerOnMainnet when combined with SolanaMainnet.
func Demo() paykit.Signer {
	priv := ed25519.PrivateKey(demoSecret)
	return &localSigner{priv: priv, pub: pubkeyOf(priv), isDemo: true}
}

// Generate produces a fresh ephemeral keypair. Test-only; production
// callers load from a file or env so the same identity survives
// restarts.
func Generate() paykit.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &localSigner{priv: priv, pub: pubkeyOf(priv)}
}

// FromBytes wraps a 64-byte raw secret key.
func FromBytes(b []byte) (paykit.Signer, error) {
	if len(b) != ed25519.PrivateKeySize {
		return nil, &InvalidKeyError{
			Source: "bytes",
			Reason: fmt.Sprintf("expected %d bytes, got %d", ed25519.PrivateKeySize, len(b)),
		}
	}
	priv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(priv, b)
	return &localSigner{priv: priv, pub: pubkeyOf(priv)}, nil
}

// MustFromBytes panics on a wrong-length input.
func MustFromBytes(b []byte) paykit.Signer { return mustSigner(FromBytes(b)) }

// FromJSON parses the Solana-CLI keypair JSON array shape
// (`[1,2,...,64]`).
func FromJSON(raw string) (paykit.Signer, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, &InvalidKeyError{Source: "json", Reason: "empty input"}
	}
	var ints []int
	if err := json.Unmarshal([]byte(trimmed), &ints); err != nil {
		return nil, &InvalidKeyError{Source: "json", Reason: err.Error()}
	}
	b := make([]byte, len(ints))
	for i, v := range ints {
		if v < 0 || v > 255 {
			return nil, &InvalidKeyError{Source: "json", Reason: fmt.Sprintf("byte %d out of range: %d", i, v)}
		}
		b[i] = byte(v)
	}
	return FromBytes(b)
}

// MustFromJSON panics on a malformed array.
func MustFromJSON(raw string) paykit.Signer { return mustSigner(FromJSON(raw)) }

// FromHex parses a 128-character hex string (64 bytes encoded).
func FromHex(raw string) (paykit.Signer, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) != ed25519.PrivateKeySize*2 {
		return nil, &InvalidKeyError{
			Source: "hex",
			Reason: fmt.Sprintf("expected %d hex chars, got %d", ed25519.PrivateKeySize*2, len(trimmed)),
		}
	}
	b, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, &InvalidKeyError{Source: "hex", Reason: err.Error()}
	}
	return FromBytes(b)
}

// MustFromHex panics on a malformed hex string.
func MustFromHex(raw string) paykit.Signer { return mustSigner(FromHex(raw)) }

// FromBase58 parses a Phantom / Solflare export string.
func FromBase58(raw string) (paykit.Signer, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, &InvalidKeyError{Source: "base58", Reason: "empty input"}
	}
	pk, err := solana.PrivateKeyFromBase58(trimmed)
	if err != nil {
		return nil, &InvalidKeyError{Source: "base58", Reason: err.Error()}
	}
	return FromBytes(pk[:])
}

// MustFromBase58 panics on a malformed base58 string.
func MustFromBase58(raw string) paykit.Signer { return mustSigner(FromBase58(raw)) }

// FromFile reads the path (Solana-CLI JSON-array format) and parses it.
func FromFile(path string) (paykit.Signer, error) {
	if path == "" {
		return nil, &InvalidKeyError{Source: "file", Reason: "empty path"}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &InvalidKeyError{Source: "file", Reason: err.Error()}
	}
	return FromJSON(string(raw))
}

// MustFromFile panics on missing / malformed files.
func MustFromFile(path string) paykit.Signer { return mustSigner(FromFile(path)) }

// FromEnv reads an env var and auto-detects the encoding (JSON, hex, or
// base58). Returns (nil, nil) when the var is unset or empty so it
// composes cleanly with Operator zero-value resolution:
//
//	cfg.Operator.Signer = signer.MustFromEnvOrDemo("PAY_KIT_OPERATOR_KEY")
//
// A var that IS set but malformed returns (nil, *InvalidKeyError); a
// silent fallback to demo would mask a real bug.
func FromEnv(name string) (paykit.Signer, error) {
	if name == "" {
		return nil, &InvalidKeyError{Source: "env", Reason: "empty var name"}
	}
	raw, ok := os.LookupEnv(name)
	if !ok {
		return nil, nil
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	switch {
	case strings.HasPrefix(trimmed, "["):
		return FromJSON(trimmed)
	case len(trimmed) == ed25519.PrivateKeySize*2 && isHex(trimmed):
		return FromHex(trimmed)
	default:
		return FromBase58(trimmed)
	}
}

// MustFromEnvOrDemo returns the env-resolved signer when set, the demo
// signer when unset, and panics on a malformed env value.
func MustFromEnvOrDemo(name string) paykit.Signer {
	s, err := FromEnv(name)
	if err != nil {
		panic(err)
	}
	if s == nil {
		return Demo()
	}
	return s
}

func mustSigner(s paykit.Signer, err error) paykit.Signer {
	if err != nil {
		var ike *InvalidKeyError
		if errors.As(err, &ike) {
			panic(ike)
		}
		panic(err)
	}
	return s
}

func pubkeyOf(priv ed25519.PrivateKey) paykit.Address {
	pub := priv.Public().(ed25519.PublicKey)
	var arr [32]byte
	copy(arr[:], pub)
	return paykit.Address(solana.PublicKey(arr).String())
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func init() { paykit.DefaultSigner = Demo }
