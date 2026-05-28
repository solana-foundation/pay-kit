// Cross-language harness adapter for the Go PayKit umbrella server.
//
// One TCP server, two settle paths (x402:exact and mpp:charge), picked
// per scenario by which env namespace the harness orchestrator sets
// (or by the explicit PAY_KIT_INTEROP_PROTOCOL hint). Mirrors
// harness/lua-server/server.lua, harness/ruby-server/server.rb and
// harness/php-server/server.php.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/solana-foundation/pay-kit/go/paykit"
	_ "github.com/solana-foundation/pay-kit/go/paykit/schemes/mpp"
	_ "github.com/solana-foundation/pay-kit/go/paykit/schemes/x402"
	"github.com/solana-foundation/pay-kit/go/paykit/signer"
)

type readyMessage struct {
	Type           string `json:"type"`
	Implementation string `json:"implementation"`
	Role           string `json:"role"`
	Port           int    `json:"port"`
}

func main() {
	protocol := strings.ToLower(os.Getenv("PAY_KIT_INTEROP_PROTOCOL"))
	if protocol == "" {
		switch {
		case os.Getenv("X402_INTEROP_RPC_URL") != "":
			protocol = "x402"
		case os.Getenv("MPP_INTEROP_RPC_URL") != "":
			protocol = "mpp"
		default:
			log.Fatal("set exactly one of X402_INTEROP_RPC_URL / MPP_INTEROP_RPC_URL, or PAY_KIT_INTEROP_PROTOCOL")
		}
	}

	cfg := paykit.Config{
		Network: paykit.SolanaLocalnet,
	}
	// preflight: false for the harness; the harness preps surfpool.
	preflight := false
	cfg.Preflight = &preflight

	switch protocol {
	case "x402":
		rpcURL := requireEnv("X402_INTEROP_RPC_URL")
		payTo := requireEnv("X402_INTEROP_PAY_TO")
		facilitator := requireEnv("X402_INTEROP_FACILITATOR_SECRET_KEY")
		cfg.RPCURL = rpcURL
		cfg.Accept = []paykit.Scheme{paykit.X402}
		cfg.Operator = paykit.Operator{
			Recipient: paykit.Address(payTo),
			Signer:    signer.MustFromJSON(facilitator),
			FeePayer:  true,
		}
		cfg.MPP = paykit.MPPConfig{ChallengeBindingSecret: []byte("unused-x402")}
	case "mpp":
		rpcURL := requireEnv("MPP_INTEROP_RPC_URL")
		payTo := requireEnv("MPP_INTEROP_PAY_TO")
		secret := optionalEnv("MPP_INTEROP_SECRET_KEY", "pay-kit-interop-secret")
		feePayerKey := os.Getenv("MPP_INTEROP_FEE_PAYER_SECRET_KEY")
		cfg.RPCURL = rpcURL
		cfg.Accept = []paykit.Scheme{paykit.MPP}
		op := paykit.Operator{
			Recipient: paykit.Address(payTo),
			FeePayer:  feePayerKey != "",
		}
		if feePayerKey != "" {
			op.Signer = signer.MustFromJSON(feePayerKey)
		}
		cfg.Operator = op
		cfg.MPP = paykit.MPPConfig{
			Realm:                  "Harness",
			ChallengeBindingSecret: []byte(secret),
		}
	default:
		log.Fatalf("unknown protocol %q", protocol)
	}

	client, err := paykit.New(cfg)
	if err != nil {
		log.Fatalf("paykit.New: %v", err)
	}

	resourcePath := optionalEnv("X402_INTEROP_RESOURCE_PATH",
		optionalEnv("MPP_INTEROP_RESOURCE_PATH", "/paid"))
	amount := optionalEnv("X402_INTEROP_AMOUNT",
		optionalEnv("MPP_INTEROP_AMOUNT", "1000"))
	// Convert the integer-base-units amount the harness passes back
	// to a decimal USD figure (assume 6 decimals).
	amountUSD := convertUnitsToUSD(amount, 6)
	gate := paykit.Gate{
		Amount: paykit.MustParseUSD(amountUSD),
		Desc:   resourcePath,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.Handle(resourcePath, client.Require(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "paid": true, "protocol": protocol})
	})))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	if err := json.NewEncoder(os.Stdout).Encode(readyMessage{
		Type: "ready", Implementation: "go-paykit", Role: "server", Port: port,
	}); err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, mux))
}

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("missing required env: %s", name)
	}
	return v
}

func optionalEnv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// convertUnitsToUSD turns an integer-base-units amount into a decimal
// USD string given the stablecoin's decimals (USDC = 6).
func convertUnitsToUSD(amount string, decimals int) string {
	n, err := strconv.Atoi(amount)
	if err != nil {
		return amount
	}
	whole := n / pow10(decimals)
	frac := n % pow10(decimals)
	return fmt.Sprintf("%d.%0*d", whole, decimals, frac)
}

func pow10(n int) int {
	out := 1
	for i := 0; i < n; i++ {
		out *= 10
	}
	return out
}
