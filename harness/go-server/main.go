// Cross-language harness adapter for the Go PayKit umbrella server.
//
// One TCP server, two settle paths (x402:exact and mpp:charge), picked
// per scenario by which env namespace the harness orchestrator sets
// (or by the explicit PAY_KIT_HARNESS_PROTOCOL hint). Mirrors
// harness/lua-server/server.lua, harness/ruby-server/server.rb and
// harness/php-server/server.php.
//
// The x402 path routes through paykit.Client.Require so the umbrella
// adapter is the load-bearing surface under test. The MPP path
// bypasses the umbrella and uses the legacy server.Mpp +
// server.PaymentMiddleware directly so the harness can inject
// scenario-specific splits, payment modes, and replay-source routes
// the way the PHP server does (the umbrella's Gate cannot carry the
// raw methodDetails the harness needs to mutate).
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

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	_ "github.com/solana-foundation/pay-kit/go/paykit/adapters/mpp"
	_ "github.com/solana-foundation/pay-kit/go/paykit/adapters/x402"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/errorcodes"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/server"
)

type readyMessage struct {
	Type           string `json:"type"`
	Implementation string `json:"implementation"`
	Role           string `json:"role"`
	Port           int    `json:"port"`
}

func main() {
	protocolMode := strings.ToLower(os.Getenv("PAY_KIT_HARNESS_PROTOCOL"))
	if protocolMode == "" {
		switch {
		case os.Getenv("X402_HARNESS_RPC_URL") != "":
			protocolMode = "x402"
		case os.Getenv("MPP_HARNESS_RPC_URL") != "":
			protocolMode = "mpp"
		default:
			log.Fatal("set exactly one of X402_HARNESS_RPC_URL / MPP_HARNESS_RPC_URL, or PAY_KIT_HARNESS_PROTOCOL")
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	resourcePath := optionalEnv("X402_HARNESS_RESOURCE_PATH",
		optionalEnv("MPP_HARNESS_RESOURCE_PATH", "/paid"))
	settlementHeader := optionalEnv("X402_HARNESS_SETTLEMENT_HEADER",
		optionalEnv("MPP_HARNESS_SETTLEMENT_HEADER", "x-payment-settlement-signature"))

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	switch protocolMode {
	case "x402-upto":
		mountX402Upto(mux, resourcePath)
	case "x402":
		mountX402(mux, resourcePath, settlementHeader)
	case "mpp":
		mountMPP(mux, resourcePath, settlementHeader)
	default:
		log.Fatalf("unknown protocol %q", protocolMode)
	}

	if err := json.NewEncoder(os.Stdout).Encode(readyMessage{
		Type: "ready", Implementation: "go-paykit", Role: "server", Port: port,
	}); err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, mux))
}

func mountX402(mux *http.ServeMux, resourcePath, settlementHeader string) {
	rpcURL := requireEnv("X402_HARNESS_RPC_URL")
	payTo := requireEnv("X402_HARNESS_PAY_TO")
	feePayer := optionalEnv("X402_HARNESS_FEE_PAYER_SECRET_KEY", "")
	if feePayer == "" {
		feePayer = requireEnv("X402_HARNESS_FACILITATOR_SECRET_KEY")
	}
	amount := optionalEnv("X402_HARNESS_AMOUNT", "1000")
	// The harness funds the scenario's mint (X402_HARNESS_MINT) and the
	// client pays in whatever mint the challenge advertises, so the gate
	// must settle in that exact mint, not the USDC default (which resolves
	// to the mainnet mint the fixtures never funded).
	mint := optionalEnv("X402_HARNESS_MINT", "")

	preflight := false
	cfg := paykit.Config{
		Network:   paykit.SolanaLocalnet,
		Preflight: &preflight,
		RPCURL:    rpcURL,
		Accept:    []paykit.Protocol{paykit.X402},
		Operator: paykit.Operator{
			Recipient: paykit.Address(payTo),
			Signer:    signer.MustFromJSON(feePayer),
			FeePayer:  true,
		},
		MPP: paykit.MPPConfig{ChallengeBindingSecret: []byte("unused-x402")},
	}
	client, err := paykit.New(cfg)
	if err != nil {
		log.Fatalf("paykit.New: %v", err)
	}

	amountUSD := convertUnitsToUSD(amount, 6)
	price := paykit.MustParseUSD(amountUSD)
	if mint != "" {
		price = paykit.MustParseUSD(amountUSD, paykit.Stablecoin(mint))
	}
	gate := paykit.Gate{Amount: price, Desc: resourcePath}

	mux.Handle(resourcePath, client.Require(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pmt, ok := paykit.PaymentFrom(r.Context()); ok {
			w.Header().Set(settlementHeader, pmt.Transaction)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "paid": true, "protocol": "x402"})
	})))
}

func mountX402Upto(mux *http.ServeMux, resourcePath string) {
	rpcURL := requireEnv("X402_HARNESS_RPC_URL")
	payTo := requireEnv("X402_HARNESS_PAY_TO")
	facilitator := requireEnv("X402_HARNESS_FACILITATOR_SECRET_KEY")
	price := optionalEnv("X402_HARNESS_PRICE", "0.10")
	mint := requireEnv("X402_HARNESS_MINT")

	preflight := false
	cfg := paykit.Config{
		Network:     paykit.SolanaLocalnet,
		Preflight:   &preflight,
		RPCURL:      rpcURL,
		Accept:      []paykit.Protocol{paykit.X402},
		Stablecoins: []paykit.Stablecoin{paykit.Stablecoin(mint)},
		Operator: paykit.Operator{
			Recipient: paykit.Address(payTo),
			Signer:    signer.MustFromJSON(facilitator),
			FeePayer:  true,
		},
		X402: paykit.X402Config{
			Scheme:         "upto",
			ChannelProgram: os.Getenv("PAYMENT_CHANNELS_PROGRAM_ID"),
		},
		MPP: paykit.MPPConfig{ChallengeBindingSecret: []byte("unused-x402-upto")},
	}
	client, err := paykit.New(cfg)
	if err != nil {
		log.Fatalf("paykit.New: %v", err)
	}
	gate := paykit.Gate{
		Amount: paykit.MustParseUSD(price, paykit.Stablecoin(mint)),
		Desc:   resourcePath,
		Kind:   paykit.GateUsage,
		Accept: []paykit.Protocol{paykit.X402},
	}
	mux.Handle(resourcePath, client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := paykit.ChargeFrom(r.Context())
		if !ok || c == nil {
			http.Error(w, "missing usage meter", http.StatusInternalServerError)
			return
		}
		actual := optionalEnv("X402_HARNESS_ACTUAL_AMOUNT", "0")
		if headerActual := r.Header.Get("X402-HARNESS-ACTUAL-AMOUNT"); headerActual != "" {
			actual = headerActual
		}
		actualUnits, err := strconv.ParseUint(actual, 10, 64)
		if err != nil {
			http.Error(w, "invalid actual amount", http.StatusInternalServerError)
			return
		}
		c.Charge(actualUnits)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "paid": true, "protocol": "x402-upto"})
	})))
}

func mountMPP(mux *http.ServeMux, resourcePath, settlementHeader string) {
	rpcURL := requireEnv("MPP_HARNESS_RPC_URL")
	payTo := requireEnv("MPP_HARNESS_PAY_TO")
	mint := requireEnv("MPP_HARNESS_MINT")
	price := optionalEnv("MPP_HARNESS_PRICE", "0.001")
	mppSecret := optionalEnv("MPP_HARNESS_SECRET_KEY", "pay-kit-harness-secret")
	network := optionalEnv("MPP_HARNESS_NETWORK", "localnet")
	paymentMode := optionalEnv("MPP_HARNESS_PAYMENT_MODE", "pull")
	replayPath := os.Getenv("MPP_HARNESS_REPLAY_SOURCE_PATH")
	replayAmount := os.Getenv("MPP_HARNESS_REPLAY_SOURCE_AMOUNT")
	feePayerJSON := requireEnv("MPP_HARNESS_FEE_PAYER_SECRET_KEY")
	splitsJSON := optionalEnv("MPP_HARNESS_SPLITS", "[]")

	feePayer := privateKeyFromJSON(feePayerJSON)
	rpcClient := rpc.New(rpcURL)

	srv, err := server.New(server.Config{
		Recipient:      payTo,
		Currency:       mint,
		Decimals:       6,
		Network:        network,
		RPCURL:         rpcURL,
		SecretKey:      mppSecret,
		Realm:          "go-paykit",
		FeePayerSigner: walletSignerFor(feePayer),
		RPC:            rpcClient,
	})
	if err != nil {
		log.Fatalf("server.New: %v", err)
	}

	splits := []paycore.Split{}
	_ = json.Unmarshal([]byte(splitsJSON), &splits)

	// Manual flow mirrors harness/go-server/main.go.serveProtected:
	// build challenge per request so VerifyCredentialWithExpected
	// pins the credential against the route's live expected request
	// (needed for cross-route replay rejection). Bypass
	// server.PaymentMiddleware so the harness sees the same shape
	// the existing Go harness server emits.
	handle := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "not_found", http.StatusNotFound)
			return
		}
		path := r.URL.Path
		amt := price
		if replayPath != "" && path == replayPath && replayAmount != "" {
			amt = optionalEnv("MPP_HARNESS_REPLAY_SOURCE_PRICE", amt)
		}
		opts := server.ChargeOptions{
			Description: "Go PayKit harness " + path,
			FeePayer:    paymentMode != "push",
			Splits:      splits,
		}
		auth := r.Header.Get(core.AuthorizationHeader)
		if auth == "" {
			challenge, err := srv.ChargeWithOptions(r.Context(), amt, opts)
			if err != nil {
				if isIssuanceConfigError(err) {
					writeMPP402ConfigError(w, err)
				} else {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}
			writeMPP402(w, challenge, nil)
			return
		}
		challenge, err := srv.ChargeWithOptions(r.Context(), amt, opts)
		if err != nil {
			if isIssuanceConfigError(err) {
				writeMPP402ConfigError(w, err)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		credential, err := core.ParseAuthorization(auth)
		if err != nil {
			writeMPP402(w, challenge, err)
			return
		}
		var expected core.ChargeRequest
		if err := challenge.Request.Decode(&expected); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		receipt, err := srv.VerifyCredentialWithExpected(r.Context(), credential, expected)
		if err != nil {
			writeMPP402(w, challenge, err)
			return
		}
		receiptHeader, _ := core.FormatReceipt(receipt)
		w.Header().Set("Content-Type", "application/json")
		if receiptHeader != "" {
			w.Header().Set(core.PaymentReceiptHeader, receiptHeader)
		}
		w.Header().Set(settlementHeader, receipt.Reference)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"paid":true,"protocol":"mpp"}`))
	}
	mux.HandleFunc(resourcePath, handle)
	if replayPath != "" && replayPath != resourcePath {
		mux.HandleFunc(replayPath, handle)
	}
}

func privateKeyFromJSON(raw string) solana.PrivateKey {
	var ints []int
	if err := json.Unmarshal([]byte(raw), &ints); err != nil {
		log.Fatalf("MPP_HARNESS_FEE_PAYER_SECRET_KEY decode: %v", err)
	}
	b := make([]byte, len(ints))
	for i, v := range ints {
		b[i] = byte(v)
	}
	pk := solana.PrivateKey(b)
	return pk
}

// walletSignerFor adapts a solana.PrivateKey into the utils.Signer
// interface server.Config expects.
func walletSignerFor(pk solana.PrivateKey) walletSignerImpl {
	return walletSignerImpl{pk: pk}
}

type walletSignerImpl struct {
	pk solana.PrivateKey
}

func (w walletSignerImpl) PublicKey() solana.PublicKey {
	return w.pk.PublicKey()
}

func (w walletSignerImpl) Sign(payload []byte) (solana.Signature, error) {
	return w.pk.Sign(payload)
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

// isIssuanceConfigError reports whether a ChargeWithOptions failure is a
// challenge-issuance config rejection that the conformance harness expects to
// surface as a 402-class outcome rather than a 500. Audit #21 promoted
// too-many-splits from a verify-time reject to a refuse-to-issue, so the
// harness now expects 402 here (see canonical-codes.ts `/too many splits/i`).
func isIssuanceConfigError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "too many splits")
}

// writeMPP402ConfigError surfaces an issuance config rejection (no challenge to
// advertise) as the 402 the harness expects.
func writeMPP402ConfigError(w http.ResponseWriter, issueErr error) {
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("content-type", "application/problem+json")
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(errorcodes.NewPaymentRequiredBody(
		errorcodes.CanonicalFromError(issueErr), issueErr.Error()))
}

// writeMPP402 emits the canonical L6 problem+json body shared across
// every MPP server SDK. The verifier error is mapped to its canonical
// code via errorcodes.CanonicalFromError so the cross-SDK fault matrix
// (G39 / caveat #7) sees the same code from Go as from TS/Rust/Ruby
// (e.g. wrong_network, charge_request_mismatch).
func writeMPP402(w http.ResponseWriter, challenge core.PaymentChallenge, verifyErr error) {
	header, err := core.FormatWWWAuthenticate(challenge)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	code := errorcodes.PaymentInvalid
	message := "Payment is required (Go PayKit harness)."
	if verifyErr != nil {
		code = errorcodes.CanonicalFromError(verifyErr)
		message = verifyErr.Error()
	}
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("content-type", "application/problem+json")
	w.Header().Set(core.WWWAuthenticateHeader, header)
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(errorcodes.NewPaymentRequiredBody(code, message))
}
