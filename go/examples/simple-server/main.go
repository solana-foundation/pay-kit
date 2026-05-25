// Package main runs a minimal MPP charge server using only net/http.
//
// It mirrors the Ruby simple-server example shape: read env vars,
// construct an mpp/server handler with the Solana charge method,
// expose /health (free) and /paid (gated), and render the
// Challenge / Settlement tagged union by hand with a switch.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	solana "github.com/gagliardetto/solana-go"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/errorcodes"
	"github.com/solana-foundation/pay-kit/go/protocol/intents"
	"github.com/solana-foundation/pay-kit/go/server"
)

const (
	defaultRPCURL          = "https://402.surfnet.dev:8899"
	defaultCurrency        = "USDC"
	defaultNetwork         = "localnet"
	defaultPayTo           = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
	defaultSecretKey       = "go-mpp-dev-secret"
	defaultRealm           = "Go MPP Example"
	defaultPort            = 4572
	defaultAmount          = "0.001"
	defaultDescription     = "Go protected endpoint"
	settlementHeaderName   = "x-payment-settlement-signature"
	shutdownTimeoutSeconds = 5
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("simple-server: %v", err)
	}
}

func run() error {
	feePayer, err := loadFeePayerFromEnv()
	if err != nil {
		return fmt.Errorf("load fee payer: %w", err)
	}

	config := server.Config{
		Recipient: envOrDefault("MPP_PAY_TO", defaultPayTo),
		Currency:  envOrDefault("MPP_CURRENCY", defaultCurrency),
		Decimals:  6,
		Network:   envOrDefault("MPP_NETWORK", defaultNetwork),
		RPCURL:    envOrDefault("MPP_RPC_URL", defaultRPCURL),
		SecretKey: envOrDefault("MPP_SECRET_KEY", defaultSecretKey),
		Realm:     defaultRealm,
	}
	if feePayer != nil {
		// Assigning the typed nil through the interface field would
		// keep it non-nil at the interface level, so only set the
		// signer when an actual key was loaded.
		config.FeePayerSigner = feePayer
	}
	handler, err := server.New(config)
	if err != nil {
		return fmt.Errorf("server.New: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/paid", paidHandler(handler, feePayer != nil))

	port, err := portFromEnv()
	if err != nil {
		return err
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	httpServer := &http.Server{Addr: address, Handler: mux}

	errs := make(chan error, 1)
	go func() {
		log.Printf("simple-server: listening on http://%s", address)
		log.Printf("simple-server: try curl http://%s/paid then pay curl http://%s/paid", address, address)
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errs <- serveErr
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeoutSeconds*time.Second)
		defer cancel()
		return httpServer.Shutdown(ctx)
	case err := <-errs:
		return err
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// paidHandler mirrors the Ruby Mpp::Challenge / Mpp::Settlement switch
// using the Go SDK's lower-level Charge + VerifyCredential primitives.
// useServerFeePayer toggles the FeePayer charge option only when a
// fee-payer secret key was loaded; otherwise the client pays its own
// fees just like the Ruby example handles the nil fee payer branch.
func paidHandler(handler *server.Mpp, useServerFeePayer bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		challenge, err := handler.ChargeWithOptions(ctx, defaultAmount, server.ChargeOptions{
			Description: defaultDescription,
			FeePayer:    useServerFeePayer,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		authHeader := r.Header.Get(mpp.AuthorizationHeader)
		if authHeader == "" {
			writeChallenge(w, challenge, nil)
			return
		}

		credential, err := mpp.ParseAuthorization(authHeader)
		if err != nil {
			writeChallenge(w, challenge, mpp.WrapError(mpp.ErrCodeInvalidPayload, "parse authorization", err))
			return
		}

		var expected intents.ChargeRequest
		if decodeErr := challenge.Request.Decode(&expected); decodeErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
			return
		}

		receipt, err := handler.VerifyCredentialWithExpected(ctx, credential, expected)
		if err != nil {
			writeChallenge(w, challenge, err)
			return
		}

		writeSettlement(w, receipt)
	}
}

// writeChallenge renders the Mpp::Challenge branch: a 402 with the
// signed WWW-Authenticate header and the canonical L6 problem+json
// body shape shared across every MPP server SDK. The body carries the
// canonical `code`, a legacy `error` alias of the same code, a human
// `message`, plus `status`, `title`, and `type`.
//
// A missing credential or a verification failure both map to
// payment_invalid by default. Verification rejections that carry an
// SDK *Error promote to their canonical L6 code via
// errorcodes.CanonicalFromError (charge_request_mismatch,
// challenge_route_mismatch, challenge_verification_failed,
// challenge_expired, wrong_network, signature_consumed).
func writeChallenge(w http.ResponseWriter, challenge mpp.PaymentChallenge, verificationErr error) {
	wwwAuth, err := mpp.FormatWWWAuthenticate(challenge)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	code := errorcodes.PaymentInvalid
	message := "Payment required"
	if verificationErr != nil {
		code = errorcodes.CanonicalFromError(verificationErr)
		message = verificationErr.Error()
	}
	body := errorcodes.NewPaymentRequiredBody(code, message)
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("content-type", "application/problem+json")
	w.Header().Set(mpp.WWWAuthenticateHeader, wwwAuth)
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(body)
}

// writeSettlement renders the Mpp::Settlement branch: a 200 with the
// Payment-Receipt header plus the on-chain signature mirrored on
// x-payment-settlement-signature for parity with the Ruby example.
func writeSettlement(w http.ResponseWriter, receipt mpp.Receipt) {
	receiptHeader, err := mpp.FormatReceipt(receipt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set(mpp.PaymentReceiptHeader, receiptHeader)
	if receipt.Reference != "" {
		w.Header().Set(settlementHeaderName, receipt.Reference)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "paid": true})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// envOrDefault mirrors Ruby's ENV.fetch(name, fallback) shape: a
// missing env var resolves to fallback, an explicitly set empty env
// var is preserved as the empty string so misconfiguration fails fast
// downstream (server.New rejects empty required fields, strconv.Atoi
// rejects an empty PORT) instead of silently picking up a default.
func envOrDefault(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func portFromEnv() (int, error) {
	raw, ok := os.LookupEnv("PORT")
	if !ok {
		return defaultPort, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid PORT %q: %w", raw, err)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("PORT %d outside 1..65535", port)
	}
	return port, nil
}

// loadFeePayerFromEnv returns nil when MPP_FEE_PAYER_SECRET_KEY is
// absent or empty so the example runs in the same client-pays-its-own-
// fees mode the Ruby example uses when the env var is unset.
func loadFeePayerFromEnv() (solana.PrivateKey, error) {
	raw, ok := os.LookupEnv("MPP_FEE_PAYER_SECRET_KEY")
	if !ok || raw == "" {
		return nil, nil
	}
	var values []int
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("parse MPP_FEE_PAYER_SECRET_KEY: %w", err)
	}
	if len(values) != 64 {
		return nil, fmt.Errorf("MPP_FEE_PAYER_SECRET_KEY must contain 64 bytes, got %d", len(values))
	}
	key := make([]byte, 64)
	for i, value := range values {
		if value < 0 || value > 255 {
			return nil, fmt.Errorf("MPP_FEE_PAYER_SECRET_KEY byte %d outside 0..255", i)
		}
		key[i] = byte(value)
	}
	return solana.PrivateKey(key), nil
}
