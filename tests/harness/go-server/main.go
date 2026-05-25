package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	solana "github.com/gagliardetto/solana-go"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/errorcodes"
	"github.com/solana-foundation/pay-kit/go/protocol"
	"github.com/solana-foundation/pay-kit/go/protocol/intents"
	mppserver "github.com/solana-foundation/pay-kit/go/server"
)

type interopEnvironment struct {
	RPCURL           string
	Network          string
	Mint             string
	Price            string
	ResourcePath     string
	ReplaySource     *replaySource
	SettlementHeader string
	PayTo            string
	SecretKey        string
	Splits           []protocol.Split
	FeePayerSecret   solana.PrivateKey
}

type replaySource struct {
	Price        string
	ResourcePath string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	environment, err := readEnvironment()
	if err != nil {
		return err
	}
	handler, err := mppserver.New(mppserver.Config{
		Recipient:      environment.PayTo,
		Currency:       environment.Mint,
		Decimals:       6,
		Network:        environment.Network,
		RPCURL:         environment.RPCURL,
		SecretKey:      environment.SecretKey,
		Realm:          "MPP Interop",
		FeePayerSigner: environment.FeePayerSecret,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		serveProtected(response, request, environment, handler)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("unexpected listener address %s", listener.Addr())
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"type":           "ready",
		"implementation": "go",
		"role":           "server",
		"port":           tcpAddr.Port,
		"capabilities":   []string{"charge"},
	}); err != nil {
		return err
	}

	server := &http.Server{Handler: mux}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stopCh)

	select {
	case <-stopCh:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func serveProtected(
	response http.ResponseWriter,
	request *http.Request,
	environment interopEnvironment,
	handler *mppserver.Mpp,
) {
	if request.Method != http.MethodGet || !isProtectedPath(request.URL.Path, environment) {
		writeJSON(response, http.StatusNotFound, map[string]any{"error": "not_found"})
		return
	}

	price := priceForPath(request.URL.Path, environment)
	options := mppserver.ChargeOptions{
		Description: "Go interop protected content",
		FeePayer:    true,
		Splits:      environment.Splits,
	}

	// Inspect Authorization before building any challenge so the
	// unauthenticated 402 branch is the only path that pays the
	// getLatestBlockhash RPC round-trip when the caller never intends
	// to pay. Authenticated requests still build a fresh challenge so
	// VerifyCredentialWithExpected pins the credential against the
	// route's live expected request (this is what enforces the
	// cross-route replay rejection; the credential's own echo cannot
	// be trusted for that pin).
	authorization := request.Header.Get(mpp.AuthorizationHeader)
	if authorization == "" {
		challenge, err := handler.ChargeWithOptions(request.Context(), price, options)
		if err != nil {
			writeJSON(response, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writePaymentRequired(response, challenge, nil)
		return
	}

	challenge, err := handler.ChargeWithOptions(request.Context(), price, options)
	if err != nil {
		writeJSON(response, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	credential, err := mpp.ParseAuthorization(authorization)
	if err != nil {
		writePaymentRequired(response, challenge, mpp.WrapError(mpp.ErrCodeInvalidPayload, "parse authorization", err))
		return
	}
	var expected intents.ChargeRequest
	if err := challenge.Request.Decode(&expected); err != nil {
		writeJSON(response, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	receipt, err := handler.VerifyCredentialWithExpected(request.Context(), credential, expected)
	if err != nil {
		writePaymentRequired(response, challenge, err)
		return
	}
	receiptHeader, err := mpp.FormatReceipt(receipt)
	if err != nil {
		writeJSON(response, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	response.Header().Set("content-type", "application/json")
	response.Header().Set(mpp.PaymentReceiptHeader, receiptHeader)
	response.Header().Set(environment.SettlementHeader, receipt.Reference)
	response.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(response, `{"ok":true,"paid":true}`)
}

// writePaymentRequired emits the canonical L6 problem+json body shared
// across every MPP server SDK. A nil verificationErr means "no
// credential was supplied"; the body carries the payment_invalid code
// in that case. A non-nil verificationErr promotes to its canonical L6
// code via errorcodes.CanonicalFromError.
func writePaymentRequired(response http.ResponseWriter, challenge mpp.PaymentChallenge, verificationErr error) {
	header, err := mpp.FormatWWWAuthenticate(challenge)
	if err != nil {
		writeJSON(response, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	code := errorcodes.PaymentInvalid
	message := "Payment is required (Go interop server)."
	if verificationErr != nil {
		code = errorcodes.CanonicalFromError(verificationErr)
		message = verificationErr.Error()
	}
	body := errorcodes.NewPaymentRequiredBody(code, message)
	response.Header().Set("cache-control", "no-store")
	response.Header().Set("content-type", "application/problem+json")
	response.Header().Set(mpp.WWWAuthenticateHeader, header)
	response.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(response).Encode(body)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("content-type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func isProtectedPath(path string, environment interopEnvironment) bool {
	return path == environment.ResourcePath ||
		(environment.ReplaySource != nil && path == environment.ReplaySource.ResourcePath)
}

func priceForPath(path string, environment interopEnvironment) string {
	if environment.ReplaySource != nil && path == environment.ReplaySource.ResourcePath {
		return environment.ReplaySource.Price
	}
	return environment.Price
}

func readEnvironment() (interopEnvironment, error) {
	feePayer, err := readPrivateKeyEnv("MPP_INTEROP_FEE_PAYER_SECRET_KEY")
	if err != nil {
		return interopEnvironment{}, err
	}
	splits, err := readSplits()
	if err != nil {
		return interopEnvironment{}, err
	}
	rpcURL, err := requiredEnv("MPP_INTEROP_RPC_URL")
	if err != nil {
		return interopEnvironment{}, err
	}
	payTo, err := requiredEnv("MPP_INTEROP_PAY_TO")
	if err != nil {
		return interopEnvironment{}, err
	}
	environment := interopEnvironment{
		RPCURL:           rpcURL,
		Network:          envOrDefault("MPP_INTEROP_NETWORK", "localnet"),
		Mint:             envOrDefault("MPP_INTEROP_MINT", "USDC"),
		Price:            envOrDefault("MPP_INTEROP_PRICE", "0.001"),
		ResourcePath:     envOrDefault("MPP_INTEROP_RESOURCE_PATH", "/protected"),
		SettlementHeader: envOrDefault("MPP_INTEROP_SETTLEMENT_HEADER", "x-fixture-settlement"),
		PayTo:            payTo,
		SecretKey:        envOrDefault("MPP_INTEROP_SECRET_KEY", "mpp-interop-secret-key"),
		Splits:           splits,
		FeePayerSecret:   feePayer,
	}
	if os.Getenv("MPP_INTEROP_REPLAY_SOURCE_PATH") != "" &&
		os.Getenv("MPP_INTEROP_REPLAY_SOURCE_PRICE") != "" {
		environment.ReplaySource = &replaySource{
			Price:        os.Getenv("MPP_INTEROP_REPLAY_SOURCE_PRICE"),
			ResourcePath: os.Getenv("MPP_INTEROP_REPLAY_SOURCE_PATH"),
		}
	}
	return environment, nil
}

func readSplits() ([]protocol.Split, error) {
	raw := os.Getenv("MPP_INTEROP_SPLITS")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var splits []protocol.Split
	if err := json.Unmarshal([]byte(raw), &splits); err != nil {
		return nil, fmt.Errorf("parse MPP_INTEROP_SPLITS: %w", err)
	}
	return splits, nil
}

func readPrivateKeyEnv(name string) (solana.PrivateKey, error) {
	raw, err := requiredEnv(name)
	if err != nil {
		return nil, err
	}
	var values []int
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if len(values) != 64 {
		return nil, fmt.Errorf("%s must contain 64 private key bytes, got %d", name, len(values))
	}
	key := make([]byte, len(values))
	for index, value := range values {
		if value < 0 || value > 255 {
			return nil, fmt.Errorf("%s byte %d is outside uint8 range", name, index)
		}
		key[index] = byte(value)
	}
	return solana.PrivateKey(key), nil
}

func requiredEnv(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
