// The HTTP API behind the pay-kit playground. Serves the playground
// endpoints with their payment gating (MPP charges through paykit, x402
// through the Go x402 adapter, sessions through the Go session method), so
// the playground web app works against it by only setting
// PAYKIT_PLAYGROUND_API_URL.
//
//	cd go
//	go run ./examples/playground-api
//
// Environment: PORT, NETWORK, RPC_URL, RECIPIENT, FEE_PAYER_KEY,
// MPP_SECRET_KEY. See README.md for the full table.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	_ "github.com/solana-foundation/pay-kit/go/protocols/mpp"
	_ "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// app carries the boot configuration shared by every module.
type app struct {
	network string // raw NETWORK tag: localnet | devnet | mainnet
	// rpcURL is the Solana JSON-RPC endpoint (RPC_URL env var; defaults to
	// the hosted Solana Payment Sandbox).
	rpcURL string
	// recipient is the base58 address paid by the charge endpoints
	// (RECIPIENT env var; defaults to the fee payer's pubkey).
	recipient string
	// secretKey is the MPP challenge-binding HMAC secret (MPP_SECRET_KEY env
	// var; a random per-boot hex secret when unset).
	secretKey string
	// feePayer is the operator keypair that signs and pays fees for
	// settlement transactions (FEE_PAYER_KEY env var; random when unset).
	feePayer solana.PrivateKey
	// rpcClient is the shared RPC client bound to rpcURL.
	rpcClient *rpc.Client
	// repoRoot is the repository checkout root; "" outside a checkout, which
	// disables the docs browser default root and the SPA file server.
	repoRoot string
}

func main() {
	network := envOr("NETWORK", "localnet")
	// Default to the hosted Solana Payment Sandbox so the playground works
	// zero-config: it has the payment-channels program preloaded and supports
	// the surfnet cheatcodes used by the faucet. Override RPC_URL to point at
	// a local surfpool when you need offline iteration.
	rpcURL := envOr("RPC_URL", "https://402.surfnet.dev:8899")
	secretKey := os.Getenv("MPP_SECRET_KEY")
	if secretKey == "" {
		secretKey = randomHexSecret()
	}
	port, err := strconv.Atoi(envOr("PORT", "3000"))
	if err != nil {
		log.Fatalf("invalid PORT: %v", err)
	}

	var feePayer solana.PrivateKey
	if raw := os.Getenv("FEE_PAYER_KEY"); raw != "" {
		feePayer, err = solana.PrivateKeyFromBase58(raw)
		if err != nil {
			log.Fatalf("invalid FEE_PAYER_KEY: %v", err)
		}
	} else {
		feePayer, err = solana.NewRandomPrivateKey()
		if err != nil {
			log.Fatalf("generate fee payer: %v", err)
		}
	}
	recipient := envOr("RECIPIENT", feePayer.PublicKey().String())

	a := &app{
		network:   network,
		rpcURL:    rpcURL,
		recipient: recipient,
		secretKey: secretKey,
		feePayer:  feePayer,
		rpcClient: rpc.New(rpcURL),
		repoRoot:  findRepoRoot(),
	}

	bootstrapFunding(a)

	handler, shutdown, err := newApp(a)
	if err != nil {
		log.Fatalf("playground-api: %v", err)
	}
	defer shutdown()

	addr := fmt.Sprintf(":%d", port)
	log.Println()
	log.Printf("  %s  %s", bold("PayKit Playground (Go)"), dim(fmt.Sprintf("http://localhost:%d", port)))
	log.Println()
	log.Printf("  %s     %s", dim("Network"), magenta(a.network))
	log.Printf("  %s         %s", dim("RPC"), cyan(a.rpcURL))
	log.Printf("  %s   %s", dim("Recipient"), green(a.recipient))
	log.Printf("  %s   %s", dim("Fee payer"), green(a.feePayer.PublicKey().String()))
	log.Printf("  %s        %s", dim("Plan"), yellow("not bootstrapped (subscriptions are not implemented in the Go SDK)"))
	log.Printf("  %s    %s", dim("Sessions"), green("enabled (in-process)"))
	log.Println()
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}

// newApp wires every module onto one handler. Split from main so the smoke
// test can boot the full route table against a stub RPC without binding a
// real port or funding accounts.
func newApp(a *app) (http.Handler, func(), error) {
	mux := http.NewServeMux()

	registerHealthAndConfig(mux, a)
	registerFaucet(mux, a)
	registerDocs(mux, a)

	chargesClient, err := newChargesClient(a)
	if err != nil {
		return nil, nil, fmt.Errorf("charges paykit client: %w", err)
	}
	if err := registerCharges(mux, a, chargesClient); err != nil {
		return nil, nil, fmt.Errorf("charges module: %w", err)
	}

	registerSubscriptions(mux)

	sessionsShutdown, err := registerSessions(mux, a)
	if err != nil {
		return nil, nil, fmt.Errorf("sessions module: %w", err)
	}

	if err := registerX402(mux, a); err != nil {
		sessionsShutdown()
		return nil, nil, fmt.Errorf("x402 module: %w", err)
	}

	registerSPA(mux, a.repoRoot)

	return corsMiddleware(mux), sessionsShutdown, nil
}

// newChargesClient builds the paykit client gating the charge endpoints.
// MPP is the only accepted protocol.
func newChargesClient(a *app) (*paykit.Client, error) {
	network, err := paykit.ParseNetwork(a.network)
	if err != nil {
		return nil, err
	}
	operatorSigner, err := signer.FromBase58(a.feePayer.String())
	if err != nil {
		return nil, err
	}
	return paykit.New(paykit.Config{
		Network: network,
		RPCURL:  a.rpcURL,
		Accept:  []paykit.Protocol{paykit.MPP},
		Operator: paykit.Operator{
			Recipient: paykit.Address(a.recipient),
			Signer:    operatorSigner,
			FeePayer:  true,
		},
		MPP: paykit.MPPConfig{
			Realm:                  "PayKit Playground",
			ChallengeBindingSecret: []byte(a.secretKey),
		},
	})
}

// bootstrapFunding funds the fee payer and recipient on the local surfnet so
// the demo works zero-config. Best-effort: a warning is logged when the
// sandbox is unreachable.
func bootstrapFunding(a *app) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := rpcCall(ctx, a.rpcURL, "surfnet_setAccount", []any{
		a.feePayer.PublicKey().String(),
		map[string]any{
			"lamports":   solFundLamports,
			"data":       "",
			"executable": false,
			"owner":      paycore.SystemProgram,
			"rentEpoch":  0,
		},
	})
	if err == nil {
		_, err = rpcCall(ctx, a.rpcURL, "surfnet_setTokenAccount", []any{
			a.recipient,
			paycore.USDCMainnetMint,
			map[string]any{"amount": usdcFundAmount, "state": "initialized"},
			paycore.TokenProgram,
		})
	}
	if err != nil {
		log.Println(yellow("  Surfpool not reachable; fee payer may not have SOL for fees."))
	}
}

// registerHealthAndConfig mounts the health check and the endpoint catalog
// that drives the playground web app's sidebar.
func registerHealthAndConfig(mux *http.ServeMux, a *app) {
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{
			"ok":        true,
			"feePayer":  a.feePayer.PublicKey().String(),
			"recipient": a.recipient,
			"network":   a.network,
			"rpcUrl":    a.rpcURL,
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		if out, err := a.rpcClient.GetBalance(ctx, a.feePayer.PublicKey(), rpc.CommitmentConfirmed); err == nil && out != nil {
			body["feePayerBalance"] = float64(out.Value) / 1e9
		}
		writeJSON(w, http.StatusOK, body)
	})

	mux.HandleFunc("GET /api/v1/config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"recipient": a.recipient,
			"network":   a.network,
			"rpcUrl":    a.rpcURL,
			"feePayer":  a.feePayer.PublicKey().String(),
			"endpoints": buildEndpointList(),
		})
	})
}

// endpointParam describes one path or query parameter of a catalog entry.
type endpointParam struct {
	// Name is the parameter name as it appears in the :param path
	// placeholder or query string.
	Name string `json:"name"`
	// Default is the value the playground form pre-fills; "" renders an
	// empty input for an optional parameter.
	Default string `json:"default"`
	// Description is optional help text for the form field; omitted when
	// empty.
	Description string `json:"description,omitempty"`
}

// endpointInfo is one entry of the /api/v1/config endpoint catalog.
type endpointInfo struct {
	// ID is the stable slug the web app uses to key the endpoint in its nav.
	ID string `json:"id"`
	// Primitive is the payment primitive gating the route ("charge" or
	// "session").
	Primitive string `json:"primitive"`
	// Method is the HTTP method the endpoint expects (GET, POST, ...).
	Method string `json:"method"`
	// Path is the route pattern with :param placeholders the web app
	// substitutes from Params.
	Path string `json:"path"`
	// Title is the short label shown in the playground sidebar.
	Title string `json:"title"`
	// Description is the one-line summary shown under the title.
	Description string `json:"description"`
	// Cost is the human-readable price label (e.g. "0.01 USDC", "varies").
	Cost string `json:"cost"`
	// UnitPrice is the per-unit price of session endpoints in USDC base
	// units (6 decimals) as a decimal string; omitted for charge endpoints.
	UnitPrice string `json:"unitPrice,omitempty"`
	// Params lists the path/query parameters the web app renders as form
	// inputs; omitted when the endpoint takes none.
	Params []endpointParam `json:"params,omitempty"`
}

// buildEndpointList builds the /api/v1/config endpoint catalog. The
// subscription entry is omitted because the Go SDK has no subscription
// server method (see README.md); the stocks-search / stocks-history /
// weather / fortune / x402 routes stay live server-side but are not
// advertised in the nav.
func buildEndpointList() []endpointInfo {
	return []endpointInfo{
		{
			ID:          "stocks-quote",
			Primitive:   "charge",
			Method:      "GET",
			Path:        "/api/v1/stocks/quote/:symbol",
			Title:       "Stock quote",
			Description: "Real-time price for a single ticker.",
			Cost:        "0.01 USDC",
			Params:      []endpointParam{{Name: "symbol", Default: "AAPL"}},
		},
		{
			ID:          "marketplace-buy",
			Primitive:   "charge",
			Method:      "GET",
			Path:        "/api/v1/marketplace/buy/:productId",
			Title:       "Marketplace purchase",
			Description: "Multi-recipient split (seller + platform + referral).",
			Cost:        "varies",
			Params: []endpointParam{
				{Name: "productId", Default: "sol-hoodie"},
				{Name: "referrer", Default: ""},
			},
		},
		{
			ID:          "sessions-stream",
			Primitive:   "session",
			Method:      "GET",
			Path:        "/sessions/stream",
			Title:       "Metered stream",
			Description: "Pay-per-chunk SSE delivery via session vouchers.",
			Cost:        "0.0001 USDC / chunk",
			UnitPrice:   "100",
		},
		{
			ID:          "sessions-compute",
			Primitive:   "session",
			Method:      "POST",
			Path:        "/sessions/compute",
			Title:       "Pay-per-call compute",
			Description: "Voucher-billed inference; cap 0.50 USDC per session.",
			Cost:        "0.005 USDC / call",
			UnitPrice:   "5000",
		},
	}
}

// corsMiddleware sets permissive origins and exposes to browsers the
// payment headers the web app reads.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Access-Control-Allow-Origin", "*")
		header.Set("Access-Control-Expose-Headers",
			"www-authenticate, payment-receipt, x-payment-required, x-payment-response")
		if r.Method == http.MethodOptions {
			header.Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
			if requested := r.Header.Get("Access-Control-Request-Headers"); requested != "" {
				header.Set("Access-Control-Allow-Headers", requested)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// registerSPA serves the built playground web app (playground/app/dist at
// the repo root) with an index.html catch-all.
func registerSPA(mux *http.ServeMux, repoRoot string) {
	dist := ""
	if repoRoot != "" {
		dist = filepath.Join(repoRoot, "playground", "app", "dist")
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if dist != "" {
			candidate := filepath.Join(dist, filepath.FromSlash(r.URL.Path))
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				http.ServeFile(w, r, candidate)
				return
			}
			index := filepath.Join(dist, "index.html")
			if _, err := os.Stat(index); err == nil {
				http.ServeFile(w, r, index)
				return
			}
		}
		writeJSONError(w, http.StatusNotFound,
			"not found (build playground/app to serve the web app from this server)")
	})
}

// findRepoRoot walks up from the working directory to the repository root
// (the directory containing .git or the top-level justfile). Returns ""
// when no marker is found.
func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, "justfile")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// envOr returns the environment variable value, or fallback when unset or
// empty.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// randomHexSecret generates the per-boot challenge HMAC secret used when
// MPP_SECRET_KEY is unset.
func randomHexSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("generate MPP secret: %v", err)
	}
	return hex.EncodeToString(buf)
}
