package main

// Surfpool-gated end-to-end test: boots the real playground handler against
// the hosted Solana Payment Sandbox, funds a wallet through the faucet
// cheatcodes, opens a payment channel on the /sessions/stream 402 (client
// pre-signs, server completes the fee-payer signature and broadcasts),
// streams the metered SSE chunks, commits a voucher through the side
// channel, and polls /sessions/receipt until the idle-close watchdog settles
// the channel on-chain. Skips explicitly (never silently passes) when the
// sandbox is unreachable or under -short.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// sandboxRPCURL resolves the sandbox endpoint, honoring the harness override.
func sandboxRPCURL() string {
	if url := os.Getenv("MPP_HARNESS_RPC_URL"); url != "" {
		return url
	}
	return "https://402.surfnet.dev:8899"
}

// requireSandbox skips the test explicitly when the sandbox is unreachable.
func requireSandbox(t *testing.T) *rpc.Client {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping surfpool e2e in -short mode")
	}
	url := sandboxRPCURL()
	rpcClient := rpc.New(url)
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := rpcClient.GetLatestBlockhash(probeCtx, rpc.CommitmentConfirmed); err != nil {
		t.Skipf("surfpool sandbox unreachable at %s: %v", url, err)
	}
	return rpcClient
}

func TestPlaygroundSessionE2ESurfpool(t *testing.T) {
	rpcClient := requireSandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	feePayer, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("generate fee payer: %v", err)
	}
	a := &app{
		network:   "localnet",
		rpcURL:    sandboxRPCURL(),
		recipient: feePayer.PublicKey().String(),
		secretKey: "playground-e2e-secret",
		feePayer:  feePayer,
		rpcClient: rpcClient,
		repoRoot:  t.TempDir(),
	}
	bootstrapFunding(a)

	handler, shutdown, err := newApp(a)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(shutdown)
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)

	// Fund the paying wallet through the playground's own faucet endpoint.
	payer, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("generate payer: %v", err)
	}
	response, body := playgroundRequest(t, http.MethodPost, httpServer.URL+"/api/v1/faucet/airdrop",
		`{"address":"`+payer.PublicKey().String()+`"}`, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("faucet airdrop failed: %d %s", response.StatusCode, body)
	}

	// 1. Unauthenticated request: 402 with a session challenge carrying a
	// recent blockhash from the sandbox.
	streamURL := httpServer.URL + "/sessions/stream"
	response, body = playgroundRequest(t, http.MethodGet, streamURL, "", "")
	if response.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d: %s", response.StatusCode, body)
	}
	challenge, request, err := client.ParseSessionChallenge(response.Header.Get(core.WWWAuthenticateHeader))
	if err != nil {
		t.Fatalf("ParseSessionChallenge: %v", err)
	}
	if request.RecentBlockhash == nil {
		t.Fatal("challenge missing recentBlockhash")
	}

	// 2. Open: the client derives the channel and partial-signs as the payer;
	// the playground completes the fee-payer signature and broadcasts.
	sessionSigner, err := client.NewEphemeralSessionSigner()
	if err != nil {
		t.Fatalf("NewEphemeralSessionSigner: %v", err)
	}
	opener, err := client.CreatePaymentChannelSessionOpener(request, payer, sessionSigner, "",
		client.PaymentChannelSessionOpenOptions{})
	if err != nil {
		t.Fatalf("CreatePaymentChannelSessionOpener: %v", err)
	}
	openAuthorization, err := client.SerializeSessionCredential(challenge, opener.Action)
	if err != nil {
		t.Fatalf("serialize open credential: %v", err)
	}
	response, body = playgroundRequest(t, http.MethodGet, streamURL, "", openAuthorization)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("open failed: %d %s", response.StatusCode, body)
	}
	if !strings.Contains(body, "payment channel") || !strings.Contains(body, "[DONE]") {
		t.Fatalf("stream body missing chunks or sentinel: %s", body)
	}
	channelID := opener.Session.ChannelIDString()

	// 3. Side-channel reserve + commit for the seven streamed chunks.
	directive := struct {
		DeliveryID string `json:"deliveryId"`
	}{}
	response, body = playgroundRequest(t, http.MethodPost, httpServer.URL+"/__402/session/deliveries",
		`{"sessionId":"`+channelID+`","amount":"700"}`, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reserve failed: %d %s", response.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &directive); err != nil || directive.DeliveryID == "" {
		t.Fatalf("reserve directive = %s (%v)", body, err)
	}
	voucher, err := opener.Session.PrepareIncrement(700)
	if err != nil {
		t.Fatalf("PrepareIncrement: %v", err)
	}
	voucherJSON, err := json.Marshal(voucher)
	if err != nil {
		t.Fatalf("marshal voucher: %v", err)
	}
	response, body = playgroundRequest(t, http.MethodPost, httpServer.URL+"/__402/session/commit",
		`{"deliveryId":"`+directive.DeliveryID+`","voucher":`+string(voucherJSON)+`}`, "")
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `"committed"`) {
		t.Fatalf("commit failed: %d %s", response.StatusCode, body)
	}
	if err := opener.Session.RecordVoucher(voucher); err != nil {
		t.Fatalf("RecordVoucher: %v", err)
	}

	// 4. The idle-close watchdog settles on-chain ~2s after the last
	// voucher; poll the receipt endpoint the way the web app does.
	receipt := struct {
		Finalized        bool    `json:"finalized"`
		Cumulative       string  `json:"cumulative"`
		SettledSignature *string `json:"settledSignature"`
	}{}
	deadline := time.Now().Add(60 * time.Second)
	for {
		response, body = playgroundRequest(t, http.MethodGet,
			httpServer.URL+"/sessions/receipt/"+channelID, "", "")
		if response.StatusCode == http.StatusOK {
			if err := json.Unmarshal([]byte(body), &receipt); err != nil {
				t.Fatalf("receipt body = %s (%v)", body, err)
			}
			if receipt.Finalized && receipt.SettledSignature != nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("receipt never finalized: %d %s", response.StatusCode, body)
		}
		time.Sleep(time.Second)
	}
	if receipt.Cumulative != "700" {
		t.Fatalf("settled cumulative = %s, want 700", receipt.Cumulative)
	}

	// 5. The settle transaction confirmed on-chain.
	settleSignature, err := solana.SignatureFromBase58(*receipt.SettledSignature)
	if err != nil {
		t.Fatalf("settled signature %q invalid: %v", *receipt.SettledSignature, err)
	}
	confirmDeadline := time.Now().Add(30 * time.Second)
	for {
		statuses, err := rpcClient.GetSignatureStatuses(ctx, true, settleSignature)
		if err == nil && len(statuses.Value) > 0 && statuses.Value[0] != nil {
			if statuses.Value[0].Err != nil {
				t.Fatalf("settlement failed on-chain: %+v", statuses.Value[0].Err)
			}
			break
		}
		if time.Now().After(confirmDeadline) {
			t.Fatalf("settlement %s never confirmed", settleSignature)
		}
		time.Sleep(time.Second)
	}
}

// playgroundRequest performs one HTTP request against the playground under
// test and returns the response plus its body.
func playgroundRequest(t *testing.T, method, url, body, authorization string) (*http.Response, string) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set(core.AuthorizationHeader, authorization)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response, string(raw)
}
