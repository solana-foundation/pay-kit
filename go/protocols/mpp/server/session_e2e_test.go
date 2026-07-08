package server

// Surfpool-gated end-to-end session lifecycle test.
//
// Exercises a real payment-channel open completed and broadcast by the
// server, metered vouchers, side-channel reserve/commit, and on-chain settle
// at close against the hosted Solana Payment Sandbox. The suite gates at
// runtime: it skips explicitly (never silently passes) when the sandbox is
// unreachable or the suite runs with -short.

import (
	"bytes"
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

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// surfpoolRPCURL resolves the sandbox RPC endpoint, honoring the harness
// override.
func surfpoolRPCURL() string {
	if url := os.Getenv("MPP_HARNESS_RPC_URL"); url != "" {
		return url
	}
	return "https://402.surfnet.dev:8899"
}

// The public hosted sandbox can lag the repo's generated payment-channels ABI.
// Keep explicit MPP_HARNESS_RPC_URL runs strict; only skip the default hosted
// endpoint on the known ABI-drift signature.
func hostedPaymentChannelsABIDrift(body string) bool {
	if os.Getenv("MPP_HARNESS_RPC_URL") != "" {
		return false
	}
	if !strings.Contains(body, paymentchannels.ProgramID) {
		return false
	}
	// NotEnoughAccountKeys: pre-rename deployments missing newer accounts.
	// Custom error 0x104 (invalidRecipientCount) on a well-formed open: the
	// deployment predates the openSlot open-arg, so it misparses the arg
	// bytes that follow gracePeriod as the recipients count.
	return strings.Contains(body, "NotEnoughAccountKeys") ||
		strings.Contains(body, "custom program error: 0x104")
}

// requireSurfpool skips the test explicitly when the sandbox is unreachable.
func requireSurfpool(t *testing.T) *rpc.Client {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping surfpool e2e in -short mode")
	}
	url := surfpoolRPCURL()
	rpcClient := rpc.New(url)
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := rpcClient.GetLatestBlockhash(probeCtx, rpc.CommitmentConfirmed); err != nil {
		t.Skipf("surfpool sandbox unreachable at %s: %v", url, err)
	}
	return rpcClient
}

// surfnetSetAccount funds owner with lamports via the surfnet cheatcode.
func surfnetSetAccount(ctx context.Context, t *testing.T, rpcClient *rpc.Client, owner solana.PublicKey, lamports uint64) {
	t.Helper()
	params := []any{
		owner.String(),
		map[string]any{
			"lamports":   lamports,
			"data":       "",
			"executable": false,
			"owner":      "11111111111111111111111111111111",
			"rentEpoch":  0,
		},
	}
	var out json.RawMessage
	if err := rpcClient.RPCCallForInto(ctx, &out, "surfnet_setAccount", params); err != nil {
		t.Fatalf("surfnet_setAccount(%s): %v", owner, err)
	}
}

// surfnetSetTokenAccount provisions owner's token account via the surfnet
// cheatcode.
func surfnetSetTokenAccount(ctx context.Context, t *testing.T, rpcClient *rpc.Client, owner solana.PublicKey, mint string, amount uint64) {
	t.Helper()
	params := []any{
		owner.String(),
		mint,
		map[string]any{"amount": amount, "state": "initialized"},
		paycore.TokenProgram,
	}
	var out json.RawMessage
	if err := rpcClient.RPCCallForInto(ctx, &out, "surfnet_setTokenAccount", params); err != nil {
		t.Fatalf("surfnet_setTokenAccount(%s): %v", owner, err)
	}
}

// authedGet performs a GET with the given Authorization header and returns
// the response plus its body.
func authedGet(t *testing.T, url, authorization string) (*http.Response, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if authorization != "" {
		request.Header.Set(core.AuthorizationHeader, authorization)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response, string(body)
}

func TestSessionServerE2ESurfpool(t *testing.T) {
	rpcClient := requireSurfpool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// The operator funds fees, completes the open signature server-side, and
	// receives the proceeds.
	operator := testutil.NewPrivateKey()
	payer := testutil.NewPrivateKey()
	mint := paycore.ResolveMint("USDC", "localnet")

	surfnetSetAccount(ctx, t, rpcClient, operator.PublicKey(), 10_000_000_000)
	surfnetSetAccount(ctx, t, rpcClient, payer.PublicKey(), 10_000_000_000)
	surfnetSetTokenAccount(ctx, t, rpcClient, payer.PublicKey(), mint, 100_000_000)
	surfnetSetTokenAccount(ctx, t, rpcClient, operator.PublicKey(), mint, 0)

	strategy := intents.SessionPullVoucherStrategyClientVoucher
	session, err := NewSession(SessionOptions{
		Operator:                  operator.PublicKey().String(),
		Recipient:                 operator.PublicKey().String(),
		Cap:                       1_000_000, // 1.00 USDC
		Currency:                  "USDC",
		Decimals:                  6,
		Network:                   "localnet",
		SecretKey:                 "session-e2e-secret",
		Realm:                     "e2e.test",
		Modes:                     []intents.SessionMode{intents.SessionModePull},
		PullVoucherStrategy:       &strategy,
		OpenTxSubmitter:           OpenTxSubmitterServer,
		PaymentChannelPayerSigner: operator,
		Signer:                    operator,
		RPC:                       rpcClient,
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(session.Shutdown)

	mux := http.NewServeMux()
	routes := session.Routes()
	mux.HandleFunc("/__402/session/deliveries", routes.Deliveries)
	mux.HandleFunc("/__402/session/commit", routes.Commit)
	mux.Handle("/stream", SessionMiddleware(session, func(*http.Request) (SessionChallengeOptions, error) {
		return SessionChallengeOptions{Description: "Metered token stream"}, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})))
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	streamURL := httpServer.URL + "/stream"

	// 1. Unauthenticated request: 402 with a session challenge carrying a
	// recent blockhash from the sandbox.
	response, body := authedGet(t, streamURL, "")
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

	// 2. Open: the client derives the channel, partial-signs as the payer
	// against the challenge blockhash, and the server completes the fee-payer
	// signature and broadcasts.
	sessionSigner, err := client.NewEphemeralSessionSigner()
	if err != nil {
		t.Fatalf("NewEphemeralSessionSigner: %v", err)
	}
	opener, err := client.CreatePaymentChannelSessionOpener(request, payer, sessionSigner, "", client.PaymentChannelSessionOpenOptions{})
	if err != nil {
		t.Fatalf("CreatePaymentChannelSessionOpener: %v", err)
	}
	openAuthorization, err := client.SerializeSessionCredential(challenge, opener.Action)
	if err != nil {
		t.Fatalf("serialize open credential: %v", err)
	}
	response, body = authedGet(t, streamURL, openAuthorization)
	if response.StatusCode != http.StatusOK {
		if hostedPaymentChannelsABIDrift(body) {
			t.Skipf("hosted Surfpool payment-channels program ABI is behind the repo generated client: %s", body)
		}
		t.Fatalf("open failed: %d %s", response.StatusCode, body)
	}
	channelID := opener.Session.ChannelIDString()
	state := mustGetChannel(t, session, channelID)
	if state == nil || state.Deposit != 1_000_000 {
		t.Fatalf("channel state after open = %+v", state)
	}

	// The broadcast open transaction confirmed on-chain.
	openReceipt, err := core.ParseReceipt(response.Header.Get(core.PaymentReceiptHeader))
	if err != nil {
		t.Fatalf("parse open receipt: %v", err)
	}
	openSignature, err := solana.SignatureFromBase58(openReceipt.Reference)
	if err != nil {
		t.Fatalf("open receipt reference %q is not a signature: %v", openReceipt.Reference, err)
	}
	statuses, err := rpcClient.GetSignatureStatuses(ctx, true, openSignature)
	if err != nil || len(statuses.Value) == 0 || statuses.Value[0] == nil || statuses.Value[0].Err != nil {
		t.Fatalf("open signature %s not confirmed: %v %+v", openSignature, err, statuses)
	}

	// 3. In-band voucher: advances the watermark.
	voucherAction, err := opener.Session.VoucherAction(100)
	if err != nil {
		t.Fatalf("VoucherAction: %v", err)
	}
	voucherAuthorization, err := client.SerializeSessionCredential(challenge, voucherAction)
	if err != nil {
		t.Fatalf("serialize voucher credential: %v", err)
	}
	response, body = authedGet(t, streamURL, voucherAuthorization)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("voucher failed: %d %s", response.StatusCode, body)
	}
	if mustGetChannel(t, session, channelID).Cumulative != 100 {
		t.Fatal("voucher did not advance the watermark")
	}

	// 4. Side-channel reserve + commit.
	reserve := reserveDeliveryHTTP(t, httpServer.URL, map[string]any{"sessionId": channelID, "amount": "200"})
	voucher, err := opener.Session.PrepareIncrement(150)
	if err != nil {
		t.Fatalf("PrepareIncrement: %v", err)
	}
	receipt := commitDeliveryHTTP(t, httpServer.URL, reserve.DeliveryID, voucher)
	if receipt.Status != intents.CommitStatusCommitted || receipt.Cumulative != "250" {
		t.Fatalf("commit receipt = %+v", receipt)
	}
	if err := opener.Session.RecordVoucher(voucher); err != nil {
		t.Fatalf("RecordVoucher: %v", err)
	}

	// 5. Close: settles the highest voucher on-chain and seals.
	closeAuthorization, err := client.SerializeSessionCredential(challenge,
		intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID}))
	if err != nil {
		t.Fatalf("serialize close credential: %v", err)
	}
	response, body = authedGet(t, streamURL, closeAuthorization)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("close failed: %d %s", response.StatusCode, body)
	}
	state = mustGetChannel(t, session, channelID)
	if !state.Sealed || state.SettledSignature == nil {
		t.Fatalf("channel not settled: %+v", state)
	}
	settleSignature, err := solana.SignatureFromBase58(*state.SettledSignature)
	if err != nil {
		t.Fatalf("settled signature %q invalid: %v", *state.SettledSignature, err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		statuses, err := rpcClient.GetSignatureStatuses(ctx, true, settleSignature)
		if err == nil && len(statuses.Value) > 0 && statuses.Value[0] != nil {
			if statuses.Value[0].Err != nil {
				t.Fatalf("settlement failed on-chain: %+v", statuses.Value[0].Err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("settlement %s never confirmed", settleSignature)
		}
		time.Sleep(time.Second)
	}
}

// reserveDeliveryHTTP reserves a delivery through the live side channel.
func reserveDeliveryHTTP(t *testing.T, baseURL string, body map[string]any) intents.MeteringDirective {
	t.Helper()
	directive := intents.MeteringDirective{}
	postSessionJSON(t, baseURL+"/__402/session/deliveries", body, &directive)
	return directive
}

// commitDeliveryHTTP commits a delivery through the live side channel.
func commitDeliveryHTTP(t *testing.T, baseURL, deliveryID string, voucher intents.SignedVoucher) intents.CommitReceipt {
	t.Helper()
	receipt := intents.CommitReceipt{}
	postSessionJSON(t, baseURL+"/__402/session/commit", map[string]any{
		"deliveryId": deliveryID,
		"voucher":    voucher,
	}, &receipt)
	return receipt
}

// postSessionJSON POSTs a JSON body and decodes the 200 response into out.
func postSessionJSON(t *testing.T, url string, body map[string]any, out any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	response, err := http.Post(url, "application/json", bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: %d %s", url, response.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
