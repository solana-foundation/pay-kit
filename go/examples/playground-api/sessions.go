package main

// Two session-gated demo endpoints driven by the in-process session method,
// the reserve/commit metering side channel, and the settle-status receipt
// poll. Both methods share one channel store so the receipt endpoint can
// read the settled signature whichever endpoint opened the channel.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	server "github.com/solana-foundation/pay-kit/go/protocols/mpp/server"
)

// tokenChunks is the canned token stream payload.
var tokenChunks = []string{
	"A payment channel ",
	"lets a client and server ",
	"authorize many small ",
	"off-chain debits ",
	"against a single on-chain ",
	"deposit, settling the highest ",
	"cumulative voucher at close.",
}

// registerSessions mounts the session endpoints and returns the watchdog
// shutdown hook.
//
// Routes:
//   - GET  /sessions/stream: pay-per-chunk SSE, cap 1.00 USDC, 0.0001 USDC/chunk
//   - GET  /api/v1/stream: TS-reference alias for /sessions/stream
//   - POST /sessions/stream: voucher commits for the stream endpoint
//   - POST /api/v1/stream: TS-reference alias for voucher commits
//   - POST /sessions/compute: pay-per-call compute, cap 0.50 USDC, 0.005 USDC/call
//     (also accepts voucher commits)
//   - POST /__402/session/deliveries: SessionFetch-style delivery reservation
//   - POST /__402/session/commit: body-voucher commit variant of the above
//   - GET  /sessions/receipt/{channelId}: settle-status poll for the UI
func registerSessions(mux *http.ServeMux, a *app) (func(), error) {
	// Shared store across both session methods so /sessions/receipt can read
	// channel state regardless of which endpoint opened the channel.
	sharedStore := server.NewMemoryChannelStore()
	strategy := intents.SessionPullVoucherStrategyClientVoucher

	newMethod := func(cap uint64) (*server.Session, error) {
		return server.NewSession(server.SessionOptions{
			Operator:  a.feePayer.PublicKey().String(),
			Recipient: a.recipient,
			Cap:       cap,
			Currency:  paycore.USDCMainnetMint,
			Decimals:  usdcDecimals,
			Network:   a.network,
			SecretKey: a.secretKey,
			// Real on-chain opens: the browser pre-signs a payment-channel
			// open transaction (fee payer = operator) and the server
			// completes the signature, broadcasts, and waits for
			// confirmation before metering.
			Modes:               []intents.SessionMode{intents.SessionModePull},
			PullVoucherStrategy: &strategy,
			OpenTxSubmitter:     server.OpenTxSubmitterServer,
			// Settle roughly two seconds after the stream ends so the UI's
			// receipt poll resolves quickly.
			CloseDelay:                2 * time.Second,
			PaymentChannelPayerSigner: a.feePayer,
			Signer:                    a.feePayer,
			RPC:                       a.rpcClient,
			Store:                     sharedStore,
		})
	}

	streamSession, err := newMethod(1_000_000) // 1.00 USDC
	if err != nil {
		return nil, fmt.Errorf("stream session method: %w", err)
	}
	computeSession, err := newMethod(500_000) // 0.50 USDC
	if err != nil {
		streamSession.Shutdown()
		return nil, fmt.Errorf("compute session method: %w", err)
	}
	shutdown := func() {
		streamSession.Shutdown()
		computeSession.Shutdown()
	}

	streamGate := server.SessionMiddleware(streamSession, func(*http.Request) (server.SessionChallengeOptions, error) {
		return server.SessionChallengeOptions{Cap: "1000000", Description: "Metered token stream"}, nil
	})
	computeGate := server.SessionMiddleware(computeSession, func(*http.Request) (server.SessionChallengeOptions, error) {
		return server.SessionChallengeOptions{Cap: "500000", Description: "Voucher-billed inference call"}, nil
	})

	streamHandler := streamGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		stream := server.NewMeteredStream(w)
		w.WriteHeader(http.StatusOK)
		for _, chunk := range tokenChunks {
			if err := stream.WriteJSON(map[string]string{"chunk": chunk, "cost": "100"}); err != nil {
				return
			}
			time.Sleep(80 * time.Millisecond)
		}
		_ = stream.WriteDone()
	}))
	// GET /sessions/stream and /api/v1/stream: stream tokens as SSE; each
	// chunk costs 0.0001 USDC.
	mux.Handle("GET /sessions/stream", streamHandler)
	mux.Handle("GET /api/v1/stream", streamHandler)

	streamCommitHandler := streamGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, commitAck(r))
	}))
	// POST /sessions/stream and /api/v1/stream: voucher commits arrive on
	// the URL the session was opened against, with the signed voucher in the
	// Authorization credential. The middleware's verify path applies it; the
	// body is an ack.
	mux.Handle("POST /sessions/stream", streamCommitHandler)
	mux.Handle("POST /api/v1/stream", streamCommitHandler)

	// POST /sessions/compute: pay-per-call compute; the same handler also
	// accepts voucher commits (a deliveryId in the body discriminates).
	mux.Handle("POST /sessions/compute", computeGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Prompt     string `json:"prompt"`
			DeliveryID string `json:"deliveryId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.DeliveryID != "" {
			writeJSON(w, http.StatusOK, map[string]string{
				"amount":     "0",
				"deliveryId": body.DeliveryID,
				"status":     "committed",
			})
			return
		}
		logPayment(r.URL.Path, w.Header())
		writeJSON(w, http.StatusOK, map[string]string{
			"prompt":     body.Prompt,
			"output":     "Echo: " + body.Prompt + " (computed for 0.005 USDC)",
			"computedAt": time.Now().UTC().Format(time.RFC3339),
		})
	})))

	// Side-channel metering routes: SessionFetch-style clients reserve
	// capacity for each metered delivery before signing + committing the
	// voucher. Both handlers share the methods' channel store.
	routes := streamSession.Routes()
	mux.HandleFunc("POST /__402/session/deliveries", routes.Deliveries)
	mux.HandleFunc("POST /__402/session/commit", routes.Commit)

	// Receipt poll endpoint: the UI hits this after the stream ends to learn
	// the on-chain settle signature. The idle-close watchdog fires about
	// CloseDelay after the last voucher and, with Signer + RPC configured
	// above, attempts the on-chain settle-and-distribute.
	mux.HandleFunc("GET /sessions/receipt/{channelId}", func(w http.ResponseWriter, r *http.Request) {
		channelID := r.PathValue("channelId")
		if channelID == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid-channel-id")
			return
		}
		state, err := sharedStore.GetChannel(r.Context(), channelID)
		if err != nil || state == nil {
			writeJSONError(w, http.StatusNotFound, "channel-not-found")
			return
		}
		var settledSignature any
		if state.SettledSignature != nil {
			settledSignature = *state.SettledSignature
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"channelId":        state.ChannelID,
			"cumulative":       fmt.Sprintf("%d", state.Cumulative),
			"deposit":          fmt.Sprintf("%d", state.Deposit),
			"finalized":        state.Finalized,
			"settledSignature": settledSignature,
		})
	})

	return shutdown, nil
}

// commitAck is the minimal CommitReceipt-shaped JSON ack the stream commit
// handler returns.
func commitAck(r *http.Request) map[string]string {
	var body struct {
		Amount     string `json:"amount"`
		DeliveryID string `json:"deliveryId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Amount == "" {
		body.Amount = "0"
	}
	return map[string]string{
		"amount":     body.Amount,
		"deliveryId": body.DeliveryID,
		"status":     "committed",
	}
}
