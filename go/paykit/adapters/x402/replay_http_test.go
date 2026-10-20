package x402

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// This is an HTTP integration regression with transport-free simulated RPC,
// real disposable signatures and the production Require middleware. It is
// deliberately not evidence of a confirmed ledger transfer.
func TestReplayHTTPIntegrationOffline(t *testing.T) {
	a, gate, rpcClient, partial, full := replayIdentityFixture(t, false, proto.X402Version)
	paykit.RegisterAdapter(paykit.X402, func(paykit.Config) (paykit.Adapter, error) { return a, nil })
	t.Cleanup(func() { paykit.RegisterAdapter(paykit.X402, New) })
	cfg := a.cfg
	cfg.Accept = []paykit.Protocol{paykit.X402}
	cfg.RPCURL = "http://127.0.0.1:1" // Never use the hosted localnet default.
	preflight := false                // Boot checks only; the simulated RPC has no accounts.
	cfg.Preflight = &preflight
	kit, err := paykit.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	lastCode := ""
	kit.SetErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		var pe *paykit.PaymentError
		if errors.As(err, &pe) {
			lastCode = pe.Code
		}
		paykit.DefaultErrorHandler(w, r, err)
	})
	handlers := 0
	server := httptest.NewServer(kit.Require(*gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers++
		payment, ok := paykit.PaymentFrom(r.Context())
		if !ok {
			t.Error("paid handler has no verified payment")
			http.Error(w, "no payment", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"paid": true, "invocation": handlers, "transaction": payment.Transaction})
	})))
	defer server.Close()
	httpClient := &http.Client{Timeout: 5 * time.Second}
	statuses := []int{}
	settlements := []string{}
	for _, req := range []struct{ label, header string }{{"unpaid", ""}, {"partial", partial}, {"full", full}} {
		lastCode = ""
		request, err := http.NewRequest(http.MethodGet, server.URL+"/paid", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Payment-Signature", req.header)
		response, err := httpClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		settlement := response.Header.Get(proto.SettlementHeader)
		statuses = append(statuses, response.StatusCode)
		settlements = append(settlements, settlement)
		log, _ := json.Marshal(map[string]any{"evidence": "HTTP integration with simulated RPC; no ledger", "representation": req.label, "http_status": response.StatusCode, "payment_error_code": lastCode, "settlement_header": settlement, "body": string(body), "paid_handler_invocations": handlers, "rpc_send_calls": rpcClient.sends})
		t.Log(string(log))
	}
	raw, err := base64.StdEncoding.DecodeString(full)
	if err != nil {
		t.Fatal(err)
	}
	var credential proto.Credential
	if err := json.Unmarshal(raw, &credential); err != nil {
		t.Fatal(err)
	}
	fullTx, err := solanatx.DecodeTransactionBase64(credential.Payload.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	log, _ := json.Marshal(map[string]any{"evidence": "simulated RPC only", "transaction": fullTx.Signatures[0].String(), "http_statuses": statuses, "paid_handler_invocations": handlers, "rpc_send_calls": rpcClient.sends})
	t.Log(string(log))
	if statuses[0] != 402 || statuses[1] != 200 || statuses[2] != 402 || handlers != 1 || rpcClient.sends != 1 {
		t.Errorf("one signed payment must unlock one HTTP response: statuses=%v handlers=%d sends=%d", statuses, handlers, rpcClient.sends)
	}
	if settlements[1] != fullTx.Signatures[0].String() {
		t.Error("receipt does not match the actual signed transaction")
	}
	if statuses[2] == 200 && settlements[2] != settlements[1] {
		t.Error("unexpected second transaction identity")
	}
}
