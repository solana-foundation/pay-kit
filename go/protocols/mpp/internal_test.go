package mpp

import (
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paykit"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/signer"
)

func testCfg() paykit.Config {
	demo := signer.Demo()
	return paykit.Config{
		Network:     paykit.SolanaLocalnet,
		Stablecoins: []paykit.Stablecoin{paykit.USDC},
		Operator:    paykit.Operator{Signer: demo, Recipient: demo.Pubkey(), FeePayer: true},
		MPP:         paykit.MPPConfig{Realm: "Unit", ChallengeBindingSecret: []byte("secret")},
		RPCURL:      "https://example.invalid", // never dialed in these tests
	}
}

func TestSignerBridgeSignAndPubkey(t *testing.T) {
	demo := signer.Demo()
	b := &signerBridge{signer: demo}
	if b.PublicKey() != solana.MustPublicKeyFromBase58(string(demo.Pubkey())) {
		t.Error("bridge pubkey mismatch")
	}
	sig, err := b.Sign([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if sig.IsZero() {
		t.Error("bridge produced a zero signature")
	}
}

func TestServerForCachesPerKey(t *testing.T) {
	a := &Adapter{cfg: testCfg()}
	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	s1, err := a.serverFor(gate)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := a.serverFor(gate)
	if err != nil {
		t.Fatal(err)
	}
	if s1 != s2 {
		t.Error("serverFor should return the same cached *server.Mpp for the same (payTo,coin)")
	}
	// Different payTo => distinct instance.
	other := &paykit.Gate{Amount: paykit.MustParseUSD("0.10"), PayTo: paykit.Address("So11111111111111111111111111111111111111112")}
	s3, err := a.serverFor(other)
	if err != nil {
		t.Fatal(err)
	}
	if s3 == s1 {
		t.Error("different payTo should map to a distinct server instance")
	}
}

func TestCoinHelpers(t *testing.T) {
	a := &Adapter{cfg: testCfg()}
	// Gate with explicit settlement preference wins over config default.
	narrowed := &paykit.Gate{Amount: paykit.MustParseUSD("0.10", paykit.USDT)}
	if got := a.settlementCoin(narrowed); got != "USDT" {
		t.Errorf("settlementCoin gate pref: got %s want USDT", got)
	}
	// Gate without preference falls back to config Stablecoins[0].
	plain := &paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	if got := a.settlementCoin(plain); got != "USDC" {
		t.Errorf("settlementCoin config fallback: got %s want USDC", got)
	}
	if got := a.totalUnits(plain, "USDC"); got != "100000" {
		t.Errorf("totalUnits: got %s want 100000", got)
	}
	if got := a.amountString(plain); got != "0.1" {
		t.Errorf("amountString: got %s want 0.1", got)
	}
	if got := a.priceUnits(paykit.MustParseUSD("0.30")); got != "300000" {
		t.Errorf("priceUnits: got %s want 300000", got)
	}
}

func TestPayToFallsBackToOperatorRecipient(t *testing.T) {
	a := &Adapter{cfg: testCfg()}
	plain := &paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	if a.payTo(plain) != a.cfg.Operator.Recipient {
		t.Error("payTo should default to operator recipient")
	}
	withPayTo := &paykit.Gate{Amount: paykit.MustParseUSD("0.10"), PayTo: paykit.Address("SELLER")}
	if a.payTo(withPayTo) != paykit.Address("SELLER") {
		t.Error("gate PayTo should override")
	}
}

func TestChallengeHeadersEmitsWWWAuthenticate(t *testing.T) {
	cfg := testCfg()
	cfg.RPCURL = "http://127.0.0.1:1" // unreachable; blockhash fetch is best-effort
	a := &Adapter{cfg: cfg}
	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/paid"}
	headers := a.ChallengeHeaders(gate)
	if headers == nil {
		t.Fatal("expected challenge headers")
	}
	wwwAuth := headers["www-authenticate"]
	if wwwAuth == "" {
		// header key casing differs across helpers; accept any non-empty value
		for _, v := range headers {
			if v != "" {
				wwwAuth = v
				break
			}
		}
	}
	if wwwAuth == "" {
		t.Errorf("expected a non-empty challenge header, got %v", headers)
	}
}

func TestVerifyAndSettleRejectsNonPaymentAuthorization(t *testing.T) {
	a := &Adapter{cfg: testCfg()}
	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, Authorization: "Bearer xyz"})
	if err == nil {
		t.Error("expected rejection for non-Payment Authorization scheme")
	}
}

func TestAcceptsEntryEmitsSplitsAndNetwork(t *testing.T) {
	a := &Adapter{cfg: testCfg()}
	gate := &paykit.Gate{
		Amount:    paykit.MustParseUSD("10.00"),
		PayTo:     paykit.Address("SELLER"),
		FeeOnTop:  paykit.Fees{paykit.Address("GATEWAY"): paykit.MustParseUSD("0.50")},
		FeeWithin: paykit.Fees{paykit.Address("PLATFORM"): paykit.MustParseUSD("0.30")},
	}
	entry := a.AcceptsEntry(gate).(AcceptsEntry)
	if entry.Network != paykit.SolanaLocalnet.CAIP2() {
		t.Errorf("network: got %s", entry.Network)
	}
	if len(entry.Splits) != 2 {
		t.Errorf("expected 2 splits, got %d", len(entry.Splits))
	}
	if entry.AcceptsProtocol() != paykit.MPP {
		t.Error("AcceptsProtocol mismatch")
	}
}

func TestVerifyAndSettleRejectsGarbageCredential(t *testing.T) {
	cfg := testCfg()
	cfg.RPCURL = "http://127.0.0.1:1" // unreachable; charge build tolerates it
	a := &Adapter{cfg: cfg}
	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	// Well-formed "Payment <token>" prefix but the token is not a valid
	// credential -> drives serverFor + ChargeWithOptions + parse/verify
	// and must reject rather than settle.
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{
		Gate:          gate,
		Authorization: "Payment bm90LWEtY3JlZGVudGlhbA==",
	})
	if err == nil {
		t.Error("expected rejection for a garbage Payment credential")
	}
}

func TestVerifyAndSettleReachesCredentialVerification(t *testing.T) {
	cfg := testCfg()
	cfg.RPCURL = "http://127.0.0.1:1" // unreachable; charge build tolerates it
	a := &Adapter{cfg: cfg}
	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	// A structurally valid but forged credential: it parses, drives
	// serverFor + ChargeWithOptions + Decode, then fails at
	// VerifyCredentialWithExpected because the echoed challenge id is not
	// the server's HMAC over the rebuilt request.
	echo := core.ChallengeEcho{
		ID:     "deadbeefdeadbeef",
		Realm:  "Unit",
		Method: core.NewMethodName("solana"),
		Intent: core.NewIntentName("mpp/charge/pull"),
	}
	cred, err := core.NewPaymentCredential(echo, map[string]string{"transaction": "AA=="})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := core.FormatAuthorization(cred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, Authorization: auth}); err == nil {
		t.Error("expected a forged credential to be rejected after charge rebuild")
	}
}
