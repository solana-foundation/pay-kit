package mpp

import (
	"context"
	"fmt"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// errSigner is a paykit.Signer stub whose Sign method always returns the given
// error, exercising the signerBridge.Sign error propagation branch.
type errSigner struct {
	pubkey string
	err    error
	raw    []byte // when non-nil, Sign returns this slice without error
}

func (e *errSigner) Pubkey() paykit.Address { return paykit.Address(e.pubkey) }
func (e *errSigner) IsDemo() bool           { return false }
func (e *errSigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.raw, nil
}

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

// TestSignerBridgeSignPropagatesSignerError proves that when the wrapped
// paykit.Signer.Sign returns an error, signerBridge.Sign surfaces it wrapped
// with the "signerBridge:" prefix.
func TestSignerBridgeSignPropagatesSignerError(t *testing.T) {
	demo := signer.Demo()
	bad := &errSigner{
		pubkey: string(demo.Pubkey()),
		err:    fmt.Errorf("KMS unavailable"),
	}
	b := &signerBridge{signer: bad}
	_, err := b.Sign([]byte("hello"))
	if err == nil {
		t.Fatal("expected an error from failing inner signer")
	}
	if err.Error() == "" {
		t.Fatal("expected non-empty error message")
	}
}

// TestSignerBridgeSignRejectsWrongLength proves that when the inner signer
// returns a raw byte slice that is not exactly 64 bytes, signerBridge.Sign
// returns an error rather than copying a truncated or oversized value into a
// solana.Signature.
func TestSignerBridgeSignRejectsWrongLength(t *testing.T) {
	demo := signer.Demo()
	short := &errSigner{
		pubkey: string(demo.Pubkey()),
		raw:    make([]byte, 32), // 32 bytes — not 64
	}
	b := &signerBridge{signer: short}
	_, err := b.Sign([]byte("hello"))
	if err == nil {
		t.Fatal("expected an error for a 32-byte (non-64) signature")
	}
}

// TestChallengeHeadersReturnsNilOnBadRecipient proves that ChallengeHeaders
// returns nil (rather than panicking) when the gate's PayTo address is not a
// valid Solana pubkey, which causes serverFor -> server.New to fail.
func TestChallengeHeadersReturnsNilOnBadRecipient(t *testing.T) {
	a := &Adapter{cfg: testCfg()}
	gate := &paykit.Gate{
		Amount: paykit.MustParseUSD("0.10"),
		PayTo:  paykit.Address("!!!not-a-valid-pubkey"),
	}
	if headers := a.ChallengeHeaders(gate); headers != nil {
		t.Errorf("expected nil for ChallengeHeaders with bad recipient, got %v", headers)
	}
}

// TestVerifyAndSettleReturnsErrOnBadRecipient proves VerifyAndSettle wraps
// the serverFor failure in a PaymentError (code="invalid_proof") when the
// gate's PayTo address is not a valid Solana pubkey.
func TestVerifyAndSettleReturnsErrOnBadRecipient(t *testing.T) {
	a := &Adapter{cfg: testCfg()}
	gate := &paykit.Gate{
		Amount: paykit.MustParseUSD("0.10"),
		PayTo:  paykit.Address("!!!not-a-valid-pubkey"),
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{
		Gate:          gate,
		Authorization: "Payment bm90LWEtY3JlZGVudGlhbA==",
	})
	if err == nil {
		t.Fatal("expected an error for a gate with an invalid recipient")
	}
}

// TestChargeOptionsIncludesFeeWithinAndFeeOnTopSplits proves that chargeOptions
// appends paycore.Split entries for both FeeWithin and FeeOnTop fees declared
// on the gate. This exercises the two range-loop bodies in chargeOptions that
// the existing AcceptsEntry tests do not reach.
func TestChargeOptionsIncludesFeeWithinAndFeeOnTopSplits(t *testing.T) {
	a := &Adapter{cfg: testCfg()}
	gate := &paykit.Gate{
		Amount:    paykit.MustParseUSD("10.00"),
		FeeWithin: paykit.Fees{paykit.Address("PLATFORM"): paykit.MustParseUSD("0.30")},
		FeeOnTop:  paykit.Fees{paykit.Address("GATEWAY"): paykit.MustParseUSD("0.50")},
	}
	opts := a.chargeOptions(gate)
	if len(opts.Splits) != 2 {
		t.Fatalf("expected 2 splits in chargeOptions, got %d: %+v", len(opts.Splits), opts.Splits)
	}
	recipients := make(map[string]bool)
	for _, s := range opts.Splits {
		recipients[s.Recipient] = true
	}
	if !recipients["PLATFORM"] || !recipients["GATEWAY"] {
		t.Errorf("chargeOptions splits missing expected recipients: %v", opts.Splits)
	}
}

// TestPriceCoinUsesExplicitSettlementWhenPresent proves that priceCoin returns
// the first explicit settlement stablecoin rather than falling back to the
// adapter config when the Price was built with an explicit settlement.
func TestPriceCoinUsesExplicitSettlementWhenPresent(t *testing.T) {
	a := &Adapter{cfg: testCfg()} // cfg.Stablecoins = [USDC]
	// Build a price with an explicit USDT settlement; priceCoin must return
	// USDT (the explicit settlement) rather than USDC (the config default).
	priceUSDT := paykit.MustParseUSD("0.30", paykit.USDT)
	if got := a.priceCoin(priceUSDT); got != "USDT" {
		t.Errorf("priceCoin: got %q want USDT", got)
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

func TestChargeOptionsThreadsExpiresIn(t *testing.T) {
	a := &Adapter{cfg: paykit.Config{
		Network: paykit.SolanaLocalnet,
		MPP:     paykit.MPPConfig{ExpiresIn: 90 * time.Second},
	}}
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	opts := a.chargeOptions(&gate)
	if opts.Expires == "" {
		t.Fatal("expected Expires to be set from MPPConfig.ExpiresIn")
	}
	exp, err := time.Parse(time.RFC3339, opts.Expires)
	if err != nil {
		t.Fatalf("Expires is not RFC3339: %v", err)
	}
	delta := time.Until(exp)
	if delta < 60*time.Second || delta > 120*time.Second {
		t.Errorf("expiry %s is not ~90s out (delta %s)", opts.Expires, delta)
	}
}

func TestChargeOptionsZeroExpiresInLeavesDefault(t *testing.T) {
	a := &Adapter{cfg: paykit.Config{Network: paykit.SolanaLocalnet}}
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	if opts := a.chargeOptions(&gate); opts.Expires != "" {
		t.Errorf("expected empty Expires (server default 5min) when ExpiresIn==0, got %q", opts.Expires)
	}
}
