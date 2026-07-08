package client

import (
	"fmt"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// failingSigner satisfies VoucherSigner but always fails to sign, exercising
// the signing-error propagation paths.
type failingSigner struct {
	// pub is the public key the signer reports even though Sign always fails.
	pub solana.PublicKey
}

func (f failingSigner) PublicKey() solana.PublicKey { return f.pub }
func (f failingSigner) Sign([]byte) (solana.Signature, error) {
	return solana.Signature{}, fmt.Errorf("signer unavailable")
}

func TestSigningErrorPropagates(t *testing.T) {
	channel := testutil.NewPrivateKey().PublicKey()
	s := NewActiveSession(channel, failingSigner{pub: testutil.NewPrivateKey().PublicKey()})

	if _, err := s.PrepareVoucher(10); err == nil {
		t.Fatal("prepare voucher should surface the signing error")
	}
	if _, err := s.SignVoucher(10); err == nil {
		t.Fatal("sign voucher should surface the signing error")
	}
	if _, err := s.VoucherAction(10); err == nil {
		t.Fatal("voucher action should surface the signing error")
	}
	if _, err := s.CloseAction(10); err == nil {
		t.Fatal("close action with increment should surface the signing error")
	}
	// A zero-increment close never signs, so it must still succeed.
	if _, err := s.CloseAction(0); err != nil {
		t.Fatalf("close action without increment: %v", err)
	}
}

// newSession builds an ActiveSession over a fresh keypair channel and signer.
func newSession(t *testing.T) (*ActiveSession, solana.PrivateKey) {
	t.Helper()
	channel := testutil.NewPrivateKey().PublicKey()
	signer := testutil.NewPrivateKey()
	return NewActiveSession(channel, signer), signer
}

func TestNewActiveSessionDefaults(t *testing.T) {
	s, signer := newSession(t)
	if s.Cumulative() != 0 {
		t.Fatalf("cumulative = %d, want 0", s.Cumulative())
	}
	if s.Nonce() != 0 {
		t.Fatalf("nonce = %d, want 0", s.Nonce())
	}
	if s.ExpiresAt() != intents.DefaultSessionExpiresAt {
		t.Fatalf("expiresAt = %d, want %d", s.ExpiresAt(), intents.DefaultSessionExpiresAt)
	}
	if got, want := s.AuthorizedSigner(), signer.PublicKey().String(); got != want {
		t.Fatalf("authorizedSigner = %q, want %q", got, want)
	}
	if s.ChannelIDString() != s.ChannelID().String() {
		t.Fatalf("channelIdString = %q, want %q", s.ChannelIDString(), s.ChannelID().String())
	}
}

func TestNewActiveSessionAtAndSetExpiresAt(t *testing.T) {
	channel := testutil.NewPrivateKey().PublicKey()
	signer := testutil.NewPrivateKey()
	s := NewActiveSessionAt(channel, signer, 1234)

	first, err := s.PrepareIncrement(10)
	if err != nil {
		t.Fatalf("prepare increment: %v", err)
	}
	if first.Data.ExpiresAt != 1234 {
		t.Fatalf("expiresAt = %d, want 1234", first.Data.ExpiresAt)
	}
	// PrepareIncrement does not advance the watermark.
	if s.Cumulative() != 0 {
		t.Fatalf("cumulative advanced to %d after prepare", s.Cumulative())
	}

	s.SetExpiresAt(5678)
	second, err := s.PrepareIncrement(10)
	if err != nil {
		t.Fatalf("prepare increment after set: %v", err)
	}
	if second.Data.ExpiresAt != 5678 {
		t.Fatalf("expiresAt = %d, want 5678", second.Data.ExpiresAt)
	}
}

func TestSignIncrementIncreasesCumulative(t *testing.T) {
	s, _ := newSession(t)
	v, err := s.SignIncrement(100)
	if err != nil {
		t.Fatalf("sign increment: %v", err)
	}
	if s.Cumulative() != 100 {
		t.Fatalf("cumulative = %d, want 100", s.Cumulative())
	}
	if v.Data.Cumulative != "100" {
		t.Fatalf("voucher cumulative = %q, want \"100\"", v.Data.Cumulative)
	}
	if v.Data.Nonce == nil || *v.Data.Nonce != 1 {
		t.Fatalf("voucher nonce = %v, want 1", v.Data.Nonce)
	}
}

func TestSignVoucherAbsolute(t *testing.T) {
	s, _ := newSession(t)
	if _, err := s.SignIncrement(50); err != nil {
		t.Fatalf("sign increment: %v", err)
	}
	v, err := s.SignVoucher(200)
	if err != nil {
		t.Fatalf("sign voucher: %v", err)
	}
	if s.Cumulative() != 200 {
		t.Fatalf("cumulative = %d, want 200", s.Cumulative())
	}
	if v.Data.Cumulative != "200" {
		t.Fatalf("voucher cumulative = %q, want \"200\"", v.Data.Cumulative)
	}
}

func TestPrepareAndRecordVoucherAreSeparate(t *testing.T) {
	s, _ := newSession(t)
	prepared, err := s.PrepareIncrement(75)
	if err != nil {
		t.Fatalf("prepare increment: %v", err)
	}
	if prepared.Data.Cumulative != "75" {
		t.Fatalf("prepared cumulative = %q, want \"75\"", prepared.Data.Cumulative)
	}
	if prepared.Data.Nonce == nil || *prepared.Data.Nonce != 1 {
		t.Fatalf("prepared nonce = %v, want 1", prepared.Data.Nonce)
	}
	if s.Cumulative() != 0 {
		t.Fatalf("cumulative advanced to %d before record", s.Cumulative())
	}

	if err := s.RecordVoucher(prepared); err != nil {
		t.Fatalf("record voucher: %v", err)
	}
	if s.Cumulative() != 75 {
		t.Fatalf("cumulative = %d, want 75", s.Cumulative())
	}
	// Re-recording the same voucher must be rejected (non-increasing).
	if err := s.RecordVoucher(prepared); err == nil {
		t.Fatal("re-recording the same voucher should fail")
	}
}

func TestRecordVoucherInvalidAndMissingNonce(t *testing.T) {
	s, _ := newSession(t)

	bad := intents.SignedVoucher{
		Data: intents.VoucherData{
			ChannelID:  s.ChannelIDString(),
			Cumulative: "not-a-number",
			ExpiresAt:  intents.DefaultSessionExpiresAt,
		},
		Signature: "sig",
	}
	if err := s.RecordVoucher(bad); err == nil {
		t.Fatal("recording an invalid cumulative should fail")
	}

	withoutNonce := intents.SignedVoucher{
		Data: intents.VoucherData{
			ChannelID:  s.ChannelIDString(),
			Cumulative: "15",
			ExpiresAt:  intents.DefaultSessionExpiresAt,
		},
		Signature: "sig",
	}
	if err := s.RecordVoucher(withoutNonce); err != nil {
		t.Fatalf("record voucher without nonce: %v", err)
	}
	if s.Cumulative() != 15 {
		t.Fatalf("cumulative = %d, want 15", s.Cumulative())
	}
	if s.Nonce() != 1 {
		t.Fatalf("nonce = %d, want 1", s.Nonce())
	}
}

func TestRecordVoucherRejectsForeignChannel(t *testing.T) {
	s, _ := newSession(t)
	foreign := intents.SignedVoucher{
		Data: intents.VoucherData{
			ChannelID:  solana.NewWallet().PublicKey().String(),
			Cumulative: "100",
			ExpiresAt:  intents.DefaultSessionExpiresAt,
		},
		Signature: "sig",
	}
	if err := s.RecordVoucher(foreign); err == nil || !strings.Contains(err.Error(), "does not match active session") {
		t.Fatalf("recording a foreign-channel voucher should fail, got %v", err)
	}
	if s.Cumulative() != 0 {
		t.Fatalf("watermark advanced on foreign voucher: %d", s.Cumulative())
	}
}

func TestReconcileSettledAdvancesButNeverRegresses(t *testing.T) {
	s, _ := newSession(t)
	s.ReconcileSettled(100)
	if s.Cumulative() != 100 {
		t.Fatalf("cumulative = %d, want 100", s.Cumulative())
	}
	if s.Nonce() != 1 {
		t.Fatalf("nonce = %d, want 1 (advance bumps nonce)", s.Nonce())
	}
	s.ReconcileSettled(40) // stale, must not regress or touch the nonce
	if s.Cumulative() != 100 || s.Nonce() != 1 {
		t.Fatalf("stale reconcile changed state: cumulative=%d nonce=%d", s.Cumulative(), s.Nonce())
	}
	s.ReconcileSettled(250)
	if s.Cumulative() != 250 || s.Nonce() != 2 {
		t.Fatalf("cumulative=%d nonce=%d, want 250/2", s.Cumulative(), s.Nonce())
	}
}

func TestDeliveryAfterReplayDoesNotReuseSettledNonce(t *testing.T) {
	// After a lost-response replay reconciles to the settled cumulative, the
	// next prepared voucher must carry a fresh nonce, not the settled one.
	s, _ := newSession(t)
	replayed, err := s.PrepareIncrement(100)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	s.ReconcileSettled(100)
	next, err := s.PrepareIncrement(50)
	if err != nil {
		t.Fatalf("prepare next: %v", err)
	}
	if next.Data.Nonce == nil || replayed.Data.Nonce == nil || *next.Data.Nonce <= *replayed.Data.Nonce {
		t.Fatalf("next nonce %v must exceed replayed nonce %v", next.Data.Nonce, replayed.Data.Nonce)
	}
}

func TestRecordVoucherKeepsLargerNonce(t *testing.T) {
	s, _ := newSession(t)
	nonce := uint64(7)
	v := intents.SignedVoucher{
		Data: intents.VoucherData{
			ChannelID:  s.ChannelIDString(),
			Cumulative: "10",
			ExpiresAt:  intents.DefaultSessionExpiresAt,
			Nonce:      &nonce,
		},
		Signature: "sig",
	}
	if err := s.RecordVoucher(v); err != nil {
		t.Fatalf("record voucher: %v", err)
	}
	if s.Nonce() != 7 {
		t.Fatalf("nonce = %d, want 7 (voucher nonce wins)", s.Nonce())
	}
}

func TestSignVoucherRejectsNonIncreasing(t *testing.T) {
	s, _ := newSession(t)
	if _, err := s.SignIncrement(100); err != nil {
		t.Fatalf("sign increment: %v", err)
	}
	if _, err := s.SignVoucher(100); err == nil {
		t.Fatal("equal cumulative should be rejected")
	}
	if _, err := s.SignVoucher(50); err == nil {
		t.Fatal("lower cumulative should be rejected")
	}
}

func TestSignVoucherZeroRejected(t *testing.T) {
	s, _ := newSession(t)
	if _, err := s.SignVoucher(0); err == nil {
		t.Fatal("zero cumulative should be rejected")
	}
}

func TestPrepareVoucherRejectsNonIncreasing(t *testing.T) {
	s, _ := newSession(t)
	if _, err := s.SignIncrement(100); err != nil {
		t.Fatalf("sign increment: %v", err)
	}
	if _, err := s.PrepareVoucher(100); err == nil {
		t.Fatal("prepare equal cumulative should be rejected")
	}
}

func TestSignIncrementOverflowRejected(t *testing.T) {
	s, _ := newSession(t)
	if _, err := s.SignVoucher(^uint64(0)); err != nil {
		t.Fatalf("sign max voucher: %v", err)
	}
	if _, err := s.SignIncrement(1); err == nil {
		t.Fatal("increment past u64 max should be rejected")
	}
	if _, err := s.PrepareIncrement(1); err == nil {
		t.Fatal("prepare increment past u64 max should be rejected")
	}
}

func TestNonceIncrementsPerVoucher(t *testing.T) {
	s, _ := newSession(t)
	first, err := s.SignIncrement(10)
	if err != nil {
		t.Fatalf("sign increment 1: %v", err)
	}
	second, err := s.SignIncrement(10)
	if err != nil {
		t.Fatalf("sign increment 2: %v", err)
	}
	if first.Data.Nonce == nil || *first.Data.Nonce != 1 {
		t.Fatalf("first voucher nonce = %v, want 1", first.Data.Nonce)
	}
	if second.Data.Nonce == nil || *second.Data.Nonce != 2 {
		t.Fatalf("second voucher nonce = %v, want 2", second.Data.Nonce)
	}
}

func TestVoucherChannelIDMatchesSession(t *testing.T) {
	s, _ := newSession(t)
	want := s.ChannelIDString()
	v, err := s.SignIncrement(100)
	if err != nil {
		t.Fatalf("sign increment: %v", err)
	}
	if v.Data.ChannelID != want {
		t.Fatalf("voucher channelId = %q, want %q", v.Data.ChannelID, want)
	}
}

// TestVoucherSignatureVerifies signs an increment and confirms the base58
// signature verifies against the authorizedSigner pubkey over the exact 50-byte
// VoucherMessageBytes preimage.
func TestVoucherSignatureVerifies(t *testing.T) {
	channel := testutil.NewPrivateKey().PublicKey()
	signer := testutil.NewPrivateKey()
	s := NewActiveSession(channel, signer)

	v, err := s.SignIncrement(123_456)
	if err != nil {
		t.Fatalf("sign increment: %v", err)
	}

	preimage, err := paymentchannels.VoucherMessageBytes(channel, 123_456, intents.DefaultSessionExpiresAt)
	if err != nil {
		t.Fatalf("voucher message bytes: %v", err)
	}
	if len(preimage) != 50 {
		t.Fatalf("preimage length = %d, want 50", len(preimage))
	}

	sig, err := solana.SignatureFromBase58(v.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !sig.Verify(signer.PublicKey(), preimage) {
		t.Fatal("signature does not verify against authorizedSigner over the voucher preimage")
	}
	// A tampered preimage must not verify.
	preimage[0] ^= 0xFF
	if sig.Verify(signer.PublicKey(), preimage) {
		t.Fatal("signature verified against a tampered preimage")
	}
}

func TestVoucherActionFields(t *testing.T) {
	s, _ := newSession(t)
	action, err := s.VoucherAction(33)
	if err != nil {
		t.Fatalf("voucher action: %v", err)
	}
	if action.Voucher == nil {
		t.Fatal("expected a Voucher action")
	}
	if action.Voucher.Voucher.Data.Cumulative != "33" {
		t.Fatalf("voucher cumulative = %q, want \"33\"", action.Voucher.Voucher.Data.Cumulative)
	}
	if action.Voucher.Voucher.Data.ChannelID != s.ChannelIDString() {
		t.Fatalf("voucher channelId = %q, want %q", action.Voucher.Voucher.Data.ChannelID, s.ChannelIDString())
	}
}

func TestOpenActionFields(t *testing.T) {
	s, _ := newSession(t)
	channelID := s.ChannelIDString()
	authorizedSigner := s.AuthorizedSigner()
	action := s.OpenAction(1_000_000, "txsig123")
	if action.Open == nil {
		t.Fatal("expected an Open action")
	}
	p := action.Open
	if p.Mode != intents.SessionModePush {
		t.Fatalf("mode = %q, want push", p.Mode)
	}
	if p.Deposit == nil || *p.Deposit != "1000000" {
		t.Fatalf("deposit = %v, want \"1000000\"", p.Deposit)
	}
	if p.Signature != "txsig123" {
		t.Fatalf("signature = %q, want txsig123", p.Signature)
	}
	if p.ChannelID == nil || *p.ChannelID != channelID {
		t.Fatalf("channelId = %v, want %q", p.ChannelID, channelID)
	}
	if p.AuthorizedSigner != authorizedSigner {
		t.Fatalf("authorizedSigner = %q, want %q", p.AuthorizedSigner, authorizedSigner)
	}
}

func TestOpenPaymentChannelActionFields(t *testing.T) {
	s, _ := newSession(t)
	channelID := s.ChannelIDString()
	action := s.OpenPaymentChannelAction(9_000, "payer", "payee", "mint", 42, 60, 321_654_987, "open-sig")
	if action.Open == nil {
		t.Fatal("expected an Open action")
	}
	p := action.Open
	if p.Mode != intents.SessionModePush {
		t.Fatalf("mode = %q, want push", p.Mode)
	}
	if p.ChannelID == nil || *p.ChannelID != channelID {
		t.Fatalf("channelId = %v, want %q", p.ChannelID, channelID)
	}
	if p.Deposit == nil || *p.Deposit != "9000" {
		t.Fatalf("deposit = %v, want \"9000\"", p.Deposit)
	}
	if p.Payer == nil || *p.Payer != "payer" {
		t.Fatalf("payer = %v, want \"payer\"", p.Payer)
	}
	if p.Payee == nil || *p.Payee != "payee" {
		t.Fatalf("payee = %v, want \"payee\"", p.Payee)
	}
	if p.Mint == nil || *p.Mint != "mint" {
		t.Fatalf("mint = %v, want \"mint\"", p.Mint)
	}
	if p.Salt == nil || *p.Salt != 42 {
		t.Fatalf("salt = %v, want 42", p.Salt)
	}
	if p.GracePeriod == nil || *p.GracePeriod != 60 {
		t.Fatalf("gracePeriod = %v, want 60", p.GracePeriod)
	}
	if p.RecentSlot == nil || *p.RecentSlot != 321_654_987 {
		t.Fatalf("recentSlot = %v, want 321654987", p.RecentSlot)
	}
	if p.Signature != "open-sig" {
		t.Fatalf("signature = %q, want open-sig", p.Signature)
	}
}

func TestOpenPaymentChannelActionPullMode(t *testing.T) {
	s, _ := newSession(t)
	channelID := s.ChannelIDString()
	action := s.OpenPaymentChannelActionWithMode(
		intents.SessionModePull, 9_000, "payer", "payee", "mint", 42, 60, 321_654_987, "pending")
	if action.Open == nil {
		t.Fatal("expected an Open action")
	}
	p := action.Open
	if p.Mode != intents.SessionModePull {
		t.Fatalf("mode = %q, want pull", p.Mode)
	}
	if p.ChannelID == nil || *p.ChannelID != channelID {
		t.Fatalf("channelId = %v, want %q", p.ChannelID, channelID)
	}
	if p.Deposit == nil || *p.Deposit != "9000" {
		t.Fatalf("deposit = %v, want \"9000\"", p.Deposit)
	}
	if p.TokenAccount != nil {
		t.Fatalf("tokenAccount = %v, want nil", p.TokenAccount)
	}
	if p.ApprovedAmount != nil {
		t.Fatalf("approvedAmount = %v, want nil", p.ApprovedAmount)
	}
}

func TestOpenPullActionFields(t *testing.T) {
	s, _ := newSession(t)
	channelID := s.ChannelIDString() // used as tokenAccount in pull mode
	authorizedSigner := s.AuthorizedSigner()
	action := s.OpenPullAction(5_000_000, "wallet123", "approvesig")
	if action.Open == nil {
		t.Fatal("expected an Open action")
	}
	p := action.Open
	if p.Mode != intents.SessionModePull {
		t.Fatalf("mode = %q, want pull", p.Mode)
	}
	if p.ApprovedAmount == nil || *p.ApprovedAmount != "5000000" {
		t.Fatalf("approvedAmount = %v, want \"5000000\"", p.ApprovedAmount)
	}
	if p.Signature != "approvesig" {
		t.Fatalf("signature = %q, want approvesig", p.Signature)
	}
	if p.TokenAccount == nil || *p.TokenAccount != channelID {
		t.Fatalf("tokenAccount = %v, want %q", p.TokenAccount, channelID)
	}
	if p.Owner == nil || *p.Owner != "wallet123" {
		t.Fatalf("owner = %v, want \"wallet123\"", p.Owner)
	}
	if p.AuthorizedSigner != authorizedSigner {
		t.Fatalf("authorizedSigner = %q, want %q", p.AuthorizedSigner, authorizedSigner)
	}
	if p.ChannelID != nil {
		t.Fatalf("channelId = %v, want nil", p.ChannelID)
	}
	if p.Deposit != nil {
		t.Fatalf("deposit = %v, want nil", p.Deposit)
	}
}

func TestTopUpActionFields(t *testing.T) {
	s, _ := newSession(t)
	action := s.TopUpAction(5_000_000, "topuptx")
	if action.TopUp == nil {
		t.Fatal("expected a TopUp action")
	}
	p := action.TopUp
	if p.ChannelID != s.ChannelIDString() {
		t.Fatalf("channelId = %q, want %q", p.ChannelID, s.ChannelIDString())
	}
	if p.NewDeposit != "5000000" {
		t.Fatalf("newDeposit = %q, want \"5000000\"", p.NewDeposit)
	}
	if p.Signature != "topuptx" {
		t.Fatalf("signature = %q, want topuptx", p.Signature)
	}
}

func TestCloseActionNoFinalIncrement(t *testing.T) {
	s, _ := newSession(t)
	action, err := s.CloseAction(0)
	if err != nil {
		t.Fatalf("close action: %v", err)
	}
	if action.Close == nil {
		t.Fatal("expected a Close action")
	}
	if action.Close.Voucher != nil {
		t.Fatal("close with zero increment should carry no voucher")
	}
	if action.Close.ChannelID != s.ChannelIDString() {
		t.Fatalf("channelId = %q, want %q", action.Close.ChannelID, s.ChannelIDString())
	}
}

func TestCloseActionWithFinalIncrement(t *testing.T) {
	s, _ := newSession(t)
	if _, err := s.SignIncrement(100); err != nil {
		t.Fatalf("sign increment: %v", err)
	}
	action, err := s.CloseAction(50)
	if err != nil {
		t.Fatalf("close action: %v", err)
	}
	if action.Close == nil || action.Close.Voucher == nil {
		t.Fatal("expected a Close action with a voucher")
	}
	if action.Close.Voucher.Data.Cumulative != "150" {
		t.Fatalf("final voucher cumulative = %q, want \"150\"", action.Close.Voucher.Data.Cumulative)
	}
}

// TestSerializeSessionCredentialRoundTrip serializes a voucher action into an
// Authorization header and confirms it round-trips through ParseAuthorization
// back into the same SessionAction.
func TestSerializeSessionCredentialRoundTrip(t *testing.T) {
	s, _ := newSession(t)
	challenge := newSessionChallenge(t, "100000")

	action, err := s.VoucherAction(500)
	if err != nil {
		t.Fatalf("voucher action: %v", err)
	}
	header, err := SerializeSessionCredential(challenge, action)
	if err != nil {
		t.Fatalf("serialize credential: %v", err)
	}
	if !strings.HasPrefix(header, core.PaymentScheme+" ") {
		t.Fatalf("header = %q, want %q prefix", header, core.PaymentScheme)
	}

	credential, err := core.ParseAuthorization(header)
	if err != nil {
		t.Fatalf("parse authorization: %v", err)
	}
	if credential.Challenge.ID != challenge.ID {
		t.Fatalf("echoed challenge id = %q, want %q", credential.Challenge.ID, challenge.ID)
	}

	var decoded intents.SessionAction
	if err := credential.PayloadAs(&decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decoded.Voucher == nil {
		t.Fatal("decoded action is not a voucher")
	}
	if decoded.Voucher.Voucher.Data.Cumulative != "500" {
		t.Fatalf("decoded cumulative = %q, want \"500\"", decoded.Voucher.Voucher.Data.Cumulative)
	}
	if decoded.Voucher.Voucher.Signature != action.Voucher.Voucher.Signature {
		t.Fatal("decoded voucher signature does not match")
	}
}

// TestParseSessionChallenge parses a WWW-Authenticate session challenge and
// decodes the embedded SessionRequest.
func TestParseSessionChallenge(t *testing.T) {
	challenge := newSessionChallenge(t, "250000")
	headerValue, err := core.FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format www-authenticate: %v", err)
	}

	parsed, request, err := ParseSessionChallenge(headerValue)
	if err != nil {
		t.Fatalf("parse session challenge: %v", err)
	}
	if parsed.ID != challenge.ID {
		t.Fatalf("parsed id = %q, want %q", parsed.ID, challenge.ID)
	}
	if request.Cap != "250000" {
		t.Fatalf("request cap = %q, want \"250000\"", request.Cap)
	}
	if request.Currency != "USDC" {
		t.Fatalf("request currency = %q, want \"USDC\"", request.Currency)
	}
}

func TestParseSessionChallengeRejectsNonSession(t *testing.T) {
	chargeRequest, err := core.NewBase64URLJSONValue(map[string]any{
		"amount":    "1000",
		"currency":  "USDC",
		"recipient": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("encode charge request: %v", err)
	}
	challenge := core.NewChallengeWithSecret(
		"secret", "api", core.NewMethodName("solana"), core.NewIntentName("charge"), chargeRequest)
	headerValue, err := core.FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format www-authenticate: %v", err)
	}
	if _, _, err := ParseSessionChallenge(headerValue); err == nil {
		t.Fatal("a charge challenge should be rejected by ParseSessionChallenge")
	}
}

func TestParseSessionChallengeRejectsMalformedHeader(t *testing.T) {
	if _, _, err := ParseSessionChallenge("Basic realm=\"x\""); err == nil {
		t.Fatal("a non-Payment header should be rejected")
	}
}

// TestSerializeSessionCredentialRejectsEmptyAction confirms the credential
// serializer surfaces the SessionAction marshal error when no variant is set.
func TestSerializeSessionCredentialRejectsEmptyAction(t *testing.T) {
	challenge := newSessionChallenge(t, "1000")
	if _, err := SerializeSessionCredential(challenge, intents.SessionAction{}); err == nil {
		t.Fatal("an empty session action should fail to serialize")
	}
}

// TestParseSessionChallengeRejectsUndecodableRequest confirms a session
// challenge whose request bytes are not a SessionRequest object is rejected.
func TestParseSessionChallengeRejectsUndecodableRequest(t *testing.T) {
	// A bare JSON array is valid base64url JSON but not a SessionRequest object.
	encoded, err := core.NewBase64URLJSONValue([]string{"not", "an", "object"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	challenge := core.NewChallengeWithSecret(
		"secret", "api", core.NewMethodName("solana"), core.NewIntentName("session"), encoded)
	headerValue, err := core.FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	if _, _, err := ParseSessionChallenge(headerValue); err == nil {
		t.Fatal("a non-object session request should be rejected")
	}
}

// TestParseCumulativeRejectsInvalid exercises the watermark parser guard
// directly, including negative, overflowing, and non-numeric inputs.
func TestParseCumulativeRejectsInvalid(t *testing.T) {
	for _, bad := range []string{"-1", "18446744073709551616", "abc", ""} {
		if _, err := parseCumulative(bad); err == nil {
			t.Fatalf("expected rejection for %q", bad)
		}
	}
	v, err := parseCumulative("18446744073709551615")
	if err != nil || v != ^uint64(0) {
		t.Fatalf("u64 max should parse: %d %v", v, err)
	}
}

// newSessionChallenge builds an HMAC-bound session challenge carrying a
// SessionRequest with the given cap.
func newSessionChallenge(t *testing.T, sessionCap string) core.PaymentChallenge {
	t.Helper()
	request := intents.SessionRequest{
		Cap:       sessionCap,
		Currency:  "USDC",
		Operator:  testutil.NewPrivateKey().PublicKey().String(),
		Recipient: testutil.NewPrivateKey().PublicKey().String(),
	}
	encoded, err := core.NewBase64URLJSONValue(request)
	if err != nil {
		t.Fatalf("encode session request: %v", err)
	}
	return core.NewChallengeWithSecret(
		"secret", "api", core.NewMethodName("solana"), core.NewIntentName("session"), encoded)
}
