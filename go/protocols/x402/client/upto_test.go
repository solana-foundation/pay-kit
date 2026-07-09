package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

func TestRandomSalt(t *testing.T) {
	s1, err := randomSalt()
	if err != nil {
		t.Fatalf("randomSalt: %v", err)
	}
	s2, err := randomSalt()
	if err != nil {
		t.Fatalf("randomSalt: %v", err)
	}
	if s1 == s2 {
		t.Fatal("expected different salts")
	}
}

func uptoRequirements(receiverAuthorizer solana.PublicKey) *x402.UptoRequirements {
	return uptoRequirementsWithRoles(receiverAuthorizer, receiverAuthorizer)
}

func uptoRequirementsWithRoles(feePayer, receiverAuthorizer solana.PublicKey) *x402.UptoRequirements {
	decimals := uint8(6)
	return &x402.UptoRequirements{
		Scheme:            x402.UptoScheme,
		Network:           "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Amount:            "1000000",
		Asset:             "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		PayTo:             "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
		MaxTimeoutSeconds: 300,
		Extra: x402.UptoExtra{
			Decimals:           &decimals,
			TokenProgram:       paycore.TokenProgram,
			FeePayer:           feePayer.String(),
			ReceiverAuthorizer: receiverAuthorizer.String(),
			WithdrawDelay:      x402.DefaultUptoWithdrawDelaySeconds,
			RecentBlockhash:    "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h",
			RecentSlot:         "55555",
		},
	}
}

type testSigner struct{ priv solana.PrivateKey }

func (s testSigner) PublicKey() solana.PublicKey { return s.priv.PublicKey() }
func (s testSigner) Sign(msg []byte) (solana.Signature, error) {
	return s.priv.Sign(msg)
}

func TestBuildUptoPayload(t *testing.T) {
	priv := testutil.NewPrivateKey()
	feePayer := testutil.NewPrivateKey().PublicKey()
	receiverAuthorizer := testutil.NewPrivateKey().PublicKey()
	signer := testSigner{priv}
	req := uptoRequirementsWithRoles(feePayer, receiverAuthorizer)
	payload, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err != nil {
		t.Fatalf("BuildUptoPayload: %v", err)
	}
	if payload.MaxAmount != "1000000" {
		t.Fatalf("maxAmount = %q", payload.MaxAmount)
	}
	if payload.Nonce == "" || payload.Nonce == "n-1" {
		t.Fatalf("nonce = %q, want open salt decimal", payload.Nonce)
	}
	if payload.OpenSlot != "55555" {
		t.Fatalf("openSlot = %q, want 55555", payload.OpenSlot)
	}
	if payload.OpenTransaction == "" {
		t.Fatal("openTransaction is empty")
	}
	if payload.From != priv.PublicKey().String() {
		t.Fatalf("from = %s, want payer %s", payload.From, priv.PublicKey())
	}
	if payload.AuthorizedSigner != receiverAuthorizer.String() {
		t.Fatalf("authorizedSigner = %s, want receiverAuthorizer %s", payload.AuthorizedSigner, receiverAuthorizer)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.OpenTransaction)
	if err != nil {
		t.Fatalf("DecodeTransactionBase64: %v", err)
	}
	if !tx.Message.AccountKeys[0].Equals(feePayer) {
		t.Fatalf("fee payer = %s, want %s", tx.Message.AccountKeys[0], feePayer)
	}
	openIx := tx.Message.Instructions[0]
	payerFromOpen := tx.Message.AccountKeys[openIx.Accounts[0]]
	rentPayerFromOpen := tx.Message.AccountKeys[openIx.Accounts[1]]
	payeeFromOpen := tx.Message.AccountKeys[openIx.Accounts[2]]
	authorizedSignerFromOpen := tx.Message.AccountKeys[openIx.Accounts[4]]
	if !payerFromOpen.Equals(priv.PublicKey()) {
		t.Fatalf("open payer = %s, want %s", payerFromOpen, priv.PublicKey())
	}
	if !rentPayerFromOpen.Equals(feePayer) {
		t.Fatalf("open rent_payer = %s, want fee payer %s", rentPayerFromOpen, feePayer)
	}
	if !payeeFromOpen.Equals(receiverAuthorizer) {
		t.Fatalf("open payee = %s, want receiverAuthorizer %s", payeeFromOpen, receiverAuthorizer)
	}
	if !authorizedSignerFromOpen.Equals(receiverAuthorizer) {
		t.Fatalf("open authorized_signer = %s, want receiverAuthorizer %s", authorizedSignerFromOpen, receiverAuthorizer)
	}
}

func TestBuildUptoPayloadUsesCanonicalChannelProgramForChannelID(t *testing.T) {
	priv := testutil.NewPrivateKey()
	receiverAuthorizer := testutil.NewPrivateKey().PublicKey()
	signer := testSigner{priv}
	req := uptoRequirements(receiverAuthorizer)

	payload, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err != nil {
		t.Fatalf("BuildUptoPayload: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.OpenTransaction)
	if err != nil {
		t.Fatalf("DecodeTransactionBase64: %v", err)
	}
	channelFromPayload := solana.MustPublicKeyFromBase58(payload.ChannelID)
	openIx := tx.Message.Instructions[0]
	channelFromOpen := tx.Message.AccountKeys[openIx.Accounts[5]]
	if !channelFromOpen.Equals(channelFromPayload) {
		t.Fatalf("open channel account = %s, payload channelId = %s", channelFromOpen, channelFromPayload)
	}
	want, _, err := paymentchannels.FindChannelPDAForProgram(
		priv.PublicKey(),
		receiverAuthorizer,
		solana.MustPublicKeyFromBase58(req.Asset),
		receiverAuthorizer,
		mustReadOpenSalt(t, tx),
		55_555,
		paymentchannels.ProgramPubkey(),
	)
	if err != nil {
		t.Fatalf("FindChannelPDAForProgram: %v", err)
	}
	if !channelFromPayload.Equals(want) {
		t.Fatalf("payload channelId = %s, want canonical-program PDA %s", channelFromPayload, want)
	}
}

func mustReadOpenSalt(t *testing.T, tx *solana.Transaction) uint64 {
	t.Helper()
	if len(tx.Message.Instructions) != 1 {
		t.Fatalf("instructions = %d, want 1", len(tx.Message.Instructions))
	}
	if len(tx.Message.Instructions[0].Data) < 9 {
		t.Fatalf("open instruction data too short: %d", len(tx.Message.Instructions[0].Data))
	}
	return uint64(tx.Message.Instructions[0].Data[1]) |
		uint64(tx.Message.Instructions[0].Data[2])<<8 |
		uint64(tx.Message.Instructions[0].Data[3])<<16 |
		uint64(tx.Message.Instructions[0].Data[4])<<24 |
		uint64(tx.Message.Instructions[0].Data[5])<<32 |
		uint64(tx.Message.Instructions[0].Data[6])<<40 |
		uint64(tx.Message.Instructions[0].Data[7])<<48 |
		uint64(tx.Message.Instructions[0].Data[8])<<56
}

func TestBuildUptoPayloadRejectsBadAmount(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Amount = "abc"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for bad amount")
	}
}

func TestBuildUptoPayloadRejectsBadPayTo(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.PayTo = "not-a-pubkey"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for bad payTo")
	}
}

func TestBuildUptoPayloadRejectsBadAsset(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Asset = "not-a-pubkey"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for bad asset")
	}
}

func TestBuildUptoPayloadRejectsBadFeePayer(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.FeePayer = "not-a-pubkey"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for bad feePayer")
	}
}

func TestBuildUptoPayloadRejectsBadReceiverAuthorizer(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.ReceiverAuthorizer = "not-a-pubkey"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for bad receiverAuthorizer")
	}
}

func TestBuildUptoPayloadRejectsMissingRecentBlockhash(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.RecentBlockhash = ""
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for missing blockhash")
	}
}

func TestBuildUptoPayloadRejectsBadRecentBlockhash(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.RecentBlockhash = "invalid"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for bad blockhash")
	}
}

func TestBuildUptoPayloadDefaultsTokenProgram(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.TokenProgram = "" // trigger default
	payload, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err != nil {
		t.Fatalf("BuildUptoPayload: %v", err)
	}
	if payload.OpenTransaction == "" {
		t.Fatal("openTransaction is empty")
	}
}

func TestBuildUptoPayloadRejectsBadTokenProgram(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.TokenProgram = "invalid"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for bad token program")
	}
}

func TestBuildUptoPayloadRejectsMissingWithdrawDelay(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.WithdrawDelay = 0
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil || !strings.Contains(err.Error(), "withdrawDelay") {
		t.Fatalf("expected missing withdrawDelay error, got %v", err)
	}
}

func TestEncodeUptoHeader(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	payload, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err != nil {
		t.Fatalf("BuildUptoPayload: %v", err)
	}
	encoded, err := EncodeUptoHeader(req, payload)
	if err != nil {
		t.Fatalf("EncodeUptoHeader: %v", err)
	}
	if encoded == "" {
		t.Fatal("empty encoded header")
	}
}

func TestBuildUptoHeader(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	encoded, err := BuildUptoHeader(context.Background(), signer, req, 4102444800, "n-1")
	if err != nil {
		t.Fatalf("BuildUptoHeader: %v", err)
	}
	if encoded == "" {
		t.Fatal("empty encoded header")
	}
}

func TestParseUptoChallengeFromHeader(t *testing.T) {
	env := x402.UptoRequiredEnvelope{
		X402Version: 2,
		Resource:    &x402.ResourceRef{Type: "", URL: ""},
		Accepts: []x402.UptoRequirements{
			{
				Scheme:            x402.UptoScheme,
				Network:           "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				Amount:            "1000000",
				Asset:             "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				PayTo:             "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
				MaxTimeoutSeconds: 300,
			},
		},
	}
	raw, _ := json.Marshal(env)
	encoded := base64.StdEncoding.EncodeToString(raw)
	h := http.Header{}
	h.Set("payment-required", encoded)
	parsed, ok := ParseUptoChallenge(h, nil)
	if !ok {
		t.Fatal("expected ok")
	}
	if parsed == nil {
		t.Fatal("expected non-nil")
	}
	if parsed.Amount != "1000000" {
		t.Fatalf("amount = %q", parsed.Amount)
	}
}

func TestParseUptoChallengeFromBody(t *testing.T) {
	header := http.Header{}
	parsed, ok := ParseUptoChallenge(header, []byte(`{"x402Version":2,"resource":{"type":"","url":""},"accepts":[{"protocol":"x402","scheme":"upto","amount":"1000000"}]}`))
	if !ok {
		t.Fatal("expected ok")
	}
	if parsed == nil {
		t.Fatal("expected non-nil")
	}
	if parsed.Amount != "1000000" {
		t.Fatalf("amount = %q", parsed.Amount)
	}
	if parsed.Scheme != x402.UptoScheme {
		t.Fatalf("scheme = %q", parsed.Scheme)
	}
}

func TestParseUptoChallengeNoMatch(t *testing.T) {
	header := http.Header{}
	parsed, ok := ParseUptoChallenge(header, []byte(`{"x402Version":2,"resource":{"type":"","url":""},"accepts":[{"scheme":"exact","amount":"1000000"}]}`))
	if ok {
		t.Fatal("expected not ok for exact scheme")
	}
	if parsed != nil {
		t.Fatal("expected nil")
	}
}

func TestParseUptoChallengeInvalidBase64(t *testing.T) {
	h := http.Header{}
	h.Set("payment-required", "!!!invalid-base64")
	parsed, ok := ParseUptoChallenge(h, nil)
	if ok {
		t.Fatal("expected not ok")
	}
	if parsed != nil {
		t.Fatal("expected nil")
	}
}

func TestParseUptoChallengeEmpty(t *testing.T) {
	parsed, ok := ParseUptoChallenge(http.Header{}, nil)
	if ok {
		t.Fatal("expected not ok")
	}
	if parsed != nil {
		t.Fatal("expected nil")
	}
}

func TestParseUptoChallengeValidAfter(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	va := int64(1000)
	req.Extra.ValidAfter = &va
	payload, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err != nil {
		t.Fatalf("BuildUptoPayload: %v", err)
	}
	if payload.ValidAfter != 1000 {
		t.Fatalf("validAfter = %d", payload.ValidAfter)
	}
}
