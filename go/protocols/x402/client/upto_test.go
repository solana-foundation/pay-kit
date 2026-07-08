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

func TestAssetTransferMethodSupported(t *testing.T) {
	r := &x402.UptoRequirements{}
	if assetTransferMethodSupported(r) {
		t.Fatal("expected false for empty assetTransferMethod")
	}
	r.Extra.AssetTransferMethod = "permit"
	if assetTransferMethodSupported(r) {
		t.Fatal("expected false for non-matching assetTransferMethod")
	}
	r.Extra.AssetTransferMethod = x402.UptoAssetTransferMethod
	if !assetTransferMethodSupported(r) {
		t.Fatal("expected true for payment-channel assetTransferMethod")
	}
}

func TestResolveChannelProgram(t *testing.T) {
	pk, err := resolveChannelProgram("")
	if err != nil {
		t.Fatalf("resolveChannelProgram: %v", err)
	}
	if !pk.Equals(paymentchannels.ProgramPubkey()) {
		t.Fatal("expected default program")
	}
	pk, err = resolveChannelProgram(paymentchannels.ProgramID)
	if err != nil {
		t.Fatalf("resolveChannelProgram: %v", err)
	}
	if !pk.Equals(paymentchannels.ProgramPubkey()) {
		t.Fatal("expected parsed program")
	}
	_, err = resolveChannelProgram("not-a-pubkey")
	if err == nil {
		t.Fatal("expected invalid channel program error")
	}
}

func uptoRequirements(signer solana.PublicKey) *x402.UptoRequirements {
	decimals := uint8(6)
	return &x402.UptoRequirements{
		Scheme:            x402.UptoScheme,
		Network:           "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Amount:            "1000000",
		Asset:             "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		PayTo:             "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
		MaxTimeoutSeconds: 300,
		Extra: x402.UptoExtra{
			AssetTransferMethod: x402.UptoAssetTransferMethod,
			Decimals:            &decimals,
			TokenProgram:        paycore.TokenProgram,
			FacilitatorAddress:  signer.String(),
			ChannelProgram:      paymentchannels.ProgramID,
			RecentBlockhash:     "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h",
			RecentSlot:          "55555",
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
	operator := testutil.NewPrivateKey().PublicKey()
	signer := testSigner{priv}
	req := uptoRequirements(operator)
	payload, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err != nil {
		t.Fatalf("BuildUptoPayload: %v", err)
	}
	if payload.MaxAmount != "1000000" {
		t.Fatalf("maxAmount = %q", payload.MaxAmount)
	}
	if payload.Nonce != "n-1" {
		t.Fatalf("nonce = %q", payload.Nonce)
	}
	if payload.OpenTransaction == "" {
		t.Fatal("openTransaction is empty")
	}
	if payload.From != priv.PublicKey().String() {
		t.Fatalf("from = %s, want payer %s", payload.From, priv.PublicKey())
	}
	if payload.AuthorizedSigner != operator.String() {
		t.Fatalf("authorizedSigner = %s, want operator %s", payload.AuthorizedSigner, operator)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.OpenTransaction)
	if err != nil {
		t.Fatalf("DecodeTransactionBase64: %v", err)
	}
	if !tx.Message.AccountKeys[0].Equals(operator) {
		t.Fatalf("fee payer = %s, want operator %s", tx.Message.AccountKeys[0], operator)
	}
	openIx := tx.Message.Instructions[0]
	payerFromOpen := tx.Message.AccountKeys[openIx.Accounts[0]]
	rentPayerFromOpen := tx.Message.AccountKeys[openIx.Accounts[1]]
	payeeFromOpen := tx.Message.AccountKeys[openIx.Accounts[2]]
	authorizedSignerFromOpen := tx.Message.AccountKeys[openIx.Accounts[4]]
	if !payerFromOpen.Equals(priv.PublicKey()) {
		t.Fatalf("open payer = %s, want %s", payerFromOpen, priv.PublicKey())
	}
	if !rentPayerFromOpen.Equals(operator) {
		t.Fatalf("open rent_payer = %s, want operator %s", rentPayerFromOpen, operator)
	}
	if !payeeFromOpen.Equals(operator) {
		t.Fatalf("open payee = %s, want operator %s", payeeFromOpen, operator)
	}
	if !authorizedSignerFromOpen.Equals(operator) {
		t.Fatalf("open authorized_signer = %s, want operator %s", authorizedSignerFromOpen, operator)
	}
}

func TestBuildUptoPayloadUsesChannelProgramForChannelID(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	customProgram := testutil.NewPrivateKey().PublicKey()
	req.Extra.ChannelProgram = customProgram.String()

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
		solana.MustPublicKeyFromBase58(req.Extra.FacilitatorAddress),
		solana.MustPublicKeyFromBase58(req.Asset),
		solana.MustPublicKeyFromBase58(req.Extra.FacilitatorAddress),
		mustReadOpenSalt(t, tx),
		55_555,
		customProgram,
	)
	if err != nil {
		t.Fatalf("FindChannelPDAForProgram: %v", err)
	}
	if !channelFromPayload.Equals(want) {
		t.Fatalf("payload channelId = %s, want custom-program PDA %s", channelFromPayload, want)
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

func TestBuildUptoPayloadRejectsUnsupportedAssetTransferMethod(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.AssetTransferMethod = "permit"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil || !strings.Contains(err.Error(), "payment-channel") {
		t.Fatalf("expected assetTransferMethod error, got %v", err)
	}
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

func TestBuildUptoPayloadRejectsBadFacilitatorAddress(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.FacilitatorAddress = "not-a-pubkey"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for bad facilitatorAddress")
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

func TestBuildUptoPayloadRejectsBadChannelProgram(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.ChannelProgram = "invalid"
	_, err := BuildUptoPayload(context.Background(), signer, req, 4102444800, "n-1")
	if err == nil {
		t.Fatal("expected error for bad channel program")
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
