package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	token2022 "github.com/gagliardetto/solana-go/programs/token-2022"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/internal/solanautil"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/protocol"
)

func TestFormatAmountDisplayLongUnknownCurrencyTruncates(t *testing.T) {
	out := formatAmountDisplay("1000000", "SUPERLONGCURRENCYNAME", 6)
	if !strings.Contains(out, "SUPERL") {
		t.Fatalf("expected truncated currency label, got %q", out)
	}
	if strings.Contains(out, "SUPERLO") {
		t.Fatalf("expected currency label truncated to 6 chars, got %q", out)
	}
}

func TestFormatAmountDisplayInvalidNumberRendersZero(t *testing.T) {
	out := formatAmountDisplay("not-a-number", "USDC", 6)
	if !strings.Contains(out, "$") {
		t.Fatalf("expected stablecoin format on invalid number, got %q", out)
	}
}

func TestFormatAmountDisplaySOLFractional(t *testing.T) {
	out := formatAmountDisplay("500000000", "sol", 9)
	if !strings.Contains(out, "SOL") {
		t.Fatalf("expected SOL label, got %q", out)
	}
}

func TestMarkAuthorizationBoundResponseExistingVary(t *testing.T) {
	h := http.Header{}
	h.Set("Vary", "Accept, Authorization")
	markAuthorizationBoundResponse(h)
	values := h.Values("Vary")
	if len(values) != 1 {
		t.Fatalf("expected Vary preserved, got %v", values)
	}
}

func TestMarkAuthorizationBoundResponseWildcardVary(t *testing.T) {
	h := http.Header{}
	h.Set("Vary", "*")
	markAuthorizationBoundResponse(h)
	if got := h.Values("Vary"); len(got) != 1 || got[0] != "*" {
		t.Fatalf("expected wildcard Vary preserved, got %v", got)
	}
}

func TestVerifyTransfersToken2022Path(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	t2022 := solana.MustPublicKeyFromBase58(protocol.Token2022Program)

	sourceATA, _ := solanautil.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, t2022)
	recipientATA, _ := solanautil.FindAssociatedTokenAddressWithProgram(recipient, mint, t2022)

	primaryIx, err := token2022.NewTransferCheckedInstruction(
		1000, 6, sourceATA, mint, recipientATA, payer.PublicKey(), nil,
	).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build token2022 transfer failed: %v", err)
	}
	tx := newTestTransaction(t, payer, primaryIx)
	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", protocol.MethodDetails{
		TokenProgram: protocol.Token2022Program,
	})
	if err != nil {
		t.Fatalf("expected token2022 verify to pass, got: %v", err)
	}
}

func TestVerifyTransfersToken2022WrongMint(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	wrongMint := testutil.NewPrivateKey().PublicKey()
	t2022 := solana.MustPublicKeyFromBase58(protocol.Token2022Program)

	sourceATA, _ := solanautil.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), wrongMint, t2022)
	recipientATA, _ := solanautil.FindAssociatedTokenAddressWithProgram(recipient, wrongMint, t2022)

	primaryIx, err := token2022.NewTransferCheckedInstruction(
		1000, 6, sourceATA, wrongMint, recipientATA, payer.PublicKey(), nil,
	).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tx := newTestTransaction(t, payer, primaryIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", protocol.MethodDetails{
		TokenProgram: protocol.Token2022Program,
	}); err == nil {
		t.Fatal("expected mint-mismatch failure")
	}
}

func TestBuildExpectedTransfersInvalidSplitAmount(t *testing.T) {
	_, err := buildExpectedTransfers(1000, testutil.NewPrivateKey().PublicKey(), protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "not-a-number"}},
	})
	if err == nil {
		t.Fatal("expected invalid split amount error")
	}
}

func TestBuildExpectedTransfersInvalidSplitRecipient(t *testing.T) {
	_, err := buildExpectedTransfers(1000, testutil.NewPrivateKey().PublicKey(), protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: "bad-key", Amount: "100"}},
	})
	if err == nil {
		t.Fatal("expected invalid split recipient error")
	}
}

func TestBuildExpectedTransfersSplitsExceedTotal(t *testing.T) {
	_, err := buildExpectedTransfers(100, testutil.NewPrivateKey().PublicKey(), protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "200"}},
	})
	if err == nil {
		t.Fatal("expected splits-exceed error")
	}
}

func TestVerifyMemoInstructionsTooLong(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	ix, _ := solanautil.BuildSOLTransfer(payer.PublicKey(), recipient, 1)
	tx := newTestTransaction(t, payer, ix)
	matched := make([]bool, len(tx.Message.Instructions))
	err := verifyMemoInstructions(tx, matched, strings.Repeat("x", 600), nil)
	if err == nil {
		t.Fatal("expected memo too long error")
	}
}

// Middleware: marshal challenge JSON error is unreachable (challenge is always
// marshalable). Test that PaymentMiddleware writes JSON on plain Accept header.
func TestPaymentMiddlewareWritesJSON402(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := PaymentMiddleware(handler, func(_ *http.Request) (string, ChargeOptions, error) {
		return "0.001", ChargeOptions{}, nil
	})(next)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "json") {
		t.Fatalf("expected JSON content type, got %q", w.Header().Get("Content-Type"))
	}
}

func TestPaymentMiddlewareReceiptFromContextAbsent(t *testing.T) {
	if _, ok := ReceiptFromContext(context.Background()); ok {
		t.Fatal("expected no receipt in fresh context")
	}
}

// Reference mpp to silence unused import in some configurations.
var _ = mpp.AuthorizationHeader
