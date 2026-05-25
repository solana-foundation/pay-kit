package errorcodes

import (
	"errors"
	"testing"

	mpp "github.com/solana-foundation/pay-kit/go"
)

func TestAllReturnsEveryCanonicalCode(t *testing.T) {
	codes := All()
	if len(codes) != 7 {
		t.Fatalf("expected 7 canonical codes, got %d", len(codes))
	}
	for _, code := range codes {
		if !IsCanonical(code) {
			t.Fatalf("All() returned non-canonical %q", code)
		}
	}
}

func TestIsCanonical(t *testing.T) {
	for _, code := range All() {
		if !IsCanonical(code) {
			t.Errorf("IsCanonical(%q) = false", code)
		}
	}
	if IsCanonical("nope") {
		t.Fatal("expected unknown code to be non-canonical")
	}
	if IsCanonical("") {
		t.Fatal("expected empty code to be non-canonical")
	}
}

func TestCanonicalMapsEveryVerifierCode(t *testing.T) {
	tests := []struct {
		in  mpp.ErrorCode
		out string
	}{
		{mpp.ErrCodeAmountMismatch, ChargeRequestMismatch},
		{mpp.ErrCodeRecipientMismatch, ChargeRequestMismatch},
		{mpp.ErrCodeSplitsExceed, ChargeRequestMismatch},
		{mpp.ErrCodeTooManySplits, ChargeRequestMismatch},
		{mpp.ErrCodeChallengeRouteMismatch, ChallengeRouteMismatch},
		{mpp.ErrCodeMintMismatch, ChallengeRouteMismatch},
		{mpp.ErrCodeInvalidMethod, ChallengeRouteMismatch},
		{mpp.ErrCodeChallengeMismatch, ChallengeVerificationFailed},
		{mpp.ErrCodeChallengeExpired, ChallengeExpired},
		{mpp.ErrCodeWrongNetwork, WrongNetwork},
		{mpp.ErrCodeSignatureConsumed, SignatureConsumed},
		{mpp.ErrCodeInvalidPayload, PaymentInvalid},
		{mpp.ErrCodeMissingTransaction, PaymentInvalid},
		{mpp.ErrCodeMissingSignature, PaymentInvalid},
		{mpp.ErrCodeNoTransfer, PaymentInvalid},
		{mpp.ErrCodeTransactionFailed, PaymentInvalid},
		{mpp.ErrCodeTransactionNotFound, PaymentInvalid},
		{mpp.ErrCodeSimulationFailed, PaymentInvalid},
		{mpp.ErrCodeRPC, PaymentInvalid},
		{mpp.ErrCodeInvalidConfig, PaymentInvalid},
		{mpp.ErrCodeOther, PaymentInvalid},
	}
	for _, tc := range tests {
		t.Run(string(tc.in), func(t *testing.T) {
			if got := Canonical(tc.in); got != tc.out {
				t.Fatalf("Canonical(%q) = %q, want %q", tc.in, got, tc.out)
			}
		})
	}
	if got := Canonical(mpp.ErrorCode("unknown-code")); got != PaymentInvalid {
		t.Fatalf("Canonical(unknown) = %q, want %q", got, PaymentInvalid)
	}
}

func TestCanonicalFromError(t *testing.T) {
	if got := CanonicalFromError(nil); got != PaymentInvalid {
		t.Fatalf("nil err = %q, want %q", got, PaymentInvalid)
	}
	if got := CanonicalFromError(errors.New("plain")); got != PaymentInvalid {
		t.Fatalf("plain err = %q, want %q", got, PaymentInvalid)
	}
	if got := CanonicalFromError(mpp.NewError(mpp.ErrCodeWrongNetwork, "x")); got != WrongNetwork {
		t.Fatalf("wrong-network err = %q, want %q", got, WrongNetwork)
	}
	wrapped := mpp.WrapError(mpp.ErrCodeChallengeExpired, "expired", errors.New("cause"))
	if got := CanonicalFromError(wrapped); got != ChallengeExpired {
		t.Fatalf("wrapped err = %q, want %q", got, ChallengeExpired)
	}
}

func TestNewPaymentRequiredBody(t *testing.T) {
	body := NewPaymentRequiredBody(ChallengeExpired, "expired")
	if body.Code != ChallengeExpired {
		t.Fatalf("Code = %q, want %q", body.Code, ChallengeExpired)
	}
	if body.Error != ChallengeExpired {
		t.Fatalf("Error alias = %q, want %q", body.Error, ChallengeExpired)
	}
	if body.Message != "expired" {
		t.Fatalf("Message = %q, want %q", body.Message, "expired")
	}
	if body.Status != 402 {
		t.Fatalf("Status = %d, want 402", body.Status)
	}
	if body.Title != "Payment Required" {
		t.Fatalf("Title = %q, want %q", body.Title, "Payment Required")
	}
	if body.Type != "https://paymentauth.org/problems/"+ChallengeExpired {
		t.Fatalf("Type = %q, want canonical type URL", body.Type)
	}
}

func TestNewPaymentRequiredBodyFallsBackOnUnknownCode(t *testing.T) {
	body := NewPaymentRequiredBody("totally-bogus", "msg")
	if body.Code != PaymentInvalid {
		t.Fatalf("expected fallback to payment_invalid, got %q", body.Code)
	}
	if body.Error != PaymentInvalid {
		t.Fatalf("expected error alias fallback, got %q", body.Error)
	}
}
