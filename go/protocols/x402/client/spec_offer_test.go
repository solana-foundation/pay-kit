package client

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
)

// specRequired returns a base64 PAYMENT-REQUIRED header carrying one offer
// shaped exactly like x402 v2 PaymentRequirements (no `protocol` field).
func specRequired(t *testing.T, offer string) http.Header {
	t.Helper()
	h := http.Header{}
	h.Set(paymentRequiredHeader, base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2,"accepts":[`+offer+`]}`)))
	return h
}

func specOffer(extraFields string) string {
	payTo := testutil.NewPrivateKey().PublicKey().String()
	feePayer := testutil.NewPrivateKey().PublicKey().String()
	return `{"scheme":"exact","network":"` + mainnetCAIP2 + `","amount":"1000","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","payTo":"` + payTo + `","maxTimeoutSeconds":60,"extra":{"feePayer":"` + feePayer + `"}` + extraFields + `}`
}

// RULINGS X1: `protocol` is not a PaymentRequirements field. A spec-shaped
// offer used to be dropped by selectEntry (it required protocol == "x402"),
// so PaymentTransport handed the 402 back without paying.
func TestParseChallengeAcceptsSpecShapedOfferWithoutProtocol(t *testing.T) {
	got, ok := ParseChallenge(specRequired(t, specOffer("")), nil, ChallengeSelection{})
	if !ok || got == nil || got.Amount != "1000" {
		t.Fatalf("spec-shaped offer rejected: got %+v ok=%v", got, ok)
	}
}

// Positive control: a pay-kit offer that names protocol "x402" is still
// selected, while one naming another protocol, or a scheme this client
// cannot pay, is skipped.
func TestParseChallengeProtocolAndSchemeFilter(t *testing.T) {
	if _, ok := ParseChallenge(specRequired(t, specOffer(`,"protocol":"x402"`)), nil, ChallengeSelection{}); !ok {
		t.Fatal("protocol=x402 offer rejected")
	}
	if got, ok := ParseChallenge(specRequired(t, specOffer(`,"protocol":"mpp"`)), nil, ChallengeSelection{}); ok {
		t.Fatalf("protocol=mpp offer selected: %+v", got)
	}
	upto := `{"scheme":"upto","network":"` + mainnetCAIP2 + `","amount":"1000","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","payTo":"` + testutil.NewPrivateKey().PublicKey().String() + `","extra":{}}`
	if got, ok := ParseChallenge(specRequired(t, upto), nil, ChallengeSelection{}); ok {
		t.Fatalf("upto offer selected by the exact client: %+v", got)
	}
}
