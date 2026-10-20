package x402_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
	"github.com/solana-foundation/pay-kit/go/protocols/x402/client"
)

type paymentFixture struct {
	rpc   *testutil.FakeRPC
	route x402.ExactRoute
	offer x402.AcceptsEntry
}

func newPaymentFixture(t *testing.T, owner string) paymentFixture {
	t.Helper()
	mint := testutil.NewPrivateKey().PublicKey()
	payTo := testutil.NewPrivateKey().PublicKey()
	feePayer := testutil.NewPrivateKey().PublicKey()
	rpc := testutil.NewFakeRPC()
	rpc.MintOwners[mint.String()] = solana.MustPublicKeyFromBase58(owner)
	rpc.MintDecimals[mint.String()] = 6
	route, err := x402.NewExactRoute(context.Background(), rpc, x402.ExactRouteConfig{
		Network:  "devnet",
		PayTo:    payTo.String(),
		Asset:    mint.String(),
		Amount:   "1000",
		FeePayer: feePayer.String(),
	})
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	var offer x402.AcceptsEntry
	raw := `{"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","amount":"1000","asset":"` + mint.String() +
		`","payTo":"` + payTo.String() + `","maxTimeoutSeconds":60,"extra":{"feePayer":"` + feePayer.String() + `"}}`
	if err := json.Unmarshal([]byte(raw), &offer); err != nil {
		t.Fatalf("offer: %v", err)
	}
	return paymentFixture{rpc: rpc, route: route, offer: offer}
}

func (f paymentFixture) header(t *testing.T) string {
	t.Helper()
	header, err := client.BuildPaymentHeader(context.Background(), testutil.NewPrivateKey(), f.rpc, &f.offer)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return header
}

// rewrite decodes a credential header, applies edit, and re-encodes it.
func rewrite(t *testing.T, header string, edit func(map[string]any)) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(out)
}

func reasonOf(t *testing.T, err error) string {
	t.Helper()
	var ve *x402.VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want *VerifyError", err)
	}
	return ve.Code
}

// Positive control: a real client-built exact transaction (decimals and
// Token-2022 program read from the mint) passes the shared verifier.
func TestVerifyPaymentHeaderAcceptsRealTransaction(t *testing.T) {
	f := newPaymentFixture(t, paycore.Token2022Program)
	if f.route.Requirements.TokenProgram.String() != paycore.Token2022Program {
		t.Fatalf("route token program = %s, want Token-2022 from the mint owner", f.route.Requirements.TokenProgram)
	}
	verified, err := x402.VerifyPaymentHeader(f.header(t), f.route)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Transaction == nil || len(verified.RawTransaction) == 0 {
		t.Fatal("verified payment carries no transaction")
	}
}

// x402 v2 makes `accepted` required. A v2 credential without it used to
// skip the route binding entirely in the adapter.
func TestVerifyPaymentHeaderRejectsV2WithoutAccepted(t *testing.T) {
	f := newPaymentFixture(t, paycore.TokenProgram)
	header := rewrite(t, f.header(t), func(m map[string]any) { delete(m, "accepted") })
	_, err := x402.VerifyPaymentHeader(header, f.route)
	if code := reasonOf(t, err); code != x402.ReasonInvalidPayload {
		t.Fatalf("code = %s, want %s", code, x402.ReasonInvalidPayload)
	}
}

func TestVerifyPaymentHeaderEnvelopeRejects(t *testing.T) {
	f := newPaymentFixture(t, paycore.TokenProgram)
	good := f.header(t)
	cases := []struct {
		name  string
		edit  func(map[string]any)
		route func(x402.ExactRoute) x402.ExactRoute
		want  string
	}{
		{name: "amount", edit: func(m map[string]any) { m["accepted"].(map[string]any)["amount"] = "1" }, want: x402.ReasonChargeRequestMismatch},
		{name: "network", route: func(r x402.ExactRoute) x402.ExactRoute { r.Network = "mainnet"; return r }, want: x402.ReasonChargeRequestMismatch},
		{name: "version", edit: func(m map[string]any) { m["x402Version"] = 9 }, want: x402.ReasonVersionMismatch},
		{name: "v1_network", edit: func(m map[string]any) {
			delete(m, "accepted")
			m["x402Version"], m["scheme"], m["network"] = 1, "exact", "solana"
		}, want: x402.ReasonChargeRequestMismatch},
		{name: "payment_identifier", route: func(r x402.ExactRoute) x402.ExactRoute { r.RequirePaymentIdentifier = true; return r }, want: x402.ReasonPaymentIdentifierRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header, route := good, f.route
			if tc.edit != nil {
				header = rewrite(t, good, tc.edit)
			}
			if tc.route != nil {
				route = tc.route(route)
			}
			_, err := x402.VerifyPaymentHeader(header, route)
			if code := reasonOf(t, err); code != tc.want {
				t.Fatalf("code = %s, want %s (%v)", code, tc.want, err)
			}
		})
	}
	// Positive control for the v1 arm: devnet slug binds a devnet route.
	v1 := rewrite(t, good, func(m map[string]any) {
		delete(m, "accepted")
		m["x402Version"], m["scheme"], m["network"] = 1, "exact", "solana-devnet"
	})
	if _, err := x402.VerifyPaymentHeader(v1, f.route); err != nil {
		t.Fatalf("v1 devnet credential: %v", err)
	}
}
