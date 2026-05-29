package x402

import (
	"bytes"
	"context"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
)

func TestCosignPassthroughWhenOperatorAbsent(t *testing.T) {
	a, _, _ := settleFixture(t, &fakeRPC{})
	// A transaction whose fee payer is a random key the operator does not
	// hold: the operator has no empty signature slot, so cosign ships the
	// original wire bytes unchanged.
	payer := testutil.NewPrivateKey().PublicKey()
	memo, err := solanatx.BuildMemoInstruction("hi")
	if err != nil {
		t.Fatal(err)
	}
	bh := solana.MustHashFromBase58(testutil.NewPrivateKey().PublicKey().String())
	tx, err := solana.NewTransaction([]solana.Instruction{memo}, bh, solana.TransactionPayer(payer))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.cosign(context.Background(), tx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Error("cosign should pass the wire through untouched when the operator is not a missing signer")
	}
}

func TestTransferRequirementsRejectsUnresolvableMint(t *testing.T) {
	a, _, _ := settleFixture(t, &fakeRPC{})
	bad := &paykit.Gate{Amount: paykit.MustParseUSD("0.10", paykit.Stablecoin("@@notamint"))}
	if _, err := a.transferRequirements(bad); err == nil {
		t.Error("expected an error resolving a bogus settlement currency to a mint")
	}
}

func TestAwaitConfirmationHonorsContextCancellation(t *testing.T) {
	a, _, _ := settleFixture(t, &fakeRPC{}) // no confirmation status -> would loop
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.awaitConfirmation(ctx, solana.Signature{}); err == nil {
		t.Error("expected awaitConfirmation to return once the context is cancelled")
	}
}
