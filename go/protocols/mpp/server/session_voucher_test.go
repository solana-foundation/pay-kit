package server

// Voucher verifier coverage plus adversarial ordering checks: the check
// sequence (order and operators) is part of the wire contract.

import (
	"crypto/ed25519"
	"crypto/rand"
	"strconv"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

const testVoucherChannelID = "11111111111111111111111111111111"

// testVoucherSigner is an in-memory Ed25519 keypair for voucher tests.
type testVoucherSigner struct {
	pub  ed25519.PublicKey  // verify key; its base58 form is the channel's authorized signer
	priv ed25519.PrivateKey // signing key for the canonical 48-byte voucher preimage
}

func newTestVoucherSigner(t *testing.T) testVoucherSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return testVoucherSigner{pub: pub, priv: priv}
}

// Address returns the signer pubkey as base58.
func (s testVoucherSigner) Address() string {
	return solana.PublicKeyFromBytes(s.pub).String()
}

// SignVoucher signs the canonical 48-byte voucher payload.
func (s testVoucherSigner) SignVoucher(t *testing.T, channelID string, cumulative uint64, expiresAt int64) intents.SignedVoucher {
	t.Helper()
	data := intents.VoucherData{
		ChannelID:  channelID,
		Cumulative: strconv.FormatUint(cumulative, 10),
		ExpiresAt:  expiresAt,
	}
	message, err := data.MessageBytes()
	if err != nil {
		t.Fatalf("voucher message bytes: %v", err)
	}
	signature := ed25519.Sign(s.priv, message)
	return intents.SignedVoucher{Data: data, Signature: solana.SignatureFromBytes(signature).String()}
}

func farFuture() int64 {
	return time.Now().Unix() + 3600
}

func voucherTestState(authorizedSigner string) ChannelState {
	return ChannelState{
		ChannelID:        testVoucherChannelID,
		AuthorizedSigner: authorizedSigner,
		Deposit:          1_000,
	}
}

func TestVerifyVoucherForChannelHappyPath(t *testing.T) {
	signer := newTestVoucherSigner(t)
	state := voucherTestState(signer.Address())
	expiresAt := farFuture()
	voucher := signer.SignVoucher(t, state.ChannelID, 100, expiresAt)

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: state.Deposit})
	if result.Status != VoucherVerifyAccepted {
		t.Fatalf("status = %s (%s: %s), want accepted", result.Status, result.Reason, result.Detail)
	}
	if result.NewCumulative != 100 {
		t.Fatalf("newCumulative = %d, want 100", result.NewCumulative)
	}
	if result.NewSignature != voucher.Signature {
		t.Fatalf("newSignature = %q, want voucher signature", result.NewSignature)
	}
	if result.NewExpiresAt != expiresAt {
		t.Fatalf("newExpiresAt = %d, want %d", result.NewExpiresAt, expiresAt)
	}
}

func TestVerifyVoucherForChannelIdempotentReplay(t *testing.T) {
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 100, farFuture())
	state := voucherTestState(signer.Address())
	state.Cumulative = 100
	state.HighestVoucherSignature = &voucher.Signature

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyReplayed {
		t.Fatalf("status = %s, want replayed", result.Status)
	}
	if result.NewCumulative != 100 {
		t.Fatalf("newCumulative = %d, want 100", result.NewCumulative)
	}
}

func TestVerifyVoucherForChannelReplayReVerifiesSignature(t *testing.T) {
	signer := newTestVoucherSigner(t)
	forger := newTestVoucherSigner(t)
	// A forged voucher whose signature somehow got persisted as the highest:
	// the replay path must still reject it on signature re-verification.
	forged := forger.SignVoucher(t, testVoucherChannelID, 100, farFuture())
	state := voucherTestState(signer.Address())
	state.Cumulative = 100
	state.HighestVoucherSignature = &forged.Signature

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: forged, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectInvalidSignature {
		t.Fatalf("result = %+v, want invalid-signature rejection", result)
	}
}

func TestVerifyVoucherForChannelReplayOfExpiredVoucherRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	past := time.Now().Unix() - 10
	voucher := signer.SignVoucher(t, testVoucherChannelID, 100, past)
	state := voucherTestState(signer.Address())
	state.Cumulative = 100
	state.HighestVoucherSignature = &voucher.Signature

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectExpired {
		t.Fatalf("result = %+v, want expired rejection", result)
	}
}

func TestVerifyVoucherForChannelDecreasingCumulativeRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 50, farFuture())
	state := voucherTestState(signer.Address())
	state.Cumulative = 100

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectCumulativeNotMonotonic {
		t.Fatalf("result = %+v, want cumulative-not-monotonic rejection", result)
	}
}

func TestVerifyVoucherForChannelEqualCumulativeWithoutMatchingSignatureRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 100, farFuture())
	otherSignature := "5J6vbXSpEpGv4VLLqDhuRG6Tbj5n6dgEgvtTwTKpoSjvSwLTW9PSqQc6dpMUDPCvD3KZ5dGsmiTk5jzwYZyD8Xkz"
	state := voucherTestState(signer.Address())
	state.Cumulative = 100
	state.HighestVoucherSignature = &otherSignature

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectCumulativeNotMonotonic {
		t.Fatalf("result = %+v, want cumulative-not-monotonic rejection", result)
	}
}

func TestVerifyVoucherForChannelExceedsDepositRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 2_000, farFuture())
	state := voucherTestState(signer.Address())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectExceedsDeposit {
		t.Fatalf("result = %+v, want exceeds-deposit rejection", result)
	}
}

func TestVerifyVoucherForChannelBelowMinDeltaRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 5, farFuture())
	state := voucherTestState(signer.Address())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{
		State:           state,
		Signed:          voucher,
		Deposit:         1_000,
		MinVoucherDelta: 100,
	})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectBelowMinDelta {
		t.Fatalf("result = %+v, want below-min-delta rejection", result)
	}
}

func TestVerifyVoucherForChannelBadSignatureRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	other := newTestVoucherSigner(t)
	// Sign with other, but the channel authorizes signer; sig must fail.
	voucher := other.SignVoucher(t, testVoucherChannelID, 100, farFuture())
	state := voucherTestState(signer.Address())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectInvalidSignature {
		t.Fatalf("result = %+v, want invalid-signature rejection", result)
	}
}

func TestVerifyVoucherForChannelExpiredRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 100, time.Now().Unix()-10)
	state := voucherTestState(signer.Address())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectExpired {
		t.Fatalf("result = %+v, want expired rejection", result)
	}
}

func TestVerifyVoucherForChannelFinalizedRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 100, farFuture())
	state := voucherTestState(signer.Address())
	state.Finalized = true

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectChannelFinalized {
		t.Fatalf("result = %+v, want channel-finalized rejection", result)
	}
}

func TestVerifyVoucherForChannelClosePendingRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 100, farFuture())
	state := voucherTestState(signer.Address())
	closeAt := uint64(1)
	state.CloseRequestedAt = &closeAt

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectChannelClosePending {
		t.Fatalf("result = %+v, want channel-close-pending rejection", result)
	}
}

func TestVerifyVoucherForChannelNowSecondsOverrideIsDeterministic(t *testing.T) {
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 100, 1_000)
	state := voucherTestState(signer.Address())

	late := int64(2_000)
	expired := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000, NowSeconds: &late})
	if expired.Status != VoucherVerifyRejected || expired.Reason != VoucherRejectExpired {
		t.Fatalf("result = %+v, want expired rejection at now=2000", expired)
	}

	early := int64(500)
	fresh := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000, NowSeconds: &early})
	if fresh.Status != VoucherVerifyAccepted {
		t.Fatalf("result = %+v, want accepted at now=500", fresh)
	}
}

func TestVerifyVoucherForChannelInvalidCumulativeRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	real := signer.SignVoucher(t, testVoucherChannelID, 100, farFuture())
	// Tamper the data field after signing; the verifier should reject on
	// parse before the signature check.
	tampered := intents.SignedVoucher{
		Data: intents.VoucherData{
			ChannelID:  real.Data.ChannelID,
			Cumulative: "not-a-number",
			ExpiresAt:  real.Data.ExpiresAt,
		},
		Signature: real.Signature,
	}
	state := voucherTestState(signer.Address())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: tampered, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectInvalidCumulative {
		t.Fatalf("result = %+v, want invalid-cumulative rejection", result)
	}
}

// Ordering checks: each earlier step must win over every later failure
// present in the same voucher.

func TestVerifyVoucherForChannelOrderingParseBeatsFinalized(t *testing.T) {
	signer := newTestVoucherSigner(t)
	state := voucherTestState(signer.Address())
	state.Finalized = true
	voucher := intents.SignedVoucher{
		Data:      intents.VoucherData{ChannelID: state.ChannelID, Cumulative: "bogus", ExpiresAt: farFuture()},
		Signature: "sig",
	}

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Reason != VoucherRejectInvalidCumulative {
		t.Fatalf("reason = %s, want invalid-cumulative before channel-finalized", result.Reason)
	}
}

func TestVerifyVoucherForChannelOrderingFinalizedBeatsClosePending(t *testing.T) {
	signer := newTestVoucherSigner(t)
	state := voucherTestState(signer.Address())
	state.Finalized = true
	closeAt := uint64(1)
	state.CloseRequestedAt = &closeAt
	voucher := signer.SignVoucher(t, state.ChannelID, 100, farFuture())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Reason != VoucherRejectChannelFinalized {
		t.Fatalf("reason = %s, want channel-finalized before channel-close-pending", result.Reason)
	}
}

func TestVerifyVoucherForChannelOrderingMonotonicBeatsDeposit(t *testing.T) {
	signer := newTestVoucherSigner(t)
	state := voucherTestState(signer.Address())
	state.Deposit = 10
	state.Cumulative = 100
	// Non-monotonic AND over deposit: monotonicity is checked first.
	voucher := signer.SignVoucher(t, state.ChannelID, 50, farFuture())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 10})
	if result.Reason != VoucherRejectCumulativeNotMonotonic {
		t.Fatalf("reason = %s, want cumulative-not-monotonic before exceeds-deposit", result.Reason)
	}
}

func TestVerifyVoucherForChannelOrderingDepositBeatsMinDelta(t *testing.T) {
	signer := newTestVoucherSigner(t)
	state := voucherTestState(signer.Address())
	state.Deposit = 10
	// Over deposit AND below min delta relative to a large min: deposit wins.
	voucher := signer.SignVoucher(t, state.ChannelID, 20, farFuture())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 10, MinVoucherDelta: 100})
	if result.Reason != VoucherRejectExceedsDeposit {
		t.Fatalf("reason = %s, want exceeds-deposit before below-min-delta", result.Reason)
	}
}

func TestVerifyVoucherForChannelOrderingMinDeltaBeatsSignature(t *testing.T) {
	signer := newTestVoucherSigner(t)
	other := newTestVoucherSigner(t)
	state := voucherTestState(signer.Address())
	// Below min delta AND wrongly signed: min delta is checked first.
	voucher := other.SignVoucher(t, state.ChannelID, 5, farFuture())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000, MinVoucherDelta: 100})
	if result.Reason != VoucherRejectBelowMinDelta {
		t.Fatalf("reason = %s, want below-min-delta before invalid-signature", result.Reason)
	}
}

func TestVerifyVoucherForChannelOrderingSignatureBeatsExpiry(t *testing.T) {
	signer := newTestVoucherSigner(t)
	other := newTestVoucherSigner(t)
	state := voucherTestState(signer.Address())
	// Wrongly signed AND expired: the signature is verified before expiry.
	voucher := other.SignVoucher(t, state.ChannelID, 100, time.Now().Unix()-10)

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Reason != VoucherRejectInvalidSignature {
		t.Fatalf("reason = %s, want invalid-signature before expired", result.Reason)
	}
}
