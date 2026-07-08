package server

// Adversarial branch coverage for the session method layer: store and RPC
// failure surfacing, malformed payload fields, settlement error paths, the
// SubmitOpenTx failure matrix, malformed open instructions, and the
// side-channel/middleware error responses.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// failingGetStore wraps a ChannelStore and fails GetChannel.
type failingGetStore struct {
	// ChannelStore is the wrapped store handling everything but GetChannel.
	ChannelStore

	// getErr, when set, is returned by every GetChannel call.
	getErr error
}

func (f *failingGetStore) GetChannel(ctx context.Context, channelID string) (*ChannelState, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.ChannelStore.GetChannel(ctx, channelID)
}

// failingSigner satisfies solanatx.Signer but always fails to sign.
type failingSigner struct {
	key solana.PrivateKey // supplies the pubkey; Sign always fails regardless
}

func (f failingSigner) PublicKey() solana.PublicKey { return f.key.PublicKey() }

func (f failingSigner) Sign([]byte) (solana.Signature, error) {
	return solana.Signature{}, errors.New("hardware signer unavailable")
}

// failingBlockhashRPC fails GetLatestBlockhash on top of FakeRPC.
type failingBlockhashRPC struct {
	// FakeRPC handles every RPC call other than GetLatestBlockhash.
	*testutil.FakeRPC

	// err, when set, is returned by GetLatestBlockhash.
	err error

	// empty makes GetLatestBlockhash return a nil result with no error.
	empty bool
}

func (f *failingBlockhashRPC) GetLatestBlockhash(ctx context.Context, commitment rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.empty {
		return nil, nil
	}
	return f.FakeRPC.GetLatestBlockhash(ctx, commitment)
}

// failingStatusRPC fails GetSignatureStatuses on top of FakeRPC.
type failingStatusRPC struct {
	// FakeRPC handles every RPC call other than GetSignatureStatuses, which
	// this wrapper always fails.
	*testutil.FakeRPC
}

func (f *failingStatusRPC) GetSignatureStatuses(context.Context, bool, ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	return nil, errors.New("rpc unavailable")
}

func seedChannel(t *testing.T, store ChannelStore, state ChannelState) {
	t.Helper()
	if _, err := store.UpdateChannel(context.Background(), state.ChannelID, func(*ChannelState) (ChannelState, error) {
		return state, nil
	}); err != nil {
		t.Fatalf("seed channel: %v", err)
	}
}

// ── VerifyCredential decode failures ──

func TestVerifyCredentialRejectsUndecodableRequestAndMissingPayload(t *testing.T) {
	session := newTestSession(t, nil)

	// A challenge whose HMAC verifies but whose request is not a session
	// request JSON object.
	raw := core.NewBase64URLJSONRaw(`"just-a-string"`)
	challenge := core.NewChallengeWithSecretFull(
		sessionMethodSecret, "api.test", core.NewMethodName("solana"), core.NewIntentName("session"),
		raw, core.Minutes(5), "", "", nil)
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{"action": "close"})
	if err != nil {
		t.Fatalf("NewPaymentCredential: %v", err)
	}
	if _, err := session.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected request decode error")
	}

	// A credential with no payload reaches the unknown-action default.
	good, err := session.Challenge(context.Background(), SessionChallengeOptions{})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	noPayload := core.PaymentCredential{Challenge: good.ToEcho()}
	if _, err := session.VerifyCredential(context.Background(), noPayload); err == nil ||
		!strings.Contains(err.Error(), "unknown session action") {
		t.Fatalf("missing payload error = %v", err)
	}
}

func TestVerifyCredentialRejectsWrongMethodAndRealm(t *testing.T) {
	session := newTestSession(t, nil)
	action := intents.NewCloseAction(intents.ClosePayload{ChannelID: solana.NewWallet().PublicKey().String()})

	request, err := core.NewBase64URLJSONValue(session.core.BuildChallengeRequest(1_000))
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}

	wrongMethod := core.NewChallengeWithSecretFull(
		sessionMethodSecret, "api.test", core.NewMethodName("stripe"), core.NewIntentName("session"),
		request, core.Minutes(5), "", "", nil)
	credential, err := core.NewPaymentCredential(wrongMethod.ToEcho(), action)
	if err != nil {
		t.Fatalf("NewPaymentCredential: %v", err)
	}
	if _, err := session.VerifyCredential(context.Background(), credential); err == nil ||
		!strings.Contains(err.Error(), "method") {
		t.Fatalf("wrong method error = %v", err)
	}

	wrongRealm := core.NewChallengeWithSecretFull(
		sessionMethodSecret, "other.realm", core.NewMethodName("solana"), core.NewIntentName("session"),
		request, core.Minutes(5), "", "", nil)
	credential, err = core.NewPaymentCredential(wrongRealm.ToEcho(), action)
	if err != nil {
		t.Fatalf("NewPaymentCredential: %v", err)
	}
	if _, err := session.VerifyCredential(context.Background(), credential); err == nil ||
		!strings.Contains(err.Error(), "realm") {
		t.Fatalf("wrong realm error = %v", err)
	}
}

// ── open payload failures ──

func TestSessionOpenMalformedAmountsRejected(t *testing.T) {
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	session := newTestSession(t, func(o *SessionOptions) {
		o.Modes = []intents.SessionMode{intents.SessionModePush, intents.SessionModePull}
		o.PullVoucherStrategy = &strategy
	})
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()

	badDeposit := intents.OpenPayloadPush(channelID, "one-usdc", signer.Address(), "sig")
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(badDeposit)); err == nil ||
		!strings.Contains(err.Error(), "invalid deposit amount") {
		t.Fatalf("bad deposit error = %v", err)
	}

	pullNoKey := intents.OpenPayload{Mode: intents.SessionModePull, AuthorizedSigner: signer.Address(), Signature: "sig"}
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(pullNoKey)); err == nil ||
		!strings.Contains(err.Error(), "missing channelId or tokenAccount") {
		t.Fatalf("pull keying error = %v", err)
	}

	tokenAccount := solana.NewWallet().PublicKey().String()
	pullNoAmount := intents.OpenPayload{
		Mode: intents.SessionModePull, TokenAccount: &tokenAccount,
		AuthorizedSigner: signer.Address(), Signature: "sig",
	}
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(pullNoAmount)); err == nil ||
		!strings.Contains(err.Error(), "missing deposit or approvedAmount") {
		t.Fatalf("pull amount error = %v", err)
	}
}

func TestSessionPullOpenWithoutSignatureReferencesChannel(t *testing.T) {
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	session := newTestSession(t, func(o *SessionOptions) {
		o.Modes = []intents.SessionMode{intents.SessionModePull}
		o.PullVoucherStrategy = &strategy
	})
	signer := newTestVoucherSigner(t)
	tokenAccount := solana.NewWallet().PublicKey().String()
	payload := intents.OpenPayloadPull(tokenAccount, "1000", solana.NewWallet().PublicKey().String(), signer.Address(), "")

	receipt, err := verifySessionAction(t, session, intents.NewOpenAction(payload))
	if err != nil {
		t.Fatalf("pull open: %v", err)
	}
	if receipt.Reference != tokenAccount {
		t.Fatalf("reference = %q, want token account", receipt.Reference)
	}
}

func TestSessionOpenSurfacesStoreFailures(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fake := testutil.NewFakeRPC()
	store := &failingGetStore{ChannelStore: NewMemoryChannelStore(), getErr: errors.New("store offline")}
	session := newTestSession(t, func(o *SessionOptions) {
		o.Recipient = fixture.payee.String()
		// The fixture pins rentPayer (the operator/fee payer) to its own payer.
		o.Operator = fixture.payer.PublicKey().String()
		o.OpenTxSubmitter = OpenTxSubmitterServer
		o.RPC = fake
		o.Store = store
	})
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err == nil ||
		!strings.Contains(err.Error(), "store offline") {
		t.Fatalf("store failure error = %v", err)
	}
}

func TestSessionServerSubmitterSurfacesBroadcastFailure(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fake := testutil.NewFakeRPC()
	fake.SendErr = errors.New("blockhash not found")
	session := newTestSession(t, func(o *SessionOptions) {
		o.Recipient = fixture.payee.String()
		// The fixture pins rentPayer (the operator/fee payer) to its own payer.
		o.Operator = fixture.payer.PublicKey().String()
		o.OpenTxSubmitter = OpenTxSubmitterServer
		o.RPC = fake
	})
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err == nil ||
		!strings.Contains(err.Error(), "broadcast open transaction") {
		t.Fatalf("broadcast failure error = %v", err)
	}
}

// ── topUp / close failures ──

func TestSessionTopUpMalformedDepositAndStoreFailure(t *testing.T) {
	session := newTestSession(t, nil)
	_, channelID := openTrustedChannel(t, session, 1_000)
	if _, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "ten", Signature: "sig",
	})); err == nil || !strings.Contains(err.Error(), "not an unsigned integer") {
		t.Fatalf("malformed deposit error = %v", err)
	}

	store := &failingGetStore{ChannelStore: NewMemoryChannelStore(), getErr: errors.New("store offline")}
	failing := newTestSession(t, func(o *SessionOptions) { o.Store = store })
	if _, err := verifySessionAction(t, failing, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "5000", Signature: "sig",
	})); err == nil || !strings.Contains(err.Error(), "store offline") {
		t.Fatalf("store failure error = %v", err)
	}
}

func TestSessionCloseUnknownChannelAndSettledDoubleClose(t *testing.T) {
	session := newTestSession(t, nil)
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{
		ChannelID: solana.NewWallet().PublicKey().String(),
	})); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown channel error = %v", err)
	}

	// A close-pending channel that already recorded a settlement signature
	// (but is not yet marked finalized) is not re-drivable.
	channelID := solana.NewWallet().PublicKey().String()
	closeRequestedAt := uint64(1)
	settled := confirmedSignature(0xAB)
	seedChannel(t, session.Core().Store(), ChannelState{
		ChannelID:        channelID,
		AuthorizedSigner: newTestVoucherSigner(t).Address(),
		Deposit:          1_000,
		CloseRequestedAt: &closeRequestedAt,
		SettledSignature: &settled,
	})
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{
		ChannelID: channelID,
	})); err == nil || !strings.Contains(err.Error(), "close already requested") {
		t.Fatalf("settled double-close error = %v", err)
	}
}

// ── closeAndSettleChannel failure matrix ──

func TestCloseAndSettleChannelFailureMatrix(t *testing.T) {
	merchant := testutil.NewPrivateKey()
	ctx := context.Background()

	// Unknown channel settles to nothing.
	fake := testutil.NewFakeRPC()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.Signer = merchant
	})
	if signature, err := session.closeAndSettleChannel(ctx, solana.NewWallet().PublicKey().String()); err != nil || signature != "" {
		t.Fatalf("unknown channel settle = %q, %v", signature, err)
	}

	// Store read failure surfaces.
	store := &failingGetStore{ChannelStore: NewMemoryChannelStore(), getErr: errors.New("store offline")}
	failingStoreSession := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.Signer = merchant
		o.Store = store
	})
	if _, err := failingStoreSession.closeAndSettleChannel(ctx, "any"); err == nil ||
		!strings.Contains(err.Error(), "store offline") {
		t.Fatalf("store failure = %v", err)
	}

	// A non-base58 channel id fails instruction derivation.
	badChannel := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.Signer = merchant
	})
	seedChannel(t, badChannel.Core().Store(), ChannelState{
		ChannelID:        "not-base58!",
		AuthorizedSigner: newTestVoucherSigner(t).Address(),
		Deposit:          1_000,
	})
	if _, err := badChannel.closeAndSettleChannel(ctx, "not-base58!"); err == nil ||
		!strings.Contains(err.Error(), "invalid channel id") {
		t.Fatalf("bad channel id error = %v", err)
	}

	// Blockhash fetch failure and empty response both surface.
	blockhashErr := &failingBlockhashRPC{FakeRPC: testutil.NewFakeRPC(), err: errors.New("rpc down")}
	noBlockhash := newTestSession(t, func(o *SessionOptions) {
		o.RPC = blockhashErr
		o.Signer = merchant
	})
	_, channelID := openTrustedChannel(t, noBlockhash, 1_000)
	if _, err := noBlockhash.closeAndSettleChannel(ctx, channelID); err == nil ||
		!strings.Contains(err.Error(), "fetch settlement blockhash") {
		t.Fatalf("blockhash failure = %v", err)
	}
	blockhashErr.err = nil
	blockhashErr.empty = true
	if _, err := noBlockhash.closeAndSettleChannel(ctx, channelID); err == nil ||
		!strings.Contains(err.Error(), "empty response") {
		t.Fatalf("empty blockhash = %v", err)
	}

	// Merchant signer failure surfaces.
	badSigner := newTestSession(t, func(o *SessionOptions) {
		o.RPC = testutil.NewFakeRPC()
		o.Signer = failingSigner{key: merchant}
	})
	_, signerChannel := openTrustedChannel(t, badSigner, 1_000)
	if _, err := badSigner.closeAndSettleChannel(ctx, signerChannel); err == nil ||
		!strings.Contains(err.Error(), "sign settlement transaction") {
		t.Fatalf("signer failure = %v", err)
	}
}

func TestSessionIdleCloseLogsSettlementFailure(t *testing.T) {
	fake := &countingBlockhashRPC{FakeRPC: testutil.NewFakeRPC()}
	fake.SendErr = errors.New("blockhash not found")
	merchant := testutil.NewPrivateKey()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.Signer = merchant
		o.CloseDelay = 15 * time.Millisecond
	})
	_, channelID := openTrustedChannel(t, session, 1_000)
	baseline := fake.calls()

	// The watchdog fires, the settle fails (the broadcast is blocked), and
	// the channel stays re-drivable rather than finalized.
	deadline := time.Now().Add(3 * time.Second)
	for fake.calls() == baseline {
		if time.Now().After(deadline) {
			t.Fatal("idle-close watchdog never attempted settlement")
		}
		time.Sleep(5 * time.Millisecond)
	}
	state := mustGetChannel(t, session, channelID)
	if state.Finalized || state.SettledSignature != nil {
		t.Fatalf("failed settle mutated state: %+v", state)
	}
}

// ── SettlementInstructions error paths ──

func TestSettlementInstructionsStateErrorPaths(t *testing.T) {
	ctx := context.Background()
	merchant := testutil.NewPrivateKey().PublicKey()
	channelID := solana.NewWallet().PublicKey().String()
	operator := solana.NewWallet().PublicKey().String()

	// Store read failure.
	failing := NewSessionServer(sessionTestConfig(), &failingGetStore{
		ChannelStore: NewMemoryChannelStore(), getErr: errors.New("store offline"),
	})
	if _, err := failing.SettlementInstructions(ctx, channelID, merchant); err == nil ||
		!strings.Contains(err.Error(), "store offline") {
		t.Fatalf("store failure = %v", err)
	}

	seed := func(t *testing.T, config SessionConfig, state ChannelState) *SessionServer {
		server := NewSessionServer(config, NewMemoryChannelStore())
		seedChannel(t, server.Store(), state)
		return server
	}
	base := func() ChannelState {
		expiresAt := farFuture()
		signature := confirmedSignature(0xCD)
		return ChannelState{
			ChannelID:               channelID,
			AuthorizedSigner:        newTestVoucherSigner(t).Address(),
			Deposit:                 1_000,
			Cumulative:              500,
			Operator:                &operator,
			HighestVoucherSignature: &signature,
			HighestVoucherExpiresAt: &expiresAt,
		}
	}

	// Invalid stored voucher signature.
	badSignature := base()
	invalid := "not-base58!"
	badSignature.HighestVoucherSignature = &invalid
	if _, err := seed(t, sessionTestConfig(), badSignature).SettlementInstructions(ctx, channelID, merchant); err == nil ||
		!strings.Contains(err.Error(), "invalid stored voucher signature") {
		t.Fatalf("bad signature = %v", err)
	}

	// Invalid stored authorized signer.
	badSigner := base()
	badSigner.AuthorizedSigner = "not-base58!"
	if _, err := seed(t, sessionTestConfig(), badSigner).SettlementInstructions(ctx, channelID, merchant); err == nil ||
		!strings.Contains(err.Error(), "invalid stored authorized signer") {
		t.Fatalf("bad authorized signer = %v", err)
	}

	// Voucher signature without an expiry.
	noExpiry := base()
	noExpiry.HighestVoucherExpiresAt = nil
	if _, err := seed(t, sessionTestConfig(), noExpiry).SettlementInstructions(ctx, channelID, merchant); err == nil ||
		!strings.Contains(err.Error(), "no voucher expiry") {
		t.Fatalf("missing expiry = %v", err)
	}

	// Native SOL currency cannot settle a token channel.
	solConfig := sessionTestConfig()
	solConfig.Currency = "SOL"
	if _, err := seed(t, solConfig, base()).SettlementInstructions(ctx, channelID, merchant); err == nil ||
		!strings.Contains(err.Error(), "requires an SPL token") {
		t.Fatalf("SOL currency = %v", err)
	}

	// Invalid stored channel payer.
	badPayer := base()
	badPayerValue := "not-base58!"
	badPayer.Operator = &badPayerValue
	if _, err := seed(t, sessionTestConfig(), badPayer).SettlementInstructions(ctx, channelID, merchant); err == nil ||
		!strings.Contains(err.Error(), "invalid channel payer") {
		t.Fatalf("bad payer = %v", err)
	}

	// Invalid configured recipient.
	badRecipient := sessionTestConfig()
	badRecipient.Recipient = "not-base58!"
	if _, err := seed(t, badRecipient, base()).SettlementInstructions(ctx, channelID, merchant); err == nil ||
		!strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("bad recipient = %v", err)
	}
}

// ── SubmitOpenTx failure matrix ──

func TestSubmitOpenTxFailureMatrix(t *testing.T) {
	ctx := context.Background()
	fixture := buildOpenTxFixture(t, false)

	if _, err := SubmitOpenTx(ctx, fixture.expected, &fixture.payload, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "requires an RPC client") {
		t.Fatalf("nil rpc = %v", err)
	}

	// Structural validation failures propagate before any broadcast.
	fake := testutil.NewFakeRPC()
	wrongRecipient := fixture.expected
	wrongRecipient.Recipient = solana.NewWallet().PublicKey().String()
	if _, err := SubmitOpenTx(ctx, wrongRecipient, &fixture.payload, nil, fake); err == nil ||
		!strings.Contains(err.Error(), "payee") {
		t.Fatalf("verification failure = %v", err)
	}
	if len(fake.Sent) != 0 {
		t.Fatal("broadcast happened despite verification failure")
	}

	// Unsigned fee payer with no payer signer cannot broadcast.
	operator := testutil.NewPrivateKey()
	unsigned := buildServerCompletedOpenFixture(t, operator)
	if _, err := SubmitOpenTx(ctx, unsigned.expected, &unsigned.payload, nil, fake); err == nil ||
		!strings.Contains(err.Error(), "missing the fee-payer signature") {
		t.Fatalf("unsigned fee payer = %v", err)
	}

	// A payer signer that is not required by the transaction does not help.
	stranger := testutil.NewPrivateKey()
	if _, err := SubmitOpenTx(ctx, unsigned.expected, &unsigned.payload, stranger, fake); err == nil ||
		!strings.Contains(err.Error(), "missing the fee-payer signature") {
		t.Fatalf("stranger signer = %v", err)
	}

	// A required signer that fails to sign surfaces the error.
	if _, err := SubmitOpenTx(ctx, unsigned.expected, &unsigned.payload, failingSigner{key: operator}, fake); err == nil ||
		!strings.Contains(err.Error(), "co-sign open transaction") {
		t.Fatalf("co-sign failure = %v", err)
	}

	// Confirmation failure after broadcast surfaces.
	confirmFail := testutil.NewFakeRPC()
	confirmFail.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{
		Err: map[string]any{"InstructionError": []any{0, "Custom"}},
	}
	if _, err := SubmitOpenTx(ctx, fixture.expected, &fixture.payload, nil, confirmFail); err == nil ||
		!strings.Contains(err.Error(), "confirm open transaction") {
		t.Fatalf("confirmation failure = %v", err)
	}
}

// ── VerifyOpenTx malformed instruction matrix ──

// buildRawOpenPayload wraps a hand-built instruction targeting the
// payment-channels program into a signed transaction + open payload.
func buildRawOpenPayload(t *testing.T, accounts []*solana.AccountMeta, data []byte) (intents.OpenPayload, VerifyOpenTxExpected) {
	t.Helper()
	payer := testutil.NewPrivateKey()
	ix := solana.NewInstruction(paymentchannels.ProgramPubkey(), accounts, data)
	blockhash := solana.MustHashFromBase58("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, blockhash, solana.TransactionPayer(payer.PublicKey()))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	if err := solanatx.SignTransaction(tx, payer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	payload := intents.OpenPayloadPush("ignored", "1000", payer.PublicKey().String(), tx.Signatures[0].String())
	payload.ChannelID = nil
	payload.Transaction = &encoded
	expected := VerifyOpenTxExpected{
		AuthorizedSigner: payer.PublicKey().String(),
		Currency:         "USDC",
		MaxCap:           5_000_000,
		Network:          "localnet",
		Operator:         payer.PublicKey().String(),
		Recipient:        payer.PublicKey().String(),
	}
	return payload, expected
}

func TestVerifyOpenTxMalformedInstructions(t *testing.T) {
	ctx := context.Background()
	wallet := func() *solana.AccountMeta {
		return solana.Meta(solana.NewWallet().PublicKey())
	}

	// An empty currency with no explicit mint cannot resolve a mint.
	fixture := buildOpenTxFixture(t, false)
	unknownCurrency := fixture.expected
	unknownCurrency.Currency = ""
	unknownCurrency.Mint = ""
	if _, err := VerifyOpenTx(ctx, unknownCurrency, &fixture.payload, nil); err == nil ||
		!strings.Contains(err.Error(), "could not resolve mint") {
		t.Fatalf("empty currency = %v", err)
	}

	// Too few accounts on the open instruction.
	fewAccounts, expected := buildRawOpenPayload(t,
		[]*solana.AccountMeta{wallet(), wallet(), wallet()},
		append([]byte{openInstructionDiscriminator}, make([]byte, 20)...))
	if _, err := VerifyOpenTx(ctx, expected, &fewAccounts, nil); err == nil ||
		!strings.Contains(err.Error(), "too few accounts") {
		t.Fatalf("few accounts = %v", err)
	}

	// Short instruction data.
	accounts := make([]*solana.AccountMeta, 0, 8)
	for i := 0; i < 8; i++ {
		accounts = append(accounts, wallet())
	}
	shortData, shortExpected := buildRawOpenPayload(t, accounts, []byte{openInstructionDiscriminator, 1, 2, 3})
	// Point the expectations at the instruction's actual payee/mint/signer so
	// the data-length check is what fails. Account order after the rentPayer
	// (+1) shift: 0 payer, 1 rentPayer, 2 payee, 3 mint, 4 authorizedSigner, ...
	shortExpected.Operator = accounts[1].PublicKey.String()
	shortExpected.Recipient = accounts[2].PublicKey.String()
	shortExpected.Mint = accounts[3].PublicKey.String()
	shortExpected.AuthorizedSigner = accounts[4].PublicKey.String()
	if _, err := VerifyOpenTx(ctx, shortExpected, &shortData, nil); err == nil ||
		!strings.Contains(err.Error(), "data too short") {
		t.Fatalf("short data = %v", err)
	}

	// No open instruction at all (wrong discriminator).
	wrongDisc, wrongExpected := buildRawOpenPayload(t, accounts, []byte{9, 9, 9})
	if _, err := VerifyOpenTx(ctx, wrongExpected, &wrongDisc, nil); err == nil ||
		!strings.Contains(err.Error(), "no payment-channels open instruction") {
		t.Fatalf("wrong discriminator = %v", err)
	}
}

func TestConfirmTransactionSignatureRPCErrorSurfaces(t *testing.T) {
	failing := &failingStatusRPC{FakeRPC: testutil.NewFakeRPC()}
	if err := confirmTransactionSignature(context.Background(), failing, confirmedSignature(0xEF), "open"); err == nil ||
		!strings.Contains(err.Error(), "RPC error") {
		t.Fatalf("rpc error = %v", err)
	}
}

// ── routes + middleware failure responses ──

func TestSessionRoutesCommitErrorBodies(t *testing.T) {
	session := newTestSession(t, nil)
	routes := session.Routes()

	invalid := httptest.NewRequest(http.MethodPost, "/__402/session/commit", strings.NewReader("not-json"))
	recorder := httptest.NewRecorder()
	routes.Commit(recorder, invalid)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid request body") {
		t.Fatalf("invalid commit body: %d %s", recorder.Code, recorder.Body)
	}

	signer, channelID := openTrustedChannel(t, session, 1_000)
	voucher := signer.SignVoucher(t, channelID, 100, farFuture())
	unknown := commitDeliveryViaRoutes(t, routes, map[string]any{"deliveryId": "ghost", "voucher": voucher})
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "not found") {
		t.Fatalf("unknown delivery: %d %s", unknown.Code, unknown.Body)
	}
}

func TestSessionMiddlewareErrorResponses(t *testing.T) {
	session := newTestSession(t, nil)

	// challengeFn failure becomes a 500.
	failing := SessionMiddleware(session, func(*http.Request) (SessionChallengeOptions, error) {
		return SessionChallengeOptions{}, errors.New("route metadata unavailable")
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	recorder := httptest.NewRecorder()
	failing.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("challengeFn failure status = %d", recorder.Code)
	}

	// A challenge build failure (malformed cap) becomes a 500.
	badCap := SessionMiddleware(session, func(*http.Request) (SessionChallengeOptions, error) {
		return SessionChallengeOptions{Cap: "1.5"}, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	recorder = httptest.NewRecorder()
	badCap.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("bad cap status = %d", recorder.Code)
	}

	// An empty Payment token falls through to the 402 challenge.
	ok := SessionMiddleware(session, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(core.AuthorizationHeader, "Payment ")
	recorder = httptest.NewRecorder()
	ok.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("empty token status = %d", recorder.Code)
	}
}

// ── stream writer failures ──

// failAfterWriter fails every write after the first n bytes budget runs out.
type failAfterWriter struct {
	budget int // remaining bytes accepted before writes start failing
}

func (f *failAfterWriter) Write(p []byte) (int, error) {
	if f.budget <= 0 {
		return 0, errors.New("client disconnected")
	}
	f.budget -= len(p)
	return len(p), nil
}

func TestMeteredStreamSurfacesWriteFailures(t *testing.T) {
	stream := NewMeteredStreamWriter(&failAfterWriter{})
	if err := stream.WriteMetering(intents.MeteringDirective{DeliveryID: "d", SessionID: "s", Amount: "1", Currency: "USDC"}); err == nil {
		t.Fatal("expected metering write failure")
	}
	if err := stream.WriteUsage(intents.MeteringUsage{DeliveryID: "d", Amount: "1"}); err == nil {
		t.Fatal("expected usage write failure")
	}
	if err := stream.WriteEnvelope(map[string]string{"chunk": "x"}, intents.MeteringDirective{}); err == nil {
		t.Fatal("expected envelope write failure")
	}
	if err := stream.WriteDone(); err == nil {
		t.Fatal("expected done write failure")
	}
}

// ── core SessionServer gaps ──

func TestBuildChallengeRequestIncludesProgramIDOverride(t *testing.T) {
	programID := solana.NewWallet().PublicKey()
	config := sessionTestConfig()
	config.ProgramID = &programID
	server := newSessionTestServer(config)
	request := server.BuildChallengeRequest(1_000)
	if request.ProgramID == nil || *request.ProgramID != programID.String() {
		t.Fatalf("programId = %v", request.ProgramID)
	}
}

func TestVerifyVoucherSurfacesStoreFailure(t *testing.T) {
	server := NewSessionServer(sessionTestConfig(), &failingGetStore{
		ChannelStore: NewMemoryChannelStore(), getErr: errors.New("store offline"),
	})
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, solana.NewWallet().PublicKey().String(), 100, farFuture())
	if _, err := server.VerifyVoucher(context.Background(), &intents.VoucherPayload{Voucher: voucher}); err == nil ||
		!strings.Contains(err.Error(), "store offline") {
		t.Fatalf("store failure = %v", err)
	}
}

func TestProcessOpenPayloadFieldErrors(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer := newTestVoucherSigner(t)

	missingChannel := intents.OpenPayload{Mode: intents.SessionModePush, AuthorizedSigner: signer.Address(), Signature: "sig"}
	if _, err := server.ProcessOpen(context.Background(), &missingChannel); err == nil ||
		!strings.Contains(err.Error(), "missing channelId") {
		t.Fatalf("missing channelId = %v", err)
	}

	channelID := solana.NewWallet().PublicKey().String()
	badDeposit := intents.OpenPayloadPush(channelID, strconv.Quote("x"), signer.Address(), "sig")
	if _, err := server.ProcessOpen(context.Background(), &badDeposit); err == nil ||
		!strings.Contains(err.Error(), "invalid deposit amount") {
		t.Fatalf("bad deposit = %v", err)
	}
}

func TestProcessTopUpMalformedDeposit(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	if _, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID: "c", NewDeposit: "five", Signature: "sig",
	}); err == nil || !strings.Contains(err.Error(), "invalid newDeposit") {
		t.Fatalf("malformed deposit = %v", err)
	}
}

func TestProcessCommitMalformedCumulative(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	payload := intents.CommitPayload{
		DeliveryID: "d-1",
		Voucher: intents.SignedVoucher{
			Data:      intents.VoucherData{ChannelID: "c", Cumulative: "ten", ExpiresAt: farFuture()},
			Signature: confirmedSignature(0x01),
		},
	}
	if _, err := server.ProcessCommit(context.Background(), &payload); err == nil ||
		!strings.Contains(err.Error(), "invalid cumulative") {
		t.Fatalf("malformed cumulative = %v", err)
	}
}

func TestProcessCloseMalformedFinalVoucher(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000)
	voucher := intents.SignedVoucher{
		Data:      intents.VoucherData{ChannelID: channelID, Cumulative: "ten", ExpiresAt: farFuture()},
		Signature: confirmedSignature(0x02),
	}
	if _, err := server.ProcessClose(context.Background(), &intents.ClosePayload{
		ChannelID: channelID, Voucher: &voucher,
	}); err == nil || !strings.Contains(err.Error(), "invalid cumulative in final voucher") {
		t.Fatalf("malformed final voucher = %v", err)
	}
}
