package x402

// Focused branch-coverage tests for the upto engine: the accepted-object and
// settlement-header serializers, the in-flight guard, the distribution split
// derivation, the challenge lifetime (blockhash + recentSlot) resolution, the
// SettleActual failure paths, the channel-account fetch failure paths, and the
// open-instruction validator mismatch branches. The happy-path engine flow is
// pinned by TestUptoVerifyOpenAndSettle; these tests lock the error surfaces
// around it.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
)

// ── accepted object + settlement header serializers ──

func TestUptoAcceptedValueRoundTrips(t *testing.T) {
	req := uptoRequirements()
	raw, err := req.AcceptedValue()
	if err != nil {
		t.Fatalf("AcceptedValue: %v", err)
	}
	var back UptoRequirements
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal accepted value: %v", err)
	}
	if back.Scheme != UptoScheme || back.Amount != req.Amount || back.PayTo != req.PayTo {
		t.Fatalf("accepted value round-trip mismatch: %+v", back)
	}
}

func TestUptoSettlementHeaderEncodesResponse(t *testing.T) {
	engine := newCoverageUptoEngine(t, nil)
	settlement := UptoSettlementResponse{
		Success: true, Payer: "payer", Transaction: "sig", Network: "solana:mainnet", Amount: "42",
	}
	name, value, err := engine.SettlementHeader(settlement)
	if err != nil {
		t.Fatalf("SettlementHeader: %v", err)
	}
	if name != PaymentResponseHeader {
		t.Fatalf("header name = %q, want %q", name, PaymentResponseHeader)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode header value: %v", err)
	}
	var back UptoSettlementResponse
	if err := json.Unmarshal(decoded, &back); err != nil {
		t.Fatalf("unmarshal settlement: %v", err)
	}
	if back != settlement {
		t.Fatalf("settlement round-trip mismatch: %+v", back)
	}
}

// ── in-flight guard ──

func TestUptoInFlightGuardReleaseIsIdempotent(t *testing.T) {
	engine := newCoverageUptoEngine(t, nil)
	channel := testutil.NewPrivateKey().PublicKey()

	guard, err := engine.reserveChannel(channel)
	if err != nil {
		t.Fatalf("reserveChannel: %v", err)
	}
	// A second reservation for the same channel conflicts while in flight.
	if _, err := engine.reserveChannel(channel); err == nil {
		t.Fatal("expected concurrent-reservation conflict")
	}

	open := &UptoVerifiedOpen{ChannelID: channel, guard: guard}
	open.Release()
	// Releasing again (the middleware fallback) must be a no-op, as must a
	// nil open and a nil guard.
	open.Release()
	(*UptoVerifiedOpen)(nil).Release()
	(&UptoVerifiedOpen{}).Release()

	// The reservation is free again after release.
	guard, err = engine.reserveChannel(channel)
	if err != nil {
		t.Fatalf("reserveChannel after release: %v", err)
	}
	guard.release()
}

// ── distribution split derivation ──

func TestUptoDistributionBranches(t *testing.T) {
	receiverAuthorizerKey := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	// Recipient == receiver authorizer collapses to no split.
	same := newCoverageUptoEngine(t, nil)
	same.cfg.Recipient = same.ReceiverAuthorizer()
	if entries, err := same.distribution(); err != nil || entries != nil {
		t.Fatalf("distribution(recipient==receiverAuthorizer) = %v, %v; want nil, nil", entries, err)
	}

	// A distinct recipient gets the whole payment as a single split.
	split := newCoverageUptoEngine(t, nil)
	split.cfg.Recipient = recipient.String()
	entries, err := split.distribution()
	if err != nil {
		t.Fatalf("distribution: %v", err)
	}
	if len(entries) != 1 || !entries[0].Recipient.Equals(recipient) || entries[0].Bps != 10_000 {
		t.Fatalf("distribution = %+v, want single 10000bps split to recipient", entries)
	}

	// Constructor-bypassing engines exercise the defensive error branch.
	badRecipient := &X402Upto{cfg: UptoConfig{Recipient: "not-a-pubkey"}, receiverAuthorizer: receiverAuthorizerKey.PublicKey()}
	if _, err := badRecipient.distribution(); err == nil || !strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("error = %v, want invalid recipient", err)
	}
}

// ── challenge lifetime (blockhash + recentSlot) resolution ──

// lifetimeRPC overrides GetLatestBlockhash with a canned result/error so the
// recentLifetime RPC branches are reachable without the wire.
type lifetimeRPC struct {
	*testutil.FakeRPC
	out *rpc.GetLatestBlockhashResult
	err error
}

func (r *lifetimeRPC) GetLatestBlockhash(context.Context, rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return r.out, r.err
}

func TestUptoRecentLifetimeBranches(t *testing.T) {
	blockhash := solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h")

	// Providers: both configured wins without touching the RPC.
	engine := newCoverageUptoEngine(t, nil)
	gotHash, gotSlot, err := engine.recentLifetime()
	if err != nil {
		t.Fatalf("recentLifetime: %v", err)
	}
	if gotHash != blockhash.String() || gotSlot != 55_555 {
		t.Fatalf("lifetime = %q/%d, want provider values", gotHash, gotSlot)
	}

	// Blockhash provider without a slot provider is a configuration error.
	engine.cfg.RecentSlotProvider = nil
	if _, _, err := engine.recentLifetime(); err == nil || !strings.Contains(err.Error(), "RecentSlotProvider is required") {
		t.Fatalf("error = %v, want missing slot provider rejection", err)
	}

	// Provider errors propagate.
	engine.cfg.RecentSlotProvider = func() (uint64, error) { return 0, errors.New("slot boom") }
	if _, _, err := engine.recentLifetime(); err == nil || !strings.Contains(err.Error(), "slot boom") {
		t.Fatalf("error = %v, want slot provider error", err)
	}
	engine.cfg.RecentBlockhashProvider = func() (string, error) { return "", errors.New("hash boom") }
	if _, _, err := engine.recentLifetime(); err == nil || !strings.Contains(err.Error(), "hash boom") {
		t.Fatalf("error = %v, want blockhash provider error", err)
	}

	// RPC path: one getLatestBlockhash response supplies both values (the
	// context slot is the recentSlot).
	rpcEngine := newCoverageUptoEngine(t, nil)
	rpcEngine.cfg.RecentBlockhashProvider = nil
	rpcEngine.cfg.RecentSlotProvider = nil
	result := &rpc.GetLatestBlockhashResult{Value: &rpc.LatestBlockhashResult{Blockhash: blockhash}}
	result.Context.Slot = 77_777
	rpcEngine.SetRPCForTests(&lifetimeRPC{FakeRPC: testutil.NewFakeRPC(), out: result})
	gotHash, gotSlot, err = rpcEngine.recentLifetime()
	if err != nil {
		t.Fatalf("recentLifetime rpc: %v", err)
	}
	if gotHash != blockhash.String() || gotSlot != 77_777 {
		t.Fatalf("lifetime = %q/%d, want rpc blockhash + context slot", gotHash, gotSlot)
	}

	// RPC error and empty response branches.
	rpcEngine.SetRPCForTests(&lifetimeRPC{FakeRPC: testutil.NewFakeRPC(), err: errors.New("rpc boom")})
	if _, _, err := rpcEngine.recentLifetime(); err == nil || !strings.Contains(err.Error(), "rpc boom") {
		t.Fatalf("error = %v, want rpc error", err)
	}
	rpcEngine.SetRPCForTests(&lifetimeRPC{FakeRPC: testutil.NewFakeRPC(), out: &rpc.GetLatestBlockhashResult{}})
	if _, _, err := rpcEngine.recentLifetime(); err == nil || !strings.Contains(err.Error(), "empty blockhash response") {
		t.Fatalf("error = %v, want empty response rejection", err)
	}

	// The challenge builder surfaces lifetime failures.
	if _, err := rpcEngine.Upto("1.00"); err == nil || !strings.Contains(err.Error(), "failed to fetch recent blockhash") {
		t.Fatalf("Upto error = %v, want lifetime failure", err)
	}
	if _, _, err := rpcEngine.PaymentRequiredHeader("1.00"); err == nil {
		t.Fatal("PaymentRequiredHeader should surface the lifetime failure")
	}
}

func TestUptoChallengeCarriesRecentSlot(t *testing.T) {
	engine := newCoverageUptoEngine(t, nil)
	envelope, err := engine.Upto("1.00")
	if err != nil {
		t.Fatalf("Upto: %v", err)
	}
	if len(envelope.Accepts) != 1 {
		t.Fatalf("accepts = %d, want 1", len(envelope.Accepts))
	}
	if got := envelope.Accepts[0].Extra.RecentSlot; got != "55555" {
		t.Fatalf("extra.recentSlot = %q, want \"55555\"", got)
	}
	if envelope.Accepts[0].Extra.RecentBlockhash == "" {
		t.Fatal("extra.recentBlockhash missing")
	}
}

// ── SettleActual failure paths ──

// failingSigner satisfies the upto signer seam with an injectable failure.
type failingSigner struct {
	pubkey string
	sign   func(msg []byte) ([]byte, error)
}

func (s failingSigner) Pubkey() string { return s.pubkey }
func (s failingSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return s.sign(msg)
}

func TestUptoSettleActualErrorPaths(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	channel := testutil.NewPrivateKey().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	verifiedOpen := func() *UptoVerifiedOpen {
		return &UptoVerifiedOpen{
			ChannelID: channel, Payer: testutil.NewPrivateKey().PublicKey(),
			Payee: operatorKey.PublicKey(), RentPayer: operatorKey.PublicKey(),
			Mint: mint, TokenProgram: solana.TokenProgramID,
			ProgramID: paymentchannels.ProgramPubkey(),
			Deposit:   1_000_000, MaxAmount: 1_000_000,
			ExpiresAt: time.Now().Add(time.Hour).Unix(), Network: "solana:mainnet",
		}
	}

	engine := newCoverageUptoEngine(t, nil)
	if _, err := engine.SettleActual(context.Background(), nil, 1); err == nil {
		t.Fatal("expected nil-open rejection")
	}
	if _, err := engine.SettleActual(context.Background(), verifiedOpen(), 2_000_000); err == nil ||
		err.Error() != UptoErrorSettlementExceedsAmount {
		t.Fatalf("error = %v, want settlement-exceeds-amount", err)
	}

	// Voucher signing failure.
	signErr := newCoverageUptoEngine(t, nil)
	signErr.cfg.ReceiverAuthorizerSigner = failingSigner{
		pubkey: operatorKey.PublicKey().String(),
		sign:   func([]byte) ([]byte, error) { return nil, errors.New("kms down") },
	}
	if _, err := signErr.SettleActual(context.Background(), verifiedOpen(), 1); err == nil ||
		!strings.Contains(err.Error(), "voucher signing failed") {
		t.Fatalf("error = %v, want voucher signing failure", err)
	}

	// Malformed voucher signature length.
	shortSig := newCoverageUptoEngine(t, nil)
	shortSig.cfg.ReceiverAuthorizerSigner = failingSigner{
		pubkey: operatorKey.PublicKey().String(),
		sign:   func([]byte) ([]byte, error) { return make([]byte, 10), nil },
	}
	if _, err := shortSig.SettleActual(context.Background(), verifiedOpen(), 1); err == nil ||
		!strings.Contains(err.Error(), "voucher signature length") {
		t.Fatalf("error = %v, want signature length rejection", err)
	}

	// Blockhash fetch failure and empty response.
	hashErr := newCoverageUptoEngine(t, &operatorKey)
	hashErr.SetRPCForTests(&lifetimeRPC{FakeRPC: testutil.NewFakeRPC(), err: errors.New("rpc boom")})
	if _, err := hashErr.SettleActual(context.Background(), verifiedOpen(), 1); err == nil ||
		!strings.Contains(err.Error(), "blockhash fetch failed") {
		t.Fatalf("error = %v, want blockhash fetch failure", err)
	}
	hashErr.SetRPCForTests(&lifetimeRPC{FakeRPC: testutil.NewFakeRPC(), out: &rpc.GetLatestBlockhashResult{}})
	if _, err := hashErr.SettleActual(context.Background(), verifiedOpen(), 1); err == nil ||
		!strings.Contains(err.Error(), "blockhash fetch failed: empty response") {
		t.Fatalf("error = %v, want empty blockhash rejection", err)
	}

	// Settle-transaction signing failure: the receiver-authorizer key is not a
	// required signer when the configured signer advertises the wrong pubkey.
	wrongSigner := newCoverageUptoEngine(t, &operatorKey)
	wrongSigner.cfg.ReceiverAuthorizerSigner = failingSigner{
		pubkey: testutil.NewPrivateKey().PublicKey().String(),
		sign:   func([]byte) ([]byte, error) { return make([]byte, 64), nil },
	}
	wrongSigner.SetRPCForTests(newUptoTestRPC())
	if _, err := wrongSigner.SettleActual(context.Background(), verifiedOpen(), 1); err == nil ||
		!strings.Contains(err.Error(), "receiver authorizer signing failed") {
		t.Fatalf("error = %v, want receiver authorizer signing failure", err)
	}

	// Broadcast failure.
	sendErr := newCoverageUptoEngine(t, &operatorKey)
	failRPC := newUptoTestRPC()
	failRPC.SendErr = errors.New("send boom")
	sendErr.SetRPCForTests(failRPC)
	if _, err := sendErr.SettleActual(context.Background(), verifiedOpen(), 1); err == nil ||
		!strings.Contains(err.Error(), "settle broadcast failed") {
		t.Fatalf("error = %v, want broadcast failure", err)
	}
}

// ── channel account fetch ──

// accountRPC overrides GetAccountInfoWithOpts with a canned result/error.
type accountRPC struct {
	*testutil.FakeRPC
	out *rpc.GetAccountInfoResult
	err error
}

func (r *accountRPC) GetAccountInfoWithOpts(context.Context, solana.PublicKey, *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	return r.out, r.err
}

func TestUptoFetchChannelErrorPaths(t *testing.T) {
	engine := newCoverageUptoEngine(t, nil)
	channel := testutil.NewPrivateKey().PublicKey()

	// RPC error.
	engine.SetRPCForTests(&accountRPC{FakeRPC: testutil.NewFakeRPC(), err: errors.New("rpc boom")})
	if _, err := engine.fetchChannel(context.Background(), channel); err == nil ||
		!strings.Contains(err.Error(), "channel account fetch failed") {
		t.Fatalf("error = %v, want fetch failure", err)
	}

	// Missing account data.
	engine.SetRPCForTests(&accountRPC{FakeRPC: testutil.NewFakeRPC(), out: &rpc.GetAccountInfoResult{}})
	if _, err := engine.fetchChannel(context.Background(), channel); err == nil ||
		!strings.Contains(err.Error(), "missing account data") {
		t.Fatalf("error = %v, want missing-data rejection", err)
	}

	// Empty account data.
	engine.SetRPCForTests(&accountRPC{FakeRPC: testutil.NewFakeRPC(), out: &rpc.GetAccountInfoResult{
		Value: &rpc.Account{Data: rpc.DataBytesOrJSONFromBytes(nil)},
	}})
	if _, err := engine.fetchChannel(context.Background(), channel); err == nil ||
		!strings.Contains(err.Error(), "empty account data") {
		t.Fatalf("error = %v, want empty-data rejection", err)
	}

	// Truncated bytes fail Borsh decoding.
	engine.SetRPCForTests(&accountRPC{FakeRPC: testutil.NewFakeRPC(), out: &rpc.GetAccountInfoResult{
		Value: &rpc.Account{Data: rpc.DataBytesOrJSONFromBytes([]byte{1, 2, 3})},
	}})
	if _, err := engine.fetchChannel(context.Background(), channel); err == nil ||
		!strings.Contains(err.Error(), "channel decode failed") {
		t.Fatalf("error = %v, want decode failure", err)
	}
}

// ── VerifyOpen error paths ──

// coverageOpenEnvelope builds a PAYMENT-SIGNATURE header whose payload passes
// VerifyUptoPayload against the engine's "1.00" requirement, with the given
// mutation applied before encoding.
func coverageOpenEnvelope(t *testing.T, operator solana.PublicKey, mutate func(*UptoSignatureEnvelope)) string {
	t.Helper()
	channel := testutil.NewPrivateKey().PublicKey()
	envelope := UptoSignatureEnvelope{
		X402Version: X402Version,
		Scheme:      UptoScheme,
		Network:     "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Payload: UptoPayload{
			From:             testutil.NewPrivateKey().PublicKey().String(),
			MaxAmount:        "1000000",
			ExpiresAt:        time.Now().Add(time.Hour).Unix(),
			Nonce:            "7",
			ChannelID:        channel.String(),
			Deposit:          "1000000",
			AuthorizedSigner: operator.String(),
			OpenSlot:         "55555",
			OpenTransaction:  "ignored",
		},
	}
	if mutate != nil {
		mutate(&envelope)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestUptoVerifyOpenRejectsMalformedChallengeBindings(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	operator := operatorKey.PublicKey()

	cases := []struct {
		name    string
		mutate  func(*X402Upto, *UptoSignatureEnvelope)
		wantErr string
	}{
		{"network mismatch", func(_ *X402Upto, e *UptoSignatureEnvelope) {
			e.Network = "solana:devnet"
		}, "network mismatch"},
		{"invalid channel program", func(u *X402Upto, _ *UptoSignatureEnvelope) {
			u.cfg.ChannelProgram = "not-a-program"
		}, "invalid channel program"},
		{"invalid tokenProgram", func(u *X402Upto, _ *UptoSignatureEnvelope) {
			u.cfg.TokenProgram = "not-a-token-program"
		}, "invalid token program"},
		{"invalid channelId", func(_ *X402Upto, e *UptoSignatureEnvelope) {
			e.Payload.ChannelID = "not-a-pubkey"
		}, "invalid channelId"},
		{"invalid payer", func(_ *X402Upto, e *UptoSignatureEnvelope) {
			e.Payload.From = "not-a-pubkey"
		}, "invalid payer"},
		{"missing openTransaction", func(_ *X402Upto, e *UptoSignatureEnvelope) {
			e.Payload.OpenTransaction = ""
		}, "requires openTransaction"},
		{"invalid openTransaction", func(_ *X402Upto, e *UptoSignatureEnvelope) {
			e.Payload.OpenTransaction = "!!not-base64!!"
		}, "invalid transaction"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newCoverageUptoEngine(t, &operatorKey)
			header := coverageOpenEnvelope(t, operator, func(e *UptoSignatureEnvelope) {
				tc.mutate(engine, e)
			})
			_, err := engine.VerifyOpen(context.Background(), header, "1.00")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestUptoVerifyOpenRejectsConcurrentChannelReservation(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	engine := newCoverageUptoEngine(t, &operatorKey)
	channel := testutil.NewPrivateKey().PublicKey()
	if _, err := engine.reserveChannel(channel); err != nil {
		t.Fatalf("reserveChannel: %v", err)
	}
	header := coverageOpenEnvelope(t, operatorKey.PublicKey(), func(e *UptoSignatureEnvelope) {
		e.Payload.ChannelID = channel.String()
	})
	_, err := engine.VerifyOpen(context.Background(), header, "1.00")
	if err == nil || !strings.Contains(err.Error(), "already being processed") {
		t.Fatalf("error = %v, want in-flight conflict", err)
	}
}

// ── open-instruction validator mismatch branches ──

func TestValidateUptoOpenInstructionStructuralRejections(t *testing.T) {
	payer := testutil.NewPrivateKey().PublicKey()
	payee := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	operator := testutil.NewPrivateKey().PublicKey()
	blockhash := solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h")

	channel, _, err := paymentchannels.FindChannelPDA(payer, payee, mint, operator, 7, 55_555)
	if err != nil {
		t.Fatalf("FindChannelPDA: %v", err)
	}
	openIx, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer: payer, RentPayer: operator, Payee: payee, Mint: mint, AuthorizedSigner: operator,
		Salt: 7, OpenSlot: 55_555, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	buildTx := func(instructions ...solana.Instruction) *solana.Transaction {
		tx, err := solana.NewTransaction(instructions, blockhash, solana.TransactionPayer(payer))
		if err != nil {
			t.Fatalf("NewTransaction: %v", err)
		}
		return tx
	}
	validate := func(tx *solana.Transaction, program solana.PublicKey) error {
		return validateUptoOpenInstruction(tx, program, operator, operator, payer, payee, mint, solana.TokenProgramID, channel, 1_000_000, DefaultUptoWithdrawDelaySeconds, "7", "55555", nil)
	}

	// More than one instruction.
	memo, err := solanatx.BuildMemoInstruction("memo")
	if err != nil {
		t.Fatalf("BuildMemoInstruction: %v", err)
	}
	if err := validate(buildTx(openIx, memo), paymentchannels.ProgramPubkey()); err == nil ||
		!strings.Contains(err.Error(), "exactly one instruction") {
		t.Fatalf("error = %v, want single-instruction requirement", err)
	}

	// Wrong program target.
	if err := validate(buildTx(openIx), testutil.NewPrivateKey().PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "unexpected program") {
		t.Fatalf("error = %v, want unexpected-program rejection", err)
	}

	// Not the open discriminator. Clone the data first: the compiled
	// instruction shares its byte slice with the builder-produced openIx.
	notOpen := buildTx(openIx)
	notOpen.Message.Instructions[0].Data = append([]byte(nil), notOpen.Message.Instructions[0].Data...)
	notOpen.Message.Instructions[0].Data[0] = 3 // top_up
	if err := validate(notOpen, paymentchannels.ProgramPubkey()); err == nil ||
		!strings.Contains(err.Error(), "not a channel-open instruction") {
		t.Fatalf("error = %v, want non-open rejection", err)
	}

	// Account mismatches at the pinned slots surface labeled errors.
	labels := []struct {
		slot int
		want string
	}{
		{0, "payer mismatch"},
		{1, "rent_payer mismatch"},
		{2, "payee mismatch"},
		{3, "mint mismatch"},
		{4, "authorized_signer mismatch"},
		{5, "channel mismatch"},
		{9, "system_program mismatch"},
		{10, "rent_sysvar mismatch"},
		{11, "associated_token_program mismatch"},
		{12, "event_authority mismatch"},
		{13, "self_program mismatch"},
	}
	for _, tc := range labels {
		t.Run(tc.want, func(t *testing.T) {
			tx := buildTx(openIx)
			ix := &tx.Message.Instructions[0]
			// Point the slot at a different (existing) account key so only
			// this binding breaks.
			original := ix.Accounts[tc.slot]
			for candidate := range tx.Message.AccountKeys {
				if uint16(candidate) != original {
					ix.Accounts[tc.slot] = uint16(candidate)
					break
				}
			}
			if err := validate(tx, paymentchannels.ProgramPubkey()); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// ── helpers ──

// newCoverageUptoEngine builds a minimal upto engine with provider-backed
// lifetime values. When operatorKey is non-nil it becomes the operator
// signer; otherwise a fresh key is generated.
func newCoverageUptoEngine(t *testing.T, operatorKey *solana.PrivateKey) *X402Upto {
	t.Helper()
	key := testutil.NewPrivateKey()
	if operatorKey != nil {
		key = *operatorKey
	}
	engine, err := NewX402Upto(UptoConfig{
		Recipient:               key.PublicKey().String(),
		Currency:                "USDC",
		Decimals:                6,
		Network:                 paykit.SolanaLocalnet,
		RPCURL:                  "http://localhost:8899",
		MaxTimeoutSeconds:       300,
		FeePayerSigner:          signerSigner{key},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
		RecentSlotProvider:      func() (uint64, error) { return 55_555, nil },
	})
	if err != nil {
		t.Fatalf("NewX402Upto: %v", err)
	}
	return engine
}
