package server

// Fail-closed branch coverage for the #239 session on-chain verifiers:
// the signature-only authoritative open path, the bound-channel economic
// checks, token-program resolution, and the top-up reject branches. These
// exercise the rejection paths the happy-path tests skip.

import (
	"context"
	"strings"
	"testing"

	solana "github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

// ── validateBoundOpenChannel: economic and cross-check rejections ──

func TestValidateBoundOpenChannelRejections(t *testing.T) {
	match := func() (boundChannel, *VerifyOpenTxResult) {
		bound := boundChannel{Deposit: 1_000, Payer: "payerA", Salt: 7, OpenSlot: 42}
		verified := &VerifyOpenTxResult{Deposit: 1_000, Payer: "payerA", Salt: 7, OpenSlot: 42}
		return bound, verified
	}

	t.Run("zero deposit", func(t *testing.T) {
		bound, verified := match()
		bound.Deposit = 0
		if err := validateBoundOpenChannel(bound, verified, 5_000); err == nil || !strings.Contains(err.Error(), "greater than zero") {
			t.Fatalf("err = %v, want zero-deposit rejection", err)
		}
	})
	t.Run("over cap", func(t *testing.T) {
		bound, verified := match()
		if err := validateBoundOpenChannel(bound, verified, 500); err == nil || !strings.Contains(err.Error(), "exceeds max cap") {
			t.Fatalf("err = %v, want over-cap rejection", err)
		}
	})
	t.Run("nil verified is accepted", func(t *testing.T) {
		bound, _ := match()
		if err := validateBoundOpenChannel(bound, nil, 5_000); err != nil {
			t.Fatalf("nil verified must skip the transaction cross-check, got %v", err)
		}
	})
	t.Run("payer mismatch", func(t *testing.T) {
		bound, verified := match()
		verified.Payer = "payerB"
		if err := validateBoundOpenChannel(bound, verified, 5_000); err == nil || !strings.Contains(err.Error(), "transaction payer") {
			t.Fatalf("err = %v, want payer rejection", err)
		}
	})
	t.Run("deposit mismatch", func(t *testing.T) {
		bound, verified := match()
		verified.Deposit = 999
		if err := validateBoundOpenChannel(bound, verified, 5_000); err == nil || !strings.Contains(err.Error(), "transaction deposit") {
			t.Fatalf("err = %v, want deposit rejection", err)
		}
	})
	t.Run("salt mismatch", func(t *testing.T) {
		bound, verified := match()
		verified.Salt = 8
		if err := validateBoundOpenChannel(bound, verified, 5_000); err == nil || !strings.Contains(err.Error(), "salt") {
			t.Fatalf("err = %v, want salt rejection", err)
		}
	})
	t.Run("open slot mismatch", func(t *testing.T) {
		bound, verified := match()
		verified.OpenSlot = 43
		if err := validateBoundOpenChannel(bound, verified, 5_000); err == nil || !strings.Contains(err.Error(), "openSlot") {
			t.Fatalf("err = %v, want openSlot rejection", err)
		}
	})
	t.Run("all match", func(t *testing.T) {
		bound, verified := match()
		if err := validateBoundOpenChannel(bound, verified, 5_000); err != nil {
			t.Fatalf("matching bound channel rejected: %v", err)
		}
	})
}

// ── resolveSessionTokenProgram: config validation ──

func TestResolveSessionTokenProgramErrors(t *testing.T) {
	arbitraryMint := solana.NewWallet().PublicKey().String()
	t.Run("arbitrary mint requires explicit program", func(t *testing.T) {
		if _, err := resolveSessionTokenProgram("", arbitraryMint, "mainnet"); err == nil || !strings.Contains(err.Error(), "token program is required") {
			t.Fatalf("err = %v, want arbitrary-mint program requirement", err)
		}
	})
	t.Run("invalid program string", func(t *testing.T) {
		if _, err := resolveSessionTokenProgram("not-base58!!!", "USDC", "mainnet"); err == nil || !strings.Contains(err.Error(), "invalid session token program") {
			t.Fatalf("err = %v, want invalid-program rejection", err)
		}
	})
	t.Run("unsupported program", func(t *testing.T) {
		other := solana.NewWallet().PublicKey().String()
		if _, err := resolveSessionTokenProgram(other, "USDC", "mainnet"); err == nil || !strings.Contains(err.Error(), "unsupported session token program") {
			t.Fatalf("err = %v, want unsupported-program rejection", err)
		}
	})
	t.Run("configured legacy token program is accepted", func(t *testing.T) {
		got, err := resolveSessionTokenProgram(solana.TokenProgramID.String(), "USDC", "mainnet")
		if err != nil || !got.Equals(solana.TokenProgramID) {
			t.Fatalf("got %s, err %v; want the legacy token program", got, err)
		}
	})
}

// ── distribution hash / grace period ──

func TestSessionDistributionHashCommitsSplits(t *testing.T) {
	splits := []Split{
		{Recipient: solana.NewWallet().PublicKey(), BPS: 7_000},
		{Recipient: solana.NewWallet().PublicKey(), BPS: 3_000},
	}
	withSplits := sessionDistributionHash(splits)
	if withSplits == sessionDistributionHash(nil) {
		t.Fatal("non-empty splits must hash differently from the empty distribution")
	}
	if withSplits != sessionDistributionHash(splits) {
		t.Fatal("distribution hash is not deterministic for identical splits")
	}
	reordered := []Split{splits[1], splits[0]}
	if withSplits == sessionDistributionHash(reordered) {
		t.Fatal("distribution hash must be order-sensitive")
	}
}

func TestExpectedSessionGracePeriod(t *testing.T) {
	if got := expectedSessionGracePeriod(SessionConfig{SettlementWindowSeconds: 3_600}); got != 3_600 {
		t.Fatalf("configured window = %d, want 3600", got)
	}
	if got := expectedSessionGracePeriod(SessionConfig{SettlementWindowSeconds: 0}); got != 900 {
		t.Fatalf("zero window = %d, want default 900", got)
	}
	if got := expectedSessionGracePeriod(SessionConfig{SettlementWindowSeconds: int64(^uint32(0)) + 1}); got != 900 {
		t.Fatalf("out-of-range window = %d, want default 900", got)
	}
}

// ── NewOpenStateTxVerifier: signature-only (transactionless) path ──

// signatureOnlyOpenPayload strips the attached transaction so the fixture
// drives the authoritative signature-only branch of the state verifier.
func signatureOnlyOpenPayload(fixture openTxFixture) intents.OpenPayload {
	payload := fixture.payload
	payload.Transaction = nil
	return payload
}

func TestNewOpenStateTxVerifierSignatureOnlySucceeds(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := authoritativeOpenSessionConfig(fixture)
	fake := testutil.NewFakeRPC()
	tx, err := solanatx.DecodeTransactionBase64(*fixture.payload.Transaction)
	if err != nil {
		t.Fatalf("decode fixture transaction: %v", err)
	}
	fake.BySig[fixture.signature] = tx
	confirmedSlot := uint64(4242)
	fake.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		Slot:               confirmedSlot,
	}
	seedSessionChannelAccountWithSeeds(
		t, fake, fixture.channel, openFixtureDeposit, fixture.payer.PublicKey(), fixture.payee,
		fixture.authorized, fixture.mint, pcgen.ChannelStatus_Open, openFixtureSalt, openFixtureOpenSlot,
		fixture.payer.PublicKey(),
	)

	payload := signatureOnlyOpenPayload(fixture)
	result, err := NewOpenStateTxVerifier(config, fake)(context.Background(), &payload)
	if err != nil {
		t.Fatalf("signature-only state verifier: %v", err)
	}
	if result.ChannelID != fixture.channel.String() || result.Deposit != openFixtureDeposit ||
		result.Payer != fixture.payer.PublicKey().String() {
		t.Fatalf("result = %+v, want account-derived channel/deposit/payer", result)
	}
	if result.Salt != openFixtureSalt || result.OpenSlot != openFixtureOpenSlot || result.GracePeriod != openFixtureGrace {
		t.Fatalf("result = %+v, want account-derived seeds/grace", result)
	}
	if fake.LastAccountInfoOpts == nil || fake.LastAccountInfoOpts.MinContextSlot == nil ||
		*fake.LastAccountInfoOpts.MinContextSlot != confirmedSlot {
		t.Fatalf("account read minContextSlot = %#v, want %d", fake.LastAccountInfoOpts, confirmedSlot)
	}
}

func TestNewOpenStateTxVerifierSignatureOnlyRejections(t *testing.T) {
	t.Run("placeholder signature", func(t *testing.T) {
		fixture := buildOpenTxFixture(t, false)
		config := authoritativeOpenSessionConfig(fixture)
		payload := signatureOnlyOpenPayload(fixture)
		payload.Signature = strings.Repeat("1", 64)
		if _, err := NewOpenStateTxVerifier(config, testutil.NewFakeRPC())(context.Background(), &payload); err == nil ||
			!strings.Contains(err.Error(), "placeholder") {
			t.Fatalf("err = %v, want placeholder rejection", err)
		}
	})
	t.Run("push open requires recentSlot", func(t *testing.T) {
		fixture := buildOpenTxFixture(t, false)
		config := authoritativeOpenSessionConfig(fixture)
		payload := signatureOnlyOpenPayload(fixture)
		payload.RecentSlot = nil
		if _, err := NewOpenStateTxVerifier(config, testutil.NewFakeRPC())(context.Background(), &payload); err == nil ||
			!strings.Contains(err.Error(), "recentSlot") {
			t.Fatalf("err = %v, want recentSlot rejection", err)
		}
	})
	t.Run("requires channelId", func(t *testing.T) {
		fixture := buildOpenTxFixture(t, false)
		config := authoritativeOpenSessionConfig(fixture)
		payload := signatureOnlyOpenPayload(fixture)
		payload.ChannelID = nil
		if _, err := NewOpenStateTxVerifier(config, testutil.NewFakeRPC())(context.Background(), &payload); err == nil ||
			!strings.Contains(err.Error(), "channelId") {
			t.Fatalf("err = %v, want channelId rejection", err)
		}
	})
	t.Run("nil rpc client", func(t *testing.T) {
		fixture := buildOpenTxFixture(t, false)
		config := authoritativeOpenSessionConfig(fixture)
		payload := signatureOnlyOpenPayload(fixture)
		if _, err := NewOpenStateTxVerifier(config, nil)(context.Background(), &payload); err == nil ||
			!strings.Contains(err.Error(), "RPC client") {
			t.Fatalf("err = %v, want nil-rpc rejection", err)
		}
	})
	t.Run("nil payload", func(t *testing.T) {
		fixture := buildOpenTxFixture(t, false)
		config := authoritativeOpenSessionConfig(fixture)
		if _, err := NewOpenStateTxVerifier(config, testutil.NewFakeRPC())(context.Background(), nil); err == nil ||
			!strings.Contains(err.Error(), "payload") {
			t.Fatalf("err = %v, want nil-payload rejection", err)
		}
	})
}

// ── verifySignatureOnlyOpen: precondition and fetch rejections ──

func TestVerifySignatureOnlyOpenRejections(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fake := testutil.NewFakeRPC()
	ctx := context.Background()

	t.Run("nil rpc", func(t *testing.T) {
		payload := signatureOnlyOpenPayload(fixture)
		if _, _, err := verifySignatureOnlyOpen(ctx, fixture.expected, &payload, nil); err == nil ||
			!strings.Contains(err.Error(), "requires an RPC client") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("nil payload", func(t *testing.T) {
		if _, _, err := verifySignatureOnlyOpen(ctx, fixture.expected, nil, fake); err == nil ||
			!strings.Contains(err.Error(), "requires a payload") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("placeholder signature", func(t *testing.T) {
		payload := signatureOnlyOpenPayload(fixture)
		payload.Signature = strings.Repeat("1", 64)
		if _, _, err := verifySignatureOnlyOpen(ctx, fixture.expected, &payload, fake); err == nil ||
			!strings.Contains(err.Error(), "real confirmed signature") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing channelId", func(t *testing.T) {
		payload := signatureOnlyOpenPayload(fixture)
		payload.ChannelID = nil
		if _, _, err := verifySignatureOnlyOpen(ctx, fixture.expected, &payload, fake); err == nil ||
			!strings.Contains(err.Error(), "channelId") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("confirmed transaction missing on rpc", func(t *testing.T) {
		payload := signatureOnlyOpenPayload(fixture)
		// Signature confirms (default fake status) but no transaction is
		// registered, so the fetch fails closed instead of binding nothing.
		if _, _, err := verifySignatureOnlyOpen(ctx, fixture.expected, &payload, testutil.NewFakeRPC()); err == nil ||
			!strings.Contains(err.Error(), "fetch confirmed open transaction") {
			t.Fatalf("err = %v", err)
		}
	})
}

// ── fetchAndBindChannelAccount: authoritative-state rejections ──

func TestFetchAndBindChannelAccountRejections(t *testing.T) {
	config := sessionTestConfig()
	mint := solana.MustPublicKeyFromBase58(paycore.ResolveMint(config.Currency, config.Network))
	payee := solana.MustPublicKeyFromBase58(config.Recipient)
	payer := solana.NewWallet().PublicKey()
	signer := solana.NewWallet().PublicKey()
	program := paymentchannels.ProgramPubkey()
	ctx := context.Background()

	t.Run("account not found fails closed", func(t *testing.T) {
		fake := testutil.NewFakeRPC()
		_, err := fetchAndBindChannelAccount(
			ctx, fake, solana.NewWallet().PublicKey(), mint.String(), config.Recipient, payer.String(),
			signer.String(), 900, sessionDistributionHash(nil), true, &program, 1,
		)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("err = %v, want missing-account rejection", err)
		}
	})

	t.Run("authorized signer mismatch", func(t *testing.T) {
		fake := testutil.NewFakeRPC()
		channelID := solana.NewWallet().PublicKey()
		seedSessionChannelAccount(t, fake, channelID, 2_000, payer, payee, signer, mint, pcgen.ChannelStatus_Open, payer)
		_, err := fetchAndBindChannelAccount(
			ctx, fake, channelID, mint.String(), config.Recipient, payer.String(),
			solana.NewWallet().PublicKey().String(), 900, sessionDistributionHash(nil), true, &program, 1,
		)
		if err == nil || !strings.Contains(err.Error(), "authorizedSigner") {
			t.Fatalf("err = %v, want authorized-signer rejection", err)
		}
	})

	t.Run("channel account is not its own PDA", func(t *testing.T) {
		fake := testutil.NewFakeRPC()
		channelID := solana.NewWallet().PublicKey() // arbitrary account, not the derived PDA
		seedSessionChannelAccount(t, fake, channelID, 2_000, payer, payee, signer, mint, pcgen.ChannelStatus_Open, payer)
		_, err := fetchAndBindChannelAccount(
			ctx, fake, channelID, mint.String(), config.Recipient, payer.String(),
			signer.String(), 900, sessionDistributionHash(nil), true, &program, 1,
		)
		if err == nil || !strings.Contains(err.Error(), "PDA derived from authoritative state") {
			t.Fatalf("err = %v, want PDA-mismatch rejection", err)
		}
	})
}

// ── verifyTopUpTx: precondition rejections ──

func TestVerifyTopUpTxPreconditionRejections(t *testing.T) {
	program := paymentchannels.ProgramPubkey()
	fake := testutil.NewFakeRPC()
	ctx := context.Background()
	channel := solana.NewWallet().PublicKey().String()

	t.Run("nil payload", func(t *testing.T) {
		if err := verifyTopUpTx(ctx, fake, program, nil, 1_000); err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("invalid new deposit", func(t *testing.T) {
		payload := &intents.TopUpPayload{ChannelID: channel, NewDeposit: "abc", Signature: confirmedSignature(0x51)}
		if err := verifyTopUpTx(ctx, fake, program, payload, 1_000); err == nil || !strings.Contains(err.Error(), "invalid newDeposit") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("new deposit not increasing", func(t *testing.T) {
		payload := &intents.TopUpPayload{ChannelID: channel, NewDeposit: "1000", Signature: confirmedSignature(0x52)}
		if err := verifyTopUpTx(ctx, fake, program, payload, 1_000); err == nil || !strings.Contains(err.Error(), "must exceed current deposit") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("invalid channel id", func(t *testing.T) {
		payload := &intents.TopUpPayload{ChannelID: "not-base58!!!", NewDeposit: "2000", Signature: confirmedSignature(0x53)}
		if err := verifyTopUpTx(ctx, fake, program, payload, 1_000); err == nil || !strings.Contains(err.Error(), "invalid top-up channel id") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("invalid signature", func(t *testing.T) {
		payload := &intents.TopUpPayload{ChannelID: channel, NewDeposit: "2000", Signature: "not-base58!!!"}
		if err := verifyTopUpTx(ctx, fake, program, payload, 1_000); err == nil || !strings.Contains(err.Error(), "invalid top-up tx signature") {
			t.Fatalf("err = %v", err)
		}
	})
}

// ── NewTopUpStateTxVerifier: confirmation and binding rejections ──

func TestNewTopUpStateTxVerifierRejectsUnconfirmedSignature(t *testing.T) {
	config := sessionTestConfig()
	config.Network = "mainnet"
	fake := testutil.NewFakeRPC()
	signature := confirmedSignature(0x61)
	fake.Statuses[signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusProcessed,
		Slot:               77,
	}
	verifier := NewTopUpStateTxVerifier(config, fake)
	payload := &intents.TopUpPayload{ChannelID: solana.NewWallet().PublicKey().String(), NewDeposit: "2000", Signature: signature}
	if err := verifier(context.Background(), payload, ChannelState{}); err == nil || !strings.Contains(err.Error(), "only processed") {
		t.Fatalf("err = %v, want unconfirmed rejection before any account read", err)
	}
	if fake.LastAccountInfoOpts != nil {
		t.Fatal("channel account was read before signature confirmation")
	}
}

func TestNewTopUpStateTxVerifierRejectsSignatureMismatch(t *testing.T) {
	config := sessionTestConfig()
	config.Network = "mainnet"
	channel := solana.NewWallet().PublicKey()
	tx, payload := buildTopUpTx(t, channel, 1_000_000, 500_000)
	fake := testutil.NewFakeRPC()
	// Register the confirmed transaction under a signature that is not its own
	// fee-payer signature, so the fetched tx fails the signature-binding check.
	wrongSignature := confirmedSignature(0x62)
	fake.BySig[wrongSignature] = tx
	payload.Signature = wrongSignature
	verifier := NewTopUpStateTxVerifier(config, fake)
	current := ChannelState{AuthorizedSigner: solana.NewWallet().PublicKey().String(), Deposit: 1_000_000}
	if err := verifier(context.Background(), payload, current); err == nil ||
		!strings.Contains(err.Error(), "signature does not match payload signature") {
		t.Fatalf("err = %v, want fetched-signature mismatch rejection", err)
	}
}

func TestNewTopUpStateTxVerifierRejectsStoredPayerMismatch(t *testing.T) {
	config := sessionTestConfig() // localnet: binds directly to on-chain state
	fake := testutil.NewFakeRPC()
	channelID := solana.NewWallet().PublicKey()
	payer := solana.NewWallet().PublicKey()
	signer := solana.NewWallet().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.ResolveMint(config.Currency, config.Network))
	seedSessionChannelAccount(
		t, fake, channelID, 3_000, payer,
		solana.MustPublicKeyFromBase58(config.Recipient), signer, mint, pcgen.ChannelStatus_Open,
	)
	verifier := NewTopUpStateTxVerifier(config, fake)
	otherPayer := solana.NewWallet().PublicKey().String()
	current := ChannelState{AuthorizedSigner: signer.String(), Operator: &otherPayer, Deposit: 1_000}
	payload := &intents.TopUpPayload{ChannelID: channelID.String(), NewDeposit: "3000", Signature: confirmedSignature(0x63)}
	if err := verifier(context.Background(), payload, current); err == nil ||
		!strings.Contains(err.Error(), "does not match stored payer") {
		t.Fatalf("err = %v, want stored-payer mismatch rejection", err)
	}
}

// ── NewTopUpStateTxVerifier: precondition rejections ──

func TestNewTopUpStateTxVerifierPreconditionRejections(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid new deposit", func(t *testing.T) {
		config := sessionTestConfig()
		config.Network = "mainnet"
		fake := testutil.NewFakeRPC()
		verifier := NewTopUpStateTxVerifier(config, fake)
		payload := &intents.TopUpPayload{ChannelID: solana.NewWallet().PublicKey().String(), NewDeposit: "abc", Signature: confirmedSignature(0x54)}
		if err := verifier(ctx, payload, ChannelState{}); err == nil || !strings.Contains(err.Error(), "invalid newDeposit") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("unresolvable currency mint", func(t *testing.T) {
		config := sessionTestConfig()
		config.Network = "mainnet"
		config.Currency = "SOL" // ResolveMint returns "" for the native mint
		fake := testutil.NewFakeRPC()
		verifier := NewTopUpStateTxVerifier(config, fake)
		payload := &intents.TopUpPayload{ChannelID: solana.NewWallet().PublicKey().String(), NewDeposit: "2000", Signature: confirmedSignature(0x55)}
		if err := verifier(ctx, payload, ChannelState{}); err == nil || !strings.Contains(err.Error(), "requires an SPL token") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("invalid channel id", func(t *testing.T) {
		config := sessionTestConfig()
		config.Network = "mainnet"
		fake := testutil.NewFakeRPC()
		verifier := NewTopUpStateTxVerifier(config, fake)
		payload := &intents.TopUpPayload{ChannelID: "not-base58!!!", NewDeposit: "2000", Signature: confirmedSignature(0x56)}
		if err := verifier(ctx, payload, ChannelState{}); err == nil || !strings.Contains(err.Error(), "invalid channelId") {
			t.Fatalf("err = %v", err)
		}
	})
}
