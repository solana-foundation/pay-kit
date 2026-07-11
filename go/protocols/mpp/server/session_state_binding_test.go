package server

import (
	"bytes"
	"context"
	"strings"
	"testing"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

type durableTestChannelStore struct{ ChannelStore }

func (durableTestChannelStore) SessionStoreDurability() SessionStoreDurability {
	return SessionStoreDurabilityDurableShared
}

func seedSessionChannelAccount(
	t *testing.T,
	fake *testutil.FakeRPC,
	channelID solana.PublicKey,
	deposit uint64,
	payer, payee, signer, mint solana.PublicKey,
	status pcgen.ChannelStatus,
	rentPayers ...solana.PublicKey,
) {
	seedSessionChannelAccountWithSeeds(t, fake, channelID, deposit, payer, payee, signer, mint, status, 7, 42, rentPayers...)
}

func seedSessionChannelAccountWithSeeds(
	t *testing.T,
	fake *testutil.FakeRPC,
	channelID solana.PublicKey,
	deposit uint64,
	payer, payee, signer, mint solana.PublicKey,
	status pcgen.ChannelStatus,
	salt, openSlot uint64,
	rentPayers ...solana.PublicKey,
) {
	t.Helper()
	rentPayer := payee
	if len(rentPayers) > 0 {
		rentPayer = rentPayers[0]
	}
	account := pcgen.Channel{
		Discriminator:    1,
		Version:          1,
		Status:           uint8(status),
		Deposit:          deposit,
		GracePeriod:      900,
		DistributionHash: sessionDistributionHash(nil),
		Payer:            payer,
		Payee:            payee,
		AuthorizedSigner: signer,
		Mint:             mint,
		RentPayer:        rentPayer,
		Salt:             salt,
		OpenSlot:         openSlot,
	}
	buf := new(bytes.Buffer)
	if err := account.MarshalWithEncoder(bin.NewBorshEncoder(buf)); err != nil {
		t.Fatalf("encode channel account: %v", err)
	}
	fake.SetAccount(channelID, paymentchannels.ProgramPubkey(), buf.Bytes())
}

func TestSessionBarePushOpenUsesAuthoritativeChannelState(t *testing.T) {
	fake := testutil.NewFakeRPC()
	payerKey := testutil.NewPrivateKey()
	payer := payerKey.PublicKey()
	signer := solana.NewWallet().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.ResolveMint("USDC", "localnet"))
	recipient := solana.MustPublicKeyFromBase58(sessionTestRecipient)
	channelID, _, err := paymentchannels.FindChannelPDAForProgram(
		payer, recipient, mint, signer, 7, 42, paymentchannels.ProgramPubkey(),
	)
	if err != nil {
		t.Fatalf("derive channel: %v", err)
	}
	seedSessionChannelAccount(
		t, fake, channelID, 4_000, payer,
		recipient, signer, mint, pcgen.ChannelStatus_Open,
	)

	session := newTestSession(t, func(options *SessionOptions) { options.RPC = fake })
	payload := intents.OpenPayloadPush(channelID.String(), "4000", signer.String(), confirmedSignature(0x31))
	claimedPayer := solana.NewWallet().PublicKey().String()
	payload.Payer = &claimedPayer
	registerSignatureOnlyOpenTransaction(t, session, &payload, payerKey, 4_000)
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(payload)); err != nil {
		t.Fatalf("open: %v", err)
	}
	state := mustGetChannel(t, session, channelID.String())
	if state.Deposit != 4_000 {
		t.Fatalf("deposit = %d, want on-chain 4000", state.Deposit)
	}
	if state.Operator == nil || *state.Operator != payer.String() {
		t.Fatalf("payer = %v, want on-chain %s", state.Operator, payer)
	}
	if state.OpenSlot != 42 {
		t.Fatalf("open slot = %d, want authoritative 42", state.OpenSlot)
	}
	if state.Salt != 7 {
		t.Fatalf("salt = %d, want authoritative 7", state.Salt)
	}
}

func TestSessionServerRejectsLegacyOpenVerifierOffLocalnet(t *testing.T) {
	fake := testutil.NewFakeRPC()
	config := sessionTestConfig()
	config.Network = "devnet"
	config.VerifyOpenTx = NewOpenTxVerifier(config, fake)
	server := NewSessionServer(config, durableTestChannelStore{ChannelStore: NewMemoryChannelStore()})

	signer := solana.NewWallet().PublicKey()
	signature := confirmedSignature(0x61)
	fake.Statuses[signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		Slot:               99,
	}
	payload := intents.OpenPayloadPush(
		solana.NewWallet().PublicKey().String(),
		"999999",
		signer.String(),
		signature,
	)
	if _, err := server.ProcessOpen(context.Background(), &payload); err == nil ||
		!strings.Contains(err.Error(), "authoritative state") {
		t.Fatalf("legacy verifier error = %v, want authoritative-state rejection", err)
	}
	state, err := server.Store().GetChannel(context.Background(), *payload.ChannelID)
	if err != nil {
		t.Fatalf("GetChannel: %v", err)
	}
	if state != nil {
		t.Fatalf("channel persisted despite legacy verifier: %+v", state)
	}
}

func TestSessionServerStateAwareOpenPersistsAuthoritativeChannelFacts(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fake := testutil.NewFakeRPC()
	config := authoritativeOpenSessionConfig(fixture)
	config.VerifyOpenStateTx = NewOpenStateTxVerifier(config, fake)
	server := NewSessionServer(config, durableTestChannelStore{ChannelStore: NewMemoryChannelStore()})
	fake.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		Slot:               777,
	}
	seedSessionChannelAccountWithSeeds(
		t, fake, fixture.channel, openFixtureDeposit, fixture.payer.PublicKey(), fixture.payee,
		fixture.authorized, fixture.mint, pcgen.ChannelStatus_Open, openFixtureSalt, openFixtureOpenSlot,
		fixture.payer.PublicKey(),
	)

	state, err := server.ProcessOpen(context.Background(), &fixture.payload)
	if err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
	if state.Deposit != openFixtureDeposit || state.Salt != openFixtureSalt || state.OpenSlot != openFixtureOpenSlot {
		t.Fatalf("state = %+v, want authoritative deposit/salt/openSlot", state)
	}
	if state.Operator == nil || *state.Operator != fixture.payer.PublicKey().String() {
		t.Fatalf("operator = %v, want on-chain payer %s", state.Operator, fixture.payer.PublicKey())
	}
}

func TestSessionCoreRejectsPreloadedEphemeralStateOperations(t *testing.T) {
	config := sessionTestConfig()
	config.Network = "mainnet"
	server := NewSessionServer(config, NewMemoryChannelStore())
	ctx := context.Background()
	tests := map[string]func() error{
		"voucher": func() error {
			_, err := server.VerifyVoucherDetailed(ctx, &intents.VoucherPayload{})
			return err
		},
		"delivery": func() error {
			_, err := server.BeginDelivery(ctx, DeliveryRequest{})
			return err
		},
		"commit": func() error {
			_, err := server.ProcessCommit(ctx, &intents.CommitPayload{})
			return err
		},
		"close": func() error {
			_, err := server.ProcessClose(ctx, &intents.ClosePayload{})
			return err
		},
		"settlement": func() error {
			_, err := server.SettlementInstructions(ctx, "channel", solana.PublicKey{})
			return err
		},
		"seal": func() error { return server.MarkSealed(ctx, "channel") },
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil || !strings.Contains(err.Error(), "ephemeral session store") {
				t.Fatalf("safety error = %v", err)
			}
		})
	}
}

func TestTopUpVerifierBindsResultingDepositAndStatus(t *testing.T) {
	fake := testutil.NewFakeRPC()
	config := sessionTestConfig()
	channelID := solana.NewWallet().PublicKey()
	payer := solana.NewWallet().PublicKey()
	signer := solana.NewWallet().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.ResolveMint(config.Currency, config.Network))
	seedSessionChannelAccount(
		t, fake, channelID, 2_000, payer,
		solana.MustPublicKeyFromBase58(config.Recipient), signer, mint, pcgen.ChannelStatus_Open,
	)
	verifier := NewTopUpStateTxVerifier(config, fake)
	storedPayer := payer.String()
	current := ChannelState{AuthorizedSigner: signer.String(), Operator: &storedPayer, Deposit: 1_000}
	payload := &intents.TopUpPayload{
		ChannelID: channelID.String(), NewDeposit: "3000", Signature: confirmedSignature(0x32),
	}
	current.AuthorizedSigner = solana.NewWallet().PublicKey().String()
	if err := verifier(context.Background(), payload, current); err == nil || !strings.Contains(err.Error(), "stored signer") {
		t.Fatalf("authorized signer mismatch error = %v", err)
	}
	current.AuthorizedSigner = signer.String()
	if err := verifier(context.Background(), payload, current); err == nil || !strings.Contains(err.Error(), "!= asserted") {
		t.Fatalf("mismatched deposit error = %v", err)
	}

	seedSessionChannelAccount(
		t, fake, channelID, 3_000, payer,
		solana.MustPublicKeyFromBase58(config.Recipient), signer, mint, pcgen.ChannelStatus_Sealed,
	)
	if err := verifier(context.Background(), payload, current); err == nil || !strings.Contains(err.Error(), "not open") {
		t.Fatalf("sealed channel error = %v", err)
	}
}

func TestTopUpVerifierFailsClosedWithoutRPCOffLocalnet(t *testing.T) {
	config := sessionTestConfig()
	config.Network = "mainnet"
	verifier := NewTopUpStateTxVerifier(config, nil)
	if verifier == nil {
		t.Fatal("off-localnet verifier must fail closed, not be nil")
	}
	err := verifier(context.Background(), &intents.TopUpPayload{}, ChannelState{})
	if err == nil || !strings.Contains(err.Error(), "requires an rpc client") {
		t.Fatalf("error = %v", err)
	}
}

func TestSessionCoreRejectsDirectNonlocalnetBypasses(t *testing.T) {
	durable := durableTestChannelStore{ChannelStore: NewMemoryChannelStore()}
	config := sessionTestConfig()
	config.Network = "mainnet"
	config.VerifyTopUpTx = func(context.Context, *intents.TopUpPayload) (string, error) { return "", nil }
	server := NewSessionServer(config, durable)
	payload := intents.OpenPayloadPush(solana.NewWallet().PublicKey().String(), "1000", solana.NewWallet().PublicKey().String(), confirmedSignature(0x44))
	if _, err := server.ProcessOpen(context.Background(), &payload); err == nil || !strings.Contains(err.Error(), "requires an on-chain verifier") {
		t.Fatalf("direct open bypass error = %v", err)
	}
	_, _ = durable.UpdateChannel(context.Background(), "topup", func(*ChannelState) (ChannelState, error) {
		payer := solana.NewWallet().PublicKey().String()
		return ChannelState{ChannelID: "topup", AuthorizedSigner: solana.NewWallet().PublicKey().String(), Deposit: 1_000, Operator: &payer}, nil
	})
	if _, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{ChannelID: "topup", NewDeposit: "2000", Signature: confirmedSignature(0x46)}); err == nil || !strings.Contains(err.Error(), "state-aware on-chain verifier") {
		t.Fatalf("direct top-up bypass error = %v", err)
	}
	if _, err := NewSessionServer(config, NewMemoryChannelStore()).ProcessOpen(context.Background(), &payload); err == nil || !strings.Contains(err.Error(), "ephemeral") {
		t.Fatalf("direct memory-store bypass error = %v", err)
	}
	unknown := struct{ ChannelStore }{ChannelStore: NewMemoryChannelStore()}
	if _, err := NewSessionServer(config, unknown).ProcessOpen(context.Background(), &payload); err == nil || !strings.Contains(err.Error(), "explicitly declare durable shared") {
		t.Fatalf("direct unmarked-store bypass error = %v", err)
	}
}

func TestConfirmedTransactionSlotRejectsProcessedAndPinsAccountRead(t *testing.T) {
	fake := testutil.NewFakeRPC()
	signature := confirmedSignature(0x45)
	fake.Statuses[signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusProcessed,
		Slot:               77,
	}
	if _, err := confirmedTransactionSlot(context.Background(), fake, signature, "top-up"); err == nil || !strings.Contains(err.Error(), "only processed") {
		t.Fatalf("processed status error = %v", err)
	}
	fake.Statuses[signature].ConfirmationStatus = rpc.ConfirmationStatusConfirmed
	config := sessionTestConfig()
	channelID := solana.NewWallet().PublicKey()
	payer := solana.NewWallet().PublicKey()
	signer := solana.NewWallet().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.ResolveMint(config.Currency, config.Network))
	seedSessionChannelAccount(t, fake, channelID, 2_000, payer, solana.MustPublicKeyFromBase58(config.Recipient), signer, mint, pcgen.ChannelStatus_Open)
	storedPayer := payer.String()
	err := NewTopUpStateTxVerifier(config, fake)(context.Background(), &intents.TopUpPayload{
		ChannelID: channelID.String(), NewDeposit: "2000", Signature: signature,
	}, ChannelState{AuthorizedSigner: signer.String(), Deposit: 1_000, Operator: &storedPayer})
	if err != nil {
		t.Fatalf("top-up verifier: %v", err)
	}
	if fake.LastAccountInfoOpts == nil || fake.LastAccountInfoOpts.MinContextSlot == nil || *fake.LastAccountInfoOpts.MinContextSlot != 77 {
		t.Fatalf("account read minContextSlot = %#v", fake.LastAccountInfoOpts)
	}
}

func TestChannelAccountRejectsInvalidHeaderAndLength(t *testing.T) {
	fake := testutil.NewFakeRPC()
	config := sessionTestConfig()
	channelID := solana.NewWallet().PublicKey()
	payer := solana.NewWallet().PublicKey()
	signer := solana.NewWallet().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.ResolveMint(config.Currency, config.Network))
	seedSessionChannelAccount(t, fake, channelID, 2_000, payer, solana.MustPublicKeyFromBase58(config.Recipient), signer, mint, pcgen.ChannelStatus_Open)
	valid := append([]byte(nil), fake.Accounts[channelID.String()].Data.GetBinary()...)
	for name, data := range map[string][]byte{
		"discriminator": append([]byte{9}, valid[1:]...),
		"version":       append(append([]byte(nil), valid[:1]...), append([]byte{9}, valid[2:]...)...),
		"length":        valid[:len(valid)-1],
	} {
		t.Run(name, func(t *testing.T) {
			fake.SetAccount(channelID, paymentchannels.ProgramPubkey(), data)
			_, err := fetchAndValidateChannel(context.Background(), fake, channelID, mint.String(), config.Recipient, config.Operator, 900, sessionDistributionHash(nil), true, config.ProgramID, 1)
			if err == nil {
				t.Fatal("malformed Channel account accepted")
			}
		})
	}
}

func TestChannelAccountRejectsSpentOrEconomicallyMismatchedState(t *testing.T) {
	fake := testutil.NewFakeRPC()
	config := sessionTestConfig()
	channelID := solana.NewWallet().PublicKey()
	payer := solana.NewWallet().PublicKey()
	signer := solana.NewWallet().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.ResolveMint(config.Currency, config.Network))
	payee := solana.MustPublicKeyFromBase58(config.Recipient)
	seedSessionChannelAccount(t, fake, channelID, 2_000, payer, payee, signer, mint, pcgen.ChannelStatus_Open)
	valid := append([]byte(nil), fake.Accounts[channelID.String()].Data.GetBinary()...)
	var decoded pcgen.Channel
	if err := decoded.UnmarshalWithDecoder(bin.NewBorshDecoder(valid)); err != nil {
		t.Fatalf("decode channel: %v", err)
	}

	cases := map[string]func(*pcgen.Channel){
		"settled":           func(channel *pcgen.Channel) { channel.Settlement.Settled = 1 },
		"payout watermark":  func(channel *pcgen.Channel) { channel.Settlement.PayoutWatermark = 1 },
		"grace period":      func(channel *pcgen.Channel) { channel.GracePeriod++ },
		"distribution hash": func(channel *pcgen.Channel) { channel.DistributionHash[0] ^= 0xff },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			channel := decoded
			mutate(&channel)
			buf := new(bytes.Buffer)
			if err := channel.MarshalWithEncoder(bin.NewBorshEncoder(buf)); err != nil {
				t.Fatalf("encode channel: %v", err)
			}
			fake.SetAccount(channelID, paymentchannels.ProgramPubkey(), buf.Bytes())
			_, err := fetchAndValidateChannel(context.Background(), fake, channelID, mint.String(), config.Recipient, config.Operator, 900, sessionDistributionHash(nil), true, config.ProgramID, 1)
			if err == nil {
				t.Fatal("economically mismatched Channel account accepted")
			}
		})
	}
}
