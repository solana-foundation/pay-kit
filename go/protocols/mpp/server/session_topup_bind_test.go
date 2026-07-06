package server

// Regression coverage for the in-core top-up deposit bind.
//
// The exported core ProcessTopUp must not trust a client-asserted newDeposit:
// the shipped top-up seam fetches the on-chain Channel account and requires its
// deposit to have actually reached newDeposit, failing closed off localnet.
// These tests exercise the seam directly through ProcessTopUp and through the
// production-wired Session.handleTopUp path.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

// seedTopUpChannelAccount registers an open on-chain Channel account for
// channelID on the fake RPC with the given deposit, mint, payee, and
// authorizedSigner so the top-up bind reads authoritative state.
func seedTopUpChannelAccount(t *testing.T, fake *testutil.FakeRPC, channelID string, deposit uint64, mint, payee, authorizedSigner string) {
	t.Helper()
	acct := &pcgen.Channel{
		Discriminator:    uint8(pcgen.AccountDiscriminator_Channel),
		Status:           uint8(pcgen.ChannelStatus_Open),
		Deposit:          deposit,
		GracePeriod:      900,
		Payer:            solana.NewWallet().PublicKey(),
		Payee:            solana.MustPublicKeyFromBase58(payee),
		AuthorizedSigner: solana.MustPublicKeyFromBase58(authorizedSigner),
		Mint:             solana.MustPublicKeyFromBase58(mint),
		RentPayer:        solana.MustPublicKeyFromBase58(payee),
	}
	buf := new(bytes.Buffer)
	if err := acct.MarshalWithEncoder(bin.NewBorshEncoder(buf)); err != nil {
		t.Fatalf("encode channel account: %v", err)
	}
	fake.SetAccount(solana.MustPublicKeyFromBase58(channelID), paymentchannels.ProgramPubkey(), buf.Bytes())
}

// TestProcessTopUpBindsDepositThroughShippedSeam proves the exported core
// ProcessTopUp rejects a fabricated newDeposit when wired with the shipped
// top-up seam: the on-chain Channel shows a smaller deposit, so the bind must
// reject before the range checks pass and the write lands.
func TestProcessTopUpBindsDepositThroughShippedSeam(t *testing.T) {
	fake := testutil.NewFakeRPC()
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	mint := paycore.ResolveMint("USDC", "mainnet")

	config := SessionConfig{
		Operator:  sessionTestRecipient,
		Recipient: sessionTestRecipient,
		MaxCap:    10_000_000,
		Currency:  "USDC",
		Decimals:  6,
		Network:   "mainnet",
		Modes:     []intents.SessionMode{intents.SessionModePush},
	}
	// The shipped seam performs the deposit bind, not just signature liveness.
	config.VerifyTopUpTx = NewTopUpTxVerifier(config, fake)
	server := NewSessionServer(config, NewMemoryChannelStore())

	// Open the channel at 1_000_000 (bare push open, trusted here for setup).
	openPayload := intents.OpenPayloadPush(channelID, "1000000", signer.Address(), confirmedSignature(0x77))
	payer := solana.NewWallet().PublicKey().String()
	openPayload.Payer = &payer
	if _, err := server.ProcessOpen(context.Background(), &openPayload); err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}

	// The on-chain channel only reached 3_000_000; the client fabricates 5_000_000.
	seedTopUpChannelAccount(t, fake, channelID, 3_000_000, mint, sessionTestRecipient, signer.Address())
	_, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID:  channelID,
		NewDeposit: "5000000",
		Signature:  confirmedSignature(0x88),
	})
	if err == nil || !strings.Contains(err.Error(), "!= asserted newDeposit 5000000") {
		t.Fatalf("err = %v, want on-chain deposit-bind rejection", err)
	}
	state, getErr := server.Store().GetChannel(context.Background(), channelID)
	if getErr != nil || state == nil {
		t.Fatalf("GetChannel: state=%v err=%v", state, getErr)
	}
	if state.Deposit != 1_000_000 {
		t.Fatalf("deposit = %d, want unchanged 1000000 (fabricated top-up must not land)", state.Deposit)
	}
}

// TestProcessTopUpBindFailsClosedWithoutRPCOffLocalnet proves the shipped seam
// fails closed when no RPC client is configured off localnet: the raised
// deposit cannot be bound to on-chain state.
func TestProcessTopUpBindFailsClosedWithoutRPCOffLocalnet(t *testing.T) {
	config := SessionConfig{
		Operator:  sessionTestRecipient,
		Recipient: sessionTestRecipient,
		MaxCap:    10_000_000,
		Currency:  "USDC",
		Decimals:  6,
		Network:   "mainnet",
		Modes:     []intents.SessionMode{intents.SessionModePush},
	}
	// No RPC: off localnet the seam must be an erroring bind, never nil.
	config.VerifyTopUpTx = NewTopUpTxVerifier(config, nil)
	if config.VerifyTopUpTx == nil {
		t.Fatal("NewTopUpTxVerifier(config, nil) off localnet must return a fail-closed seam, not nil")
	}
	server := NewSessionServer(config, NewMemoryChannelStore())

	channelID := solana.NewWallet().PublicKey().String()
	signer := newTestVoucherSigner(t)
	openPayload := intents.OpenPayloadPush(channelID, "1000000", signer.Address(), confirmedSignature(0x11))
	payer := solana.NewWallet().PublicKey().String()
	openPayload.Payer = &payer
	if _, err := server.ProcessOpen(context.Background(), &openPayload); err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}

	_, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID:  channelID,
		NewDeposit: "5000000",
		Signature:  confirmedSignature(0x22),
	})
	if err == nil || !strings.Contains(err.Error(), "requires an rpc client") {
		t.Fatalf("err = %v, want fail-closed rejection off localnet without rpc", err)
	}
}

// TestFetchAndBindChannelAccountEmptyExpectedSignerFailsClosed proves an empty
// expected authorized signer no longer short-circuits the on-chain
// authorizedSigner compare, so a mismatch fails closed rather than being
// skipped.
func TestFetchAndBindChannelAccountEmptyExpectedSignerFailsClosed(t *testing.T) {
	fake := testutil.NewFakeRPC()
	channelID := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey().String()
	payee := solana.NewWallet().PublicKey().String()
	onChainSigner := solana.NewWallet().PublicKey().String()

	acct := &pcgen.Channel{
		Discriminator:    uint8(pcgen.AccountDiscriminator_Channel),
		Status:           uint8(pcgen.ChannelStatus_Open),
		Deposit:          1_000,
		GracePeriod:      900,
		Payer:            solana.NewWallet().PublicKey(),
		Payee:            solana.MustPublicKeyFromBase58(payee),
		AuthorizedSigner: solana.MustPublicKeyFromBase58(onChainSigner),
		Mint:             solana.MustPublicKeyFromBase58(mint),
		RentPayer:        solana.MustPublicKeyFromBase58(payee),
	}
	buf := new(bytes.Buffer)
	if err := acct.MarshalWithEncoder(bin.NewBorshEncoder(buf)); err != nil {
		t.Fatalf("encode channel: %v", err)
	}
	fake.SetAccount(channelID, paymentchannels.ProgramPubkey(), buf.Bytes())

	// An empty expected signer must NOT skip the compare: the on-chain signer is
	// non-empty and unmatched, so the bind fails closed.
	_, err := fetchAndBindChannelAccount(context.Background(), fake, channelID, mint, payee, "", nil)
	if err == nil || !strings.Contains(err.Error(), "authorizedSigner") {
		t.Fatalf("err = %v, want empty-expected-signer fail-closed rejection", err)
	}
}

// TestSessionTopUpProductionWiresTheBindSeam proves the bind is production
// wired: the real Session.handleTopUp path rejects a fabricated newDeposit that
// the on-chain Channel does not back, through the installed seam.
func TestSessionTopUpProductionWiresTheBindSeam(t *testing.T) {
	fake := testutil.NewFakeRPC()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.Network = "mainnet"
		o.Store = NewMemoryChannelStore()
	})
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	openSessionChannel(t, session, channelID, 1_000_000, signer.Address(), confirmedSignature(0x33))

	// On-chain the channel only reached 2_000_000; the client asserts 4_000_000.
	mint := paycore.ResolveMint(session.currency, session.network)
	seedTopUpChannelAccount(t, fake, channelID, 2_000_000, mint, session.recipient, signer.Address())
	_, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "4000000", Signature: confirmedSignature(0x44),
	}))
	if err == nil || !strings.Contains(err.Error(), "!= asserted newDeposit 4000000") {
		t.Fatalf("err = %v, want on-chain deposit-bind rejection through the wired seam", err)
	}
	if mustGetChannel(t, session, channelID).Deposit != 1_000_000 {
		t.Fatal("deposit raised despite on-chain mismatch through the production path")
	}
}

// topUpBindConfig returns a mainnet SessionConfig wired for the on-chain top-up
// deposit bind against the shared USDC mint and the test recipient.
func topUpBindConfig() SessionConfig {
	return SessionConfig{
		Operator:  sessionTestRecipient,
		Recipient: sessionTestRecipient,
		MaxCap:    10_000_000,
		Currency:  "USDC",
		Decimals:  6,
		Network:   "mainnet",
		Modes:     []intents.SessionMode{intents.SessionModePush},
	}
}

// seedChannelAccountWithStatus registers a Channel account for channelID with an
// explicit status/mint/payee so the on-chain bind can be driven down each
// mismatch branch. A well-formed but non-open (or otherwise mismatched) account
// must still be rejected.
func seedChannelAccountWithStatus(t *testing.T, fake *testutil.FakeRPC, channelID string, deposit uint64, status uint8, mint, payee string) {
	t.Helper()
	acct := &pcgen.Channel{
		Discriminator:    uint8(pcgen.AccountDiscriminator_Channel),
		Status:           status,
		Deposit:          deposit,
		GracePeriod:      900,
		Payer:            solana.NewWallet().PublicKey(),
		Payee:            solana.MustPublicKeyFromBase58(payee),
		AuthorizedSigner: solana.NewWallet().PublicKey(),
		Mint:             solana.MustPublicKeyFromBase58(mint),
		RentPayer:        solana.MustPublicKeyFromBase58(payee),
	}
	buf := new(bytes.Buffer)
	if err := acct.MarshalWithEncoder(bin.NewBorshEncoder(buf)); err != nil {
		t.Fatalf("encode channel account: %v", err)
	}
	fake.SetAccount(solana.MustPublicKeyFromBase58(channelID), paymentchannels.ProgramPubkey(), buf.Bytes())
}

// TestTopUpBindRejectsUnfetchableOrMalformedAccount drives the on-chain top-up
// bind down each rejection branch that guards the raised deposit: an
// unfetchable account, an account owned by the wrong program, empty or
// undecodable account data, a non-open channel, and mint / payee mismatches.
// Every one must fail closed rather than trust the client-asserted newDeposit.
func TestTopUpBindRejectsUnfetchableOrMalformedAccount(t *testing.T) {
	mint := paycore.ResolveMint("USDC", "mainnet")
	otherMint := solana.NewWallet().PublicKey().String()
	otherPayee := solana.NewWallet().PublicKey().String()

	cases := []struct {
		name    string
		seed    func(t *testing.T, fake *testutil.FakeRPC, channelID string)
		wantErr string
	}{
		{
			name:    "account not found",
			seed:    func(_ *testing.T, _ *testutil.FakeRPC, _ string) {}, // never seeded
			wantErr: "account fetch failed",
		},
		{
			name: "wrong owner",
			seed: func(_ *testing.T, fake *testutil.FakeRPC, channelID string) {
				fake.SetAccount(
					solana.MustPublicKeyFromBase58(channelID),
					solana.NewWallet().PublicKey(), // not the payment-channels program
					[]byte{1, 2, 3, 4},
				)
			},
			wantErr: "is not owned by the payment-channels program",
		},
		{
			name: "empty account data",
			seed: func(_ *testing.T, fake *testutil.FakeRPC, channelID string) {
				fake.SetAccount(
					solana.MustPublicKeyFromBase58(channelID),
					paymentchannels.ProgramPubkey(),
					[]byte{},
				)
			},
			wantErr: "account data is empty",
		},
		{
			name: "undecodable account data",
			seed: func(_ *testing.T, fake *testutil.FakeRPC, channelID string) {
				fake.SetAccount(
					solana.MustPublicKeyFromBase58(channelID),
					paymentchannels.ProgramPubkey(),
					[]byte{0xff}, // one byte: the Borsh Channel decode cannot complete
				)
			},
			wantErr: "decode failed",
		},
		{
			name: "channel not open on-chain",
			seed: func(t *testing.T, fake *testutil.FakeRPC, channelID string) {
				seedChannelAccountWithStatus(t, fake, channelID, 5_000_000, uint8(pcgen.ChannelStatus_Closing), mint, sessionTestRecipient)
			},
			wantErr: "is not open on-chain",
		},
		{
			name: "mint mismatch",
			seed: func(t *testing.T, fake *testutil.FakeRPC, channelID string) {
				seedChannelAccountWithStatus(t, fake, channelID, 5_000_000, uint8(pcgen.ChannelStatus_Open), otherMint, sessionTestRecipient)
			},
			wantErr: "!= expected mint",
		},
		{
			name: "payee mismatch",
			seed: func(t *testing.T, fake *testutil.FakeRPC, channelID string) {
				seedChannelAccountWithStatus(t, fake, channelID, 5_000_000, uint8(pcgen.ChannelStatus_Open), mint, otherPayee)
			},
			wantErr: "!= expected recipient",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := testutil.NewFakeRPC()
			config := topUpBindConfig()
			verify := NewTopUpTxVerifier(config, fake)
			if verify == nil {
				t.Fatal("NewTopUpTxVerifier off localnet must install a seam")
			}
			channelID := solana.NewWallet().PublicKey().String()
			tc.seed(t, fake, channelID)

			_, err := verify(context.Background(), &intents.TopUpPayload{
				ChannelID:  channelID,
				NewDeposit: "5000000",
				Signature:  confirmedSignature(0x99),
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestTopUpBindRejectsInvalidChannelID proves the seam rejects a malformed
// channelId before any RPC read: the base58 decode fails closed.
func TestTopUpBindRejectsInvalidChannelID(t *testing.T) {
	fake := testutil.NewFakeRPC()
	verify := NewTopUpTxVerifier(topUpBindConfig(), fake)
	if verify == nil {
		t.Fatal("NewTopUpTxVerifier off localnet must install a seam")
	}
	_, err := verify(context.Background(), &intents.TopUpPayload{
		ChannelID:  "not-a-valid-base58-pubkey!!!",
		NewDeposit: "5000000",
		Signature:  confirmedSignature(0x55),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid channelId") {
		t.Fatalf("err = %v, want invalid-channelId rejection", err)
	}
}

// TestTopUpBindRejectsNonNumericNewDeposit proves the seam rejects a
// non-numeric newDeposit before any on-chain read.
func TestTopUpBindRejectsNonNumericNewDeposit(t *testing.T) {
	fake := testutil.NewFakeRPC()
	verify := NewTopUpTxVerifier(topUpBindConfig(), fake)
	if verify == nil {
		t.Fatal("NewTopUpTxVerifier off localnet must install a seam")
	}
	_, err := verify(context.Background(), &intents.TopUpPayload{
		ChannelID:  solana.NewWallet().PublicKey().String(),
		NewDeposit: "not-a-number",
		Signature:  confirmedSignature(0x66),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid newDeposit") {
		t.Fatalf("err = %v, want invalid-newDeposit rejection", err)
	}
}

// TestTopUpBindRejectsNonSPLCurrency proves a payment-channel top-up on a
// currency that resolves to no SPL mint (e.g. native SOL) fails closed: the
// on-chain deposit bind is meaningless without a token mint to match.
func TestTopUpBindRejectsNonSPLCurrency(t *testing.T) {
	fake := testutil.NewFakeRPC()
	config := topUpBindConfig()
	config.Currency = "SOL" // resolves to an empty mint
	verify := NewTopUpTxVerifier(config, fake)
	if verify == nil {
		t.Fatal("NewTopUpTxVerifier off localnet must install a seam")
	}
	_, err := verify(context.Background(), &intents.TopUpPayload{
		ChannelID:  solana.NewWallet().PublicKey().String(),
		NewDeposit: "5000000",
		Signature:  confirmedSignature(0x44),
	})
	if err == nil || !strings.Contains(err.Error(), "requires an SPL token") {
		t.Fatalf("err = %v, want non-SPL-currency rejection", err)
	}
}

// TestTopUpBindLocalnetWithoutRPCDisablesSeam proves that on localnet a nil RPC
// leaves the seam unset (nil) so unit-test / out-of-band-verified deployments
// trust the provided deposit, while off localnet the same nil RPC fails closed.
func TestTopUpBindLocalnetWithoutRPCDisablesSeam(t *testing.T) {
	config := topUpBindConfig()
	config.Network = "localnet"
	if seam := NewTopUpTxVerifier(config, nil); seam != nil {
		t.Fatal("on localnet a nil RPC must leave the top-up seam unset")
	}
}
