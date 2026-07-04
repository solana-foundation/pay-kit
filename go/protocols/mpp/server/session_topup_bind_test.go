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
