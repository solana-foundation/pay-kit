package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

func TestNewUsageAdapter(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:     paykit.SolanaLocalnet,
		RPCURL:      "http://localhost:8899",
		Accept:      []paykit.Protocol{paykit.X402},
		Operator:    paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: signerSigner{signer}},
		Stablecoins: []paykit.Stablecoin{paykit.USDC},
	}
	adapter, err := NewUsageAdapter(cfg)
	if err != nil {
		t.Fatalf("NewUsageAdapter: %v", err)
	}
	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
}

func TestNewUsageAdapterRejectsNilSigner(t *testing.T) {
	cfg := paykit.Config{Network: paykit.SolanaLocalnet, RPCURL: "http://localhost:8899"}
	_, err := NewUsageAdapter(cfg)
	if err == nil {
		t.Fatal("expected error for nil signer")
	}
}

func TestUsageAdapterDetectUsage(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:  paykit.SolanaLocalnet,
		RPCURL:   "http://localhost:8899",
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: signerSigner{signer}},
	}
	adapter, _ := NewUsageAdapter(cfg)
	req := &paykit.AdapterRequest{PaymentSig: "abc"}
	if !adapter.DetectUsage(req) {
		t.Fatal("expected detect with PaymentSig")
	}
	req = &paykit.AdapterRequest{PaymentSigLegacy: "abc"}
	if !adapter.DetectUsage(req) {
		t.Fatal("expected detect with PaymentSigLegacy")
	}
	req = &paykit.AdapterRequest{}
	if adapter.DetectUsage(req) {
		t.Fatal("expected no detect with empty headers")
	}
}

func TestUsageAdapterChallengeHeaders(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:                 paykit.SolanaLocalnet,
		RPCURL:                  "http://localhost:8899",
		Operator:                paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: signerSigner{signer}},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	}
	adapter, _ := NewUsageAdapter(cfg)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("1.00"), Kind: paykit.GateUsage, Name: "test"}
	headers := adapter.UsageChallengeHeaders(&gate)
	if len(headers) == 0 {
		t.Fatal("expected challenge headers")
	}
	if _, ok := headers["payment-required"]; !ok {
		t.Fatalf("expected payment-required header, got %v", headers)
	}
}

func TestUsageAdapterAcceptsEntry(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:  paykit.SolanaLocalnet,
		RPCURL:   "http://localhost:8899",
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: signerSigner{signer}},
	}
	adapter, _ := NewUsageAdapter(cfg)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("1.00"), Kind: paykit.GateUsage, Name: "test"}
	entry := adapter.UsageAcceptsEntry(&gate)
	if entry == nil {
		t.Fatal("expected accepts entry")
	}
	if entry.AcceptsProtocol() != paykit.X402 {
		t.Fatalf("protocol = %v, want x402", entry.AcceptsProtocol())
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if !strings.Contains(string(raw), "upto") {
		t.Fatalf("expected upto scheme in JSON, got %s", raw)
	}
}

func TestUsageAdapterVerifyOpenEmptyHeader(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:  paykit.SolanaLocalnet,
		RPCURL:   "http://localhost:8899",
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: signerSigner{signer}},
	}
	adapter, _ := NewUsageAdapter(cfg)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("1.00"), Kind: paykit.GateUsage, Name: "test"}
	req := &paykit.AdapterRequest{Gate: &gate}
	_, _, err := adapter.VerifyOpen(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty header")
	}
	if !strings.Contains(err.Error(), "payment_required") {
		t.Fatalf("expected payment_required, got %v", err)
	}
}

func TestUsageAdapterSettleActualWrongType(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:  paykit.SolanaLocalnet,
		RPCURL:   "http://localhost:8899",
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: signerSigner{signer}},
	}
	adapter, _ := NewUsageAdapter(cfg)
	_, err := adapter.SettleActual(context.Background(), "wrong-type", 100)
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestUsageAdapterVerifyOpenAndSettleEndToEnd(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(payerKey.PublicKey()))
	solanatx.SignTransaction(tx, payerSigner{payerKey})
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)

	fakeRPC := newUptoTestRPC()
	distHash := emptyDistributionHash()
	var distHashArr [32]byte
	copy(distHashArr[:], distHash)
	fakeRPC.addChannel(channel, &pcgen.Channel{
		Discriminator: uint8(pcgen.AccountDiscriminator_Channel), Status: uint8(pcgen.ChannelStatus_Open),
		Salt: salt, Deposit: 1_000_000, DistributionHash: distHashArr,
		Payer: payerKey.PublicKey(), Payee: payee, AuthorizedSigner: operatorKey.PublicKey(), Mint: mint,
	})

	cfg := paykit.Config{
		Network:                 paykit.SolanaLocalnet,
		RPCURL:                  "http://localhost:8899",
		Accept:                  []paykit.Protocol{paykit.X402},
		Operator:                paykit.Operator{Recipient: paykit.Address(payee.String()), Signer: signerSigner{operatorKey}},
		Stablecoins:             []paykit.Stablecoin{paykit.USDC},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	}
	adapter, err := NewUsageAdapter(cfg)
	if err != nil {
		t.Fatalf("NewUsageAdapter: %v", err)
	}
	// Inject the fake RPC by reaching into the engine.
	ua := adapter.(*usageAdapter)
	ua.engine.SetRPCForTests(fakeRPC)

	envelope := UptoSignatureEnvelope{
		X402Version: x402Version, Scheme: uptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Payload: UptoPayload{
			Profile: profilePaymentChannel, From: payerKey.PublicKey().String(),
			MaxAmount: "1000000", ExpiresAt: time.Now().Add(time.Hour).Unix(),
			ChannelID: channel.String(), Deposit: "1000000",
			AuthorizedSigner: operatorKey.PublicKey().String(), OpenTransaction: txBase64,
		},
	}
	raw, _ := json.Marshal(envelope)
	header := base64.StdEncoding.EncodeToString(raw)

	gate := paykit.Gate{Amount: paykit.MustParseUSD("1.00"), Kind: paykit.GateUsage, Name: "test"}
	req := &paykit.AdapterRequest{PaymentSig: header, Gate: &gate}

	verified, pmt, err := adapter.VerifyOpen(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyOpen: %v", err)
	}
	if pmt == nil || pmt.Protocol != paykit.X402 {
		t.Fatalf("payment = %+v", pmt)
	}

	settlement, err := adapter.SettleActual(context.Background(), verified, 500_000)
	if err != nil {
		t.Fatalf("SettleActual: %v", err)
	}
	if settlement.Transaction == "" {
		t.Fatal("expected non-empty transaction")
	}
	if settlement.Headers["x-payment-settlement-signature"] == "" {
		t.Fatal("expected settlement signature header")
	}
}
