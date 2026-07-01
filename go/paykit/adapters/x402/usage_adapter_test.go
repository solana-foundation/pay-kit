package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// uptoTestRPC wraps testutil.FakeRPC with channel account data for the
// upto end-to-end test.
type uptoTestRPC struct {
	*testutil.FakeRPC
	mu       sync.Mutex
	channels map[string][]byte
}

func newUptoTestRPC() *uptoTestRPC {
	return &uptoTestRPC{
		FakeRPC:  testutil.NewFakeRPC(),
		channels: map[string][]byte{},
	}
}

func (r *uptoTestRPC) addChannel(account solana.PublicKey, channel *pcgen.Channel) {
	buf := new(bytes.Buffer)
	enc := bin.NewBorshEncoder(buf)
	if err := channel.MarshalWithEncoder(enc); err != nil {
		panic(err)
	}
	r.mu.Lock()
	r.channels[account.String()] = buf.Bytes()
	r.mu.Unlock()
}

func (r *uptoTestRPC) GetAccountInfoWithOpts(ctx context.Context, account solana.PublicKey, opts *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	r.mu.Lock()
	data, ok := r.channels[account.String()]
	r.mu.Unlock()
	if ok {
		return &rpc.GetAccountInfoResult{
			Value: &rpc.Account{
				Owner: paymentchannels.ProgramPubkey(),
				Data:  rpc.DataBytesOrJSONFromBytes(data),
			},
		}, nil
	}
	return r.FakeRPC.GetAccountInfoWithOpts(ctx, account, opts)
}

type testSigner struct {
	priv solana.PrivateKey
}

func (s testSigner) Pubkey() paykit.Address { return paykit.Address(s.priv.PublicKey().String()) }

func (s testSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	sig, err := s.priv.Sign(msg)
	if err != nil {
		return nil, err
	}
	return sig[:], nil
}

func (s testSigner) IsDemo() bool { return false }

type wrongVerifiedUsageOpen struct{}

func (wrongVerifiedUsageOpen) Release() {}

type testPayerSigner struct{ priv solana.PrivateKey }

func (s testPayerSigner) PublicKey() solana.PublicKey { return s.priv.PublicKey() }

func (s testPayerSigner) Sign(msg []byte) (solana.Signature, error) {
	return s.priv.Sign(msg)
}

func TestNewUsageAdapter(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:     paykit.SolanaLocalnet,
		RPCURL:      "http://localhost:8899",
		Accept:      []paykit.Protocol{paykit.X402},
		Operator:    paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
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

func TestUsageAdapterThreadsChannelProgramOverride(t *testing.T) {
	signer := testutil.NewPrivateKey()
	program := solana.NewWallet().PublicKey()
	cfg := paykit.Config{
		Network:     paykit.SolanaLocalnet,
		RPCURL:      "http://localhost:8899",
		Accept:      []paykit.Protocol{paykit.X402},
		Operator:    paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
		Stablecoins: []paykit.Stablecoin{paykit.USDC},
		X402:        paykit.X402Config{ChannelProgram: program.String()},
	}
	adapter, err := NewUsageAdapter(cfg)
	if err != nil {
		t.Fatalf("NewUsageAdapter: %v", err)
	}
	entry := adapter.UsageAcceptsEntry(&paykit.Gate{Amount: paykit.MustParseUSD("1.00"), Kind: paykit.GateUsage, Name: "test"})
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal accepts entry: %v", err)
	}
	if !strings.Contains(string(raw), `"channelProgram":"`+program.String()+`"`) {
		t.Fatalf("channelProgram override missing from accepts entry: %s", raw)
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
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
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
		Operator:                paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
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
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
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

func TestUptoChannelBorshRoundtrip(t *testing.T) {
	ch := &pcgen.Channel{
		Discriminator:    uint8(pcgen.AccountDiscriminator_Channel),
		Version:          0,
		Bump:             0,
		Status:           uint8(pcgen.ChannelStatus_Open),
		Salt:             7,
		Deposit:          1_000_000,
		GracePeriod:      900,
		DistributionHash: proto.EmptyDistributionHash,
	}
	buf := new(bytes.Buffer)
	enc := bin.NewBorshEncoder(buf)
	if err := ch.MarshalWithEncoder(enc); err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec := bin.NewBorshDecoder(buf.Bytes())
	var decoded pcgen.Channel
	if err := decoded.UnmarshalWithDecoder(dec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded.DistributionHash[:], proto.EmptyDistributionHash[:]) {
		t.Fatalf("DistributionHash mismatch after roundtrip: got %x", decoded.DistributionHash[:])
	}
	t.Logf("encoded %d bytes, decoded DistributionHash = %x", buf.Len(), decoded.DistributionHash[:])
}

func TestUsageAdapterVerifyOpenEmptyHeader(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:  paykit.SolanaLocalnet,
		RPCURL:   "http://localhost:8899",
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
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
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
	}
	adapter, _ := NewUsageAdapter(cfg)
	_, err := adapter.SettleActual(context.Background(), wrongVerifiedUsageOpen{}, 100)
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
	channel, _, err := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	if err != nil {
		t.Fatalf("FindChannelPDA: %v", err)
	}
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, err := paymentchannels.BuildOpenInstruction(params)
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	blockhash := solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h")
	tx, err := solana.NewTransaction([]solana.Instruction{openIx}, blockhash, solana.TransactionPayer(operatorKey.PublicKey()))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	if err := solanatx.SignTransaction(tx, testPayerSigner{payerKey}); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBase64, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("EncodeTransactionBase64: %v", err)
	}

	fakeRPC := newUptoTestRPC()
	fakeRPC.addChannel(channel, &pcgen.Channel{
		Discriminator:    uint8(pcgen.AccountDiscriminator_Channel),
		Version:          0,
		Bump:             0,
		Status:           uint8(pcgen.ChannelStatus_Open),
		Salt:             salt,
		Deposit:          1_000_000,
		GracePeriod:      900,
		DistributionHash: proto.EmptyDistributionHash,
		Payer:            payerKey.PublicKey(),
		Payee:            payee,
		AuthorizedSigner: operatorKey.PublicKey(),
		RentPayer:        operatorKey.PublicKey(),
		Mint:             mint,
	})

	cfg := paykit.Config{
		Network:                 paykit.SolanaLocalnet,
		RPCURL:                  "http://localhost:8899",
		Accept:                  []paykit.Protocol{paykit.X402},
		Operator:                paykit.Operator{Recipient: paykit.Address(payee.String()), Signer: testSigner{operatorKey}},
		Stablecoins:             []paykit.Stablecoin{paykit.USDC},
		RecentBlockhashProvider: func() (string, error) { return blockhash.String(), nil },
	}
	adapter, err := NewUsageAdapter(cfg)
	if err != nil {
		t.Fatalf("NewUsageAdapter: %v", err)
	}
	ua := adapter.(*usageAdapter)
	ua.engine.SetRPCForTests(fakeRPC)

	envelope := proto.UptoSignatureEnvelope{
		X402Version: proto.X402Version,
		Scheme:      proto.UptoScheme,
		Network:     "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Payload: proto.UptoPayload{
			From:             payerKey.PublicKey().String(),
			MaxAmount:        "1000000",
			ExpiresAt:        time.Now().Add(time.Hour).Unix(),
			ValidAfter:       0,
			Nonce:            "n-1",
			ChannelID:        channel.String(),
			Deposit:          "1000000",
			AuthorizedSigner: operatorKey.PublicKey().String(),
			OpenTransaction:  txBase64,
		},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
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
