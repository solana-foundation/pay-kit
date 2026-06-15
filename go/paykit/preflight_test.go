package paykit_test

import (
	"context"
	"errors"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
)

// fakeRPC is the paykit.PreflightRPCInterface test double. Mirrors
// PHP's FakeRpcGateway and Ruby's FakeRpc: scripted balances, account
// existence, and call passthroughs.
type fakeRPC struct {
	balance        uint64
	balanceErr     error
	accountInfo    *rpc.GetAccountInfoResult
	accountInfoErr error
	calls          []string
	callErr        error
}

func (f *fakeRPC) GetBalance(_ context.Context, _ solana.PublicKey, _ rpc.CommitmentType) (*rpc.GetBalanceResult, error) {
	if f.balanceErr != nil {
		return nil, f.balanceErr
	}
	return &rpc.GetBalanceResult{Value: f.balance}, nil
}

func (f *fakeRPC) GetAccountInfoWithOpts(_ context.Context, _ solana.PublicKey, _ *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	return f.accountInfo, f.accountInfoErr
}

func (f *fakeRPC) RPCCallForInto(_ context.Context, _ any, method string, _ []any) error {
	f.calls = append(f.calls, method)
	return f.callErr
}

func swapFactory(t *testing.T, fake paykit.PreflightRPCInterface) {
	t.Helper()
	restore := paykit.SetPreflightRPCFactoryForTests(func(_ string) paykit.PreflightRPCInterface { return fake })
	t.Cleanup(restore)
}

func demoCfg() paykit.Config {
	return paykit.Config{
		Network:     paykit.SolanaLocalnet,
		Stablecoins: []paykit.Stablecoin{paykit.USDC},
		Operator: paykit.Operator{
			Signer:    signer.Demo(),
			Recipient: signer.Demo().Pubkey(),
			FeePayer:  true,
		},
		MPP:    paykit.MPPConfig{ChallengeBindingSecret: []byte("x")},
		RPCURL: "http://stub",
	}
}

func TestPreflightAutoFundsDemoFeePayerOnLocalnet(t *testing.T) {
	fake := &fakeRPC{
		balance:     0,
		accountInfo: &rpc.GetAccountInfoResult{Value: &rpc.Account{}},
	}
	swapFactory(t, fake)
	if err := paykit.RunPreflightForTests(demoCfg()); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if len(fake.calls) == 0 || fake.calls[0] != "surfnet_setAccount" {
		t.Errorf("expected surfnet_setAccount; got %v", fake.calls)
	}
}

func TestPreflightAutoProvisionsAtaOnLocalnet(t *testing.T) {
	fake := &fakeRPC{
		balance:     2_000_000,
		accountInfo: &rpc.GetAccountInfoResult{Value: nil}, // ATA missing
	}
	swapFactory(t, fake)
	if err := paykit.RunPreflightForTests(demoCfg()); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if len(fake.calls) == 0 || fake.calls[0] != "surfnet_setTokenAccount" {
		t.Errorf("expected surfnet_setTokenAccount; got %v", fake.calls)
	}
}

func TestPreflightRaisesOnDevnetWithoutAutofix(t *testing.T) {
	fake := &fakeRPC{balance: 0}
	swapFactory(t, fake)
	cfg := demoCfg()
	cfg.Network = paykit.SolanaDevnet
	cfg.Operator.Signer = signer.Generate()
	cfg.Operator.Recipient = cfg.Operator.Signer.Pubkey()
	err := paykit.RunPreflightForTests(cfg)
	if err == nil {
		t.Fatal("expected preflight error")
	}
	var pe *paykit.PreflightError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *paykit.PreflightError, got %T", err)
	}
	if pe.Stage != "fee-payer" {
		t.Errorf("stage: got %s", pe.Stage)
	}
}

func TestPreflightRPCFailureDefersToRuntime(t *testing.T) {
	fake := &fakeRPC{
		balanceErr:     errors.New("connection refused"),
		accountInfoErr: errors.New("connection refused"),
	}
	swapFactory(t, fake)
	cfg := demoCfg()
	cfg.Network = paykit.SolanaDevnet
	// RPC failure should not block boot; the runtime resurfaces the
	// connection problem on the first request.
	if err := paykit.RunPreflightForTests(cfg); err != nil {
		t.Errorf("expected nil on RPC failure, got %v", err)
	}
}

func TestPreflightSkipsFeePayerWhenDisabled(t *testing.T) {
	fake := &fakeRPC{accountInfo: &rpc.GetAccountInfoResult{Value: &rpc.Account{}}}
	swapFactory(t, fake)
	cfg := demoCfg()
	cfg.Network = paykit.SolanaDevnet
	cfg.Operator.FeePayer = false
	if err := paykit.RunPreflightForTests(cfg); err != nil {
		t.Errorf("expected nil; got %v", err)
	}
	for _, c := range fake.calls {
		if c == "surfnet_setAccount" {
			t.Error("surfnet_setAccount should not fire when FeePayer=false")
		}
	}
}

func TestPreflightDisabledByEnv(t *testing.T) {
	t.Setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
	cfg := paykit.Config{
		Network: paykit.SolanaDevnet,
		MPP:     paykit.MPPConfig{ChallengeBindingSecret: []byte("x")},
	}
	if paykit.PreflightEnabledForTests(cfg) {
		t.Error("env kill switch should disable preflight")
	}
}

func TestPreflightDisabledByConfig(t *testing.T) {
	off := false
	cfg := paykit.Config{Network: paykit.SolanaDevnet, Preflight: &off}
	if paykit.PreflightEnabledForTests(cfg) {
		t.Error("Preflight=&false should disable")
	}
}
