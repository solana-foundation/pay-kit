package solanautil

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/mpp-sdk/go/internal/testutil"
	"github.com/solana-foundation/mpp-sdk/go/protocol"
)

// rpcStub allows fine-grained control over RPC behavior for branch coverage.
type rpcStub struct {
	*testutil.FakeRPC
	blockhashErr error
	accountErr   error
	accountValue *rpc.GetAccountInfoResult
}

func (s *rpcStub) GetLatestBlockhash(ctx context.Context, c rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	if s.blockhashErr != nil {
		return nil, s.blockhashErr
	}
	return s.FakeRPC.GetLatestBlockhash(ctx, c)
}

func (s *rpcStub) GetAccountInfoWithOpts(ctx context.Context, account solana.PublicKey, opts *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	if s.accountErr != nil {
		return nil, s.accountErr
	}
	if s.accountValue != nil {
		return s.accountValue, nil
	}
	return s.FakeRPC.GetAccountInfoWithOpts(ctx, account, opts)
}

func TestBuildMemoInstructionRoundTrip(t *testing.T) {
	ix, err := BuildMemoInstruction("hello memo")
	if err != nil {
		t.Fatalf("memo failed: %v", err)
	}
	if ix == nil {
		t.Fatal("expected instruction")
	}
	data, dErr := ix.Data()
	if dErr != nil {
		t.Fatalf("data failed: %v", dErr)
	}
	if string(data) != "hello memo" {
		t.Fatalf("unexpected memo data: %q", string(data))
	}
}

func TestBuildMemoInstructionTooLong(t *testing.T) {
	_, err := BuildMemoInstruction(strings.Repeat("x", 567))
	if err == nil {
		t.Fatal("expected too-long error")
	}
}

func TestResolveRecentBlockhashInvalidProvided(t *testing.T) {
	if _, err := ResolveRecentBlockhash(context.Background(), testutil.NewFakeRPC(), "!!!not-a-hash!!!"); err == nil {
		t.Fatal("expected error for invalid provided hash")
	}
}

func TestResolveRecentBlockhashRPCError(t *testing.T) {
	stub := &rpcStub{FakeRPC: testutil.NewFakeRPC(), blockhashErr: errors.New("rpc down")}
	if _, err := ResolveRecentBlockhash(context.Background(), stub, ""); err == nil {
		t.Fatal("expected rpc error")
	}
}

func TestResolveTokenProgramRPCError(t *testing.T) {
	stub := &rpcStub{FakeRPC: testutil.NewFakeRPC(), accountErr: errors.New("rpc down")}
	mint := testutil.NewPrivateKey().PublicKey()
	if _, err := ResolveTokenProgram(context.Background(), stub, mint, ""); err == nil {
		t.Fatal("expected rpc error")
	}
}

func TestResolveTokenProgramNilAccountValue(t *testing.T) {
	stub := &rpcStub{FakeRPC: testutil.NewFakeRPC(), accountValue: &rpc.GetAccountInfoResult{}}
	mint := testutil.NewPrivateKey().PublicKey()
	if _, err := ResolveTokenProgram(context.Background(), stub, mint, ""); err == nil {
		t.Fatal("expected mint not found error")
	}
}

func TestResolveTokenProgramUnsupportedOwner(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = testutil.NewPrivateKey().PublicKey()
	if _, err := ResolveTokenProgram(context.Background(), rpcClient, mint, ""); err == nil {
		t.Fatal("expected unsupported owner error")
	}
}

func TestResolveTokenProgramInvalidHint(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	mint := testutil.NewPrivateKey().PublicKey()
	if _, err := ResolveTokenProgram(context.Background(), rpcClient, mint, "!!!"); err == nil {
		t.Fatal("expected invalid hint error")
	}
}

// signerErr returns errors from Sign for SignTransaction error-path coverage.
type signerErr struct {
	pub solana.PublicKey
}

func (s signerErr) PublicKey() solana.PublicKey                { return s.pub }
func (s signerErr) Sign(_ []byte) (solana.Signature, error)    { return solana.Signature{}, errors.New("sign failed") }

func TestSignTransactionSignerError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	ix, _ := BuildSOLTransfer(payer.PublicKey(), recipient, 1)
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, rpcClient.Blockhash, solana.TransactionPayer(payer.PublicKey()))
	if err := SignTransaction(tx, signerErr{pub: payer.PublicKey()}); err == nil {
		t.Fatal("expected signer error")
	}
}

func TestSignTransactionWrongSigner(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	payer := testutil.NewPrivateKey()
	stranger := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	ix, _ := BuildSOLTransfer(payer.PublicKey(), recipient, 1)
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, rpcClient.Blockhash, solana.TransactionPayer(payer.PublicKey()))
	if err := SignTransaction(tx, stranger); err == nil {
		t.Fatal("expected signer-not-required error")
	}
}

func TestSimulateTransactionRPCError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	rpcClient.SimulateErr = errors.New("sim rpc down")
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	ix, _ := BuildSOLTransfer(signer.PublicKey(), recipient, 1)
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, rpcClient.Blockhash, solana.TransactionPayer(signer.PublicKey()))
	_ = SignTransaction(tx, signer)
	if err := SimulateTransaction(context.Background(), rpcClient, tx); err == nil {
		t.Fatal("expected simulate rpc error")
	}
}

// simErr emits a simulation-level error in Value.Err.
type simErrRPC struct{ *testutil.FakeRPC }

func (r *simErrRPC) SimulateTransactionWithOpts(_ context.Context, _ *solana.Transaction, _ *rpc.SimulateTransactionOpts) (*rpc.SimulateTransactionResponse, error) {
	return &rpc.SimulateTransactionResponse{Value: &rpc.SimulateTransactionResult{Err: "boom"}}, nil
}

func TestSimulateTransactionValueError(t *testing.T) {
	rpcClient := &simErrRPC{FakeRPC: testutil.NewFakeRPC()}
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	ix, _ := BuildSOLTransfer(signer.PublicKey(), recipient, 1)
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, rpcClient.Blockhash, solana.TransactionPayer(signer.PublicKey()))
	_ = SignTransaction(tx, signer)
	if err := SimulateTransaction(context.Background(), rpcClient, tx); err == nil {
		t.Fatal("expected simulate value error")
	}
}

func TestFetchTransactionRPCError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	rpcClient.GetTxErr = errors.New("get tx failed")
	sig := solana.MustSignatureFromBase58("5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv")
	if _, _, err := FetchTransaction(context.Background(), rpcClient, sig); err == nil {
		t.Fatal("expected fetch rpc error")
	}
}

func TestWaitForConfirmationContextCanceled(t *testing.T) {
	// Use empty signature so the FakeRPC default returns confirmed; ensure cancel
	// triggers ctx.Done branch by canceling before invocation but using an unknown sig
	// with status that requires re-poll. Use a stub that always returns empty results.
	stub := &waitStub{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sig := solana.MustSignatureFromBase58("5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv")
	if err := WaitForConfirmation(ctx, stub, sig); err == nil {
		t.Fatal("expected context canceled error")
	}
}

type waitStub struct{}

func (waitStub) GetAccountInfoWithOpts(_ context.Context, _ solana.PublicKey, _ *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	return nil, errors.New("not implemented")
}
func (waitStub) GetLatestBlockhash(_ context.Context, _ rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return nil, errors.New("not implemented")
}
func (waitStub) GetSignatureStatuses(_ context.Context, _ bool, _ ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	// Return an empty Value so WaitForConfirmation falls through to the ticker/ctx select.
	return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{nil}}, nil
}
func (waitStub) GetTransaction(_ context.Context, _ solana.Signature, _ *rpc.GetTransactionOpts) (*rpc.GetTransactionResult, error) {
	return nil, errors.New("not implemented")
}
func (waitStub) SendTransactionWithOpts(_ context.Context, _ *solana.Transaction, _ rpc.TransactionOpts) (solana.Signature, error) {
	return solana.Signature{}, errors.New("not implemented")
}
func (waitStub) SimulateTransactionWithOpts(_ context.Context, _ *solana.Transaction, _ *rpc.SimulateTransactionOpts) (*rpc.SimulateTransactionResponse, error) {
	return nil, errors.New("not implemented")
}

func TestWaitForConfirmationTickerThenSucceeds(t *testing.T) {
	// Cover both the unconfirmed-loop path and the ticker tick path.
	stub := &tickStub{ready: make(chan struct{})}
	sig := solana.MustSignatureFromBase58("5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv")
	go func() {
		time.Sleep(250 * time.Millisecond)
		close(stub.ready)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := WaitForConfirmation(ctx, stub, sig); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type tickStub struct {
	ready chan struct{}
}

func (tickStub) GetAccountInfoWithOpts(_ context.Context, _ solana.PublicKey, _ *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	return nil, errors.New("not implemented")
}
func (tickStub) GetLatestBlockhash(_ context.Context, _ rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return nil, errors.New("not implemented")
}
func (s *tickStub) GetSignatureStatuses(_ context.Context, _ bool, _ ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	select {
	case <-s.ready:
		return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{{
			ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		}}}, nil
	default:
		// Not yet confirmed: return empty so WaitForConfirmation loops to the ticker.
		return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{nil}}, nil
	}
}
func (tickStub) GetTransaction(_ context.Context, _ solana.Signature, _ *rpc.GetTransactionOpts) (*rpc.GetTransactionResult, error) {
	return nil, errors.New("not implemented")
}
func (tickStub) SendTransactionWithOpts(_ context.Context, _ *solana.Transaction, _ rpc.TransactionOpts) (solana.Signature, error) {
	return solana.Signature{}, errors.New("not implemented")
}
func (tickStub) SimulateTransactionWithOpts(_ context.Context, _ *solana.Transaction, _ *rpc.SimulateTransactionOpts) (*rpc.SimulateTransactionResponse, error) {
	return nil, errors.New("not implemented")
}

func TestBuildCreateAssociatedTokenAccountFindError(t *testing.T) {
	// FindAssociatedTokenAddressWithProgram returns an error for an invalid token
	// program key. We use the zero key (which is not a valid program) -- it still
	// derives a PDA via FindProgramAddress, so this hits the success branch.
	// To force an error, use FindAssociatedTokenAddress (standard token) which
	// also derives PDA successfully. There is no reachable error here without
	// reaching into the runtime; document and skip.
	t.Skip("FindAssociatedTokenAddressWithProgram has no reachable input that returns an error for valid public keys")
}

// Reference rpc to silence unused import in older Go versions.
var _ = rpc.CommitmentConfirmed
var _ = protocol.MemoProgram
