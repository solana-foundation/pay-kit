package solanatx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
)

type failingSigner struct {
	key solana.PublicKey
	err error
}

func (s failingSigner) PublicKey() solana.PublicKey {
	return s.key
}

func (s failingSigner) Sign([]byte) (solana.Signature, error) {
	return solana.Signature{}, s.err
}

func TestSplitAmounts(t *testing.T) {
	primary, err := SplitAmounts(1000, []paycore.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "100"}})
	if err != nil {
		t.Fatalf("split failed: %v", err)
	}
	if primary != 900 {
		t.Fatalf("unexpected primary amount %d", primary)
	}
}

func TestResolveRecentBlockhash(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	hash, err := ResolveRecentBlockhash(context.Background(), rpcClient, "")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if hash != rpcClient.Blockhash {
		t.Fatalf("unexpected blockhash %s", hash)
	}
}

func TestResolveTokenProgram(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	program, err := ResolveTokenProgram(context.Background(), rpcClient, mint, "")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if !program.Equals(solana.TokenProgramID) {
		t.Fatalf("unexpected token program %s", program)
	}
}

func TestSignEncodeDecodeTransaction(t *testing.T) {
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	blockhash := testutil.NewFakeRPC().Blockhash
	transfer, err := BuildSOLTransfer(signer.PublicKey(), recipient, 1000)
	if err != nil {
		t.Fatalf("transfer failed: %v", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{transfer}, blockhash, solana.TransactionPayer(signer.PublicKey()))
	if err != nil {
		t.Fatalf("tx failed: %v", err)
	}
	if err := SignTransaction(tx, signer); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	encoded, err := EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := DecodeTransactionBase64(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded.Signatures) != 1 || decoded.Signatures[0].IsZero() {
		t.Fatal("expected decoded signature")
	}
}

func TestWaitSimulateSendFetchTransaction(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	transfer, _ := BuildSOLTransfer(signer.PublicKey(), recipient, 1000)
	tx, _ := solana.NewTransaction([]solana.Instruction{transfer}, rpcClient.Blockhash, solana.TransactionPayer(signer.PublicKey()))
	_ = SignTransaction(tx, signer)
	if err := SimulateTransaction(context.Background(), rpcClient, tx); err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	signature, err := SendTransaction(context.Background(), rpcClient, tx)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if err := WaitForConfirmation(context.Background(), rpcClient, signature); err != nil {
		t.Fatalf("wait failed: %v", err)
	}
	fetched, _, err := FetchTransaction(context.Background(), rpcClient, signature)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	if len(fetched.Signatures) != 1 {
		t.Fatalf("unexpected fetched transaction")
	}
}

func TestAssociatedTokenHelpers(t *testing.T) {
	wallet := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	ata, err := FindAssociatedTokenAddress(wallet, mint)
	if err != nil || ata.IsZero() {
		t.Fatalf("ata failed: %v", err)
	}
	ata2022, err := FindAssociatedTokenAddressWithProgram(wallet, mint, solana.MustPublicKeyFromBase58(paycore.Token2022Program))
	if err != nil || ata2022.IsZero() {
		t.Fatalf("ata2022 failed: %v", err)
	}
	ix, err := BuildCreateAssociatedTokenAccount(wallet, wallet, mint, solana.TokenProgramID)
	if err != nil || ix == nil {
		t.Fatalf("create ata failed: %v", err)
	}
	ix, err = BuildTransferChecked(1, 6, ata, mint, ata, wallet, solana.TokenProgramID)
	if err != nil || ix == nil {
		t.Fatalf("transfer checked failed: %v", err)
	}
	_, err = BuildTransferChecked(1, 6, ata, mint, ata, wallet, solana.SystemProgramID)
	if err == nil {
		t.Fatal("expected unsupported token program error")
	}
	_, err = BuildComputeUnitLimit(200_000)
	if err != nil {
		t.Fatalf("compute unit limit failed: %v", err)
	}
	_, err = BuildComputeUnitPrice(1)
	if err != nil {
		t.Fatalf("compute unit price failed: %v", err)
	}
}

func TestResolveTokenProgramUsesHint(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	mint := testutil.NewPrivateKey().PublicKey()
	program, err := ResolveTokenProgram(context.Background(), rpcClient, mint, paycore.Token2022Program)
	if err != nil {
		t.Fatalf("resolve with hint failed: %v", err)
	}
	if program.String() != paycore.Token2022Program {
		t.Fatalf("unexpected program %s", program)
	}
}

func TestSplitAmountsTooManySplits(t *testing.T) {
	splits := make([]paycore.Split, 9)
	for i := range splits {
		splits[i] = paycore.Split{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "1"}
	}
	if _, err := SplitAmounts(100, splits); err == nil {
		t.Fatal("expected error for >8 splits")
	}
}

func TestSplitAmountsSplitTotalEqualsTotal(t *testing.T) {
	splits := []paycore.Split{
		{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "1000"},
	}
	if _, err := SplitAmounts(1000, splits); err == nil {
		t.Fatal("expected error when splits consume entire amount")
	}
}

func TestSplitAmountsNoSplits(t *testing.T) {
	primary, err := SplitAmounts(1000, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if primary != 1000 {
		t.Fatalf("expected 1000, got %d", primary)
	}
}

func TestSplitAmountsAccumulatorOverflow(t *testing.T) {
	recipient := testutil.NewPrivateKey().PublicKey().String()
	const maxU64 = "18446744073709551615" // 2^64 - 1
	cases := []struct {
		name    string
		total   uint64
		splits  []paycore.Split
		wantErr bool
	}{
		{
			name:  "splits sum exactly fits in uint64",
			total: 1<<63 + 1, // > sum, so primary is non-zero
			splits: []paycore.Split{
				{Recipient: recipient, Amount: "9223372036854775807"}, // 2^63 - 1
				{Recipient: recipient, Amount: "1"},
			},
			wantErr: false,
		},
		{
			name:  "splits sum overflows uint64 must reject",
			total: 1000,
			splits: []paycore.Split{
				{Recipient: recipient, Amount: maxU64},
				{Recipient: recipient, Amount: "1"},
			},
			wantErr: true,
		},
		{
			name:  "two near-max splits wrap to small value must reject",
			total: 1000,
			splits: []paycore.Split{
				{Recipient: recipient, Amount: "9223372036854775808"}, // 2^63
				{Recipient: recipient, Amount: "9223372036854775808"}, // 2^63, sum wraps to 0
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SplitAmounts(tc.total, tc.splits)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSplitAmountsInvalidAmount(t *testing.T) {
	splits := []paycore.Split{
		{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "not-a-number"},
	}
	if _, err := SplitAmounts(1000, splits); err == nil {
		t.Fatal("expected error for invalid split amount")
	}
}

func TestFindAssociatedTokenAddressWithProgramToken2022(t *testing.T) {
	wallet := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	token2022 := solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	ata, err := FindAssociatedTokenAddressWithProgram(wallet, mint, token2022)
	if err != nil {
		t.Fatalf("ata token2022 failed: %v", err)
	}
	if ata.IsZero() {
		t.Fatal("expected non-zero ATA")
	}
	// Verify it differs from standard token program ATA
	stdAta, err := FindAssociatedTokenAddress(wallet, mint)
	if err != nil {
		t.Fatalf("ata standard failed: %v", err)
	}
	if ata.Equals(stdAta) {
		t.Fatal("token2022 ATA should differ from standard token ATA")
	}
}

func TestBuildTransferCheckedToken2022(t *testing.T) {
	wallet := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	token2022 := solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	source, _ := FindAssociatedTokenAddressWithProgram(wallet, mint, token2022)
	dest, _ := FindAssociatedTokenAddressWithProgram(testutil.NewPrivateKey().PublicKey(), mint, token2022)
	ix, err := BuildTransferChecked(1000, 6, source, mint, dest, wallet, token2022)
	if err != nil {
		t.Fatalf("build transfer checked failed: %v", err)
	}
	if ix == nil {
		t.Fatal("expected instruction")
	}
}

func TestDecodeTransactionBase64InvalidBase64(t *testing.T) {
	if _, err := DecodeTransactionBase64("!!!not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodeTransactionBase64InvalidTransaction(t *testing.T) {
	// Valid base64 but not a valid transaction
	if _, err := DecodeTransactionBase64("aGVsbG8="); err == nil {
		t.Fatal("expected error for invalid transaction data")
	}
}

func TestResolveRecentBlockhashWithProvided(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	provided := "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"
	hash, err := ResolveRecentBlockhash(context.Background(), rpcClient, provided)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	expected := solana.MustHashFromBase58(provided)
	if hash != expected {
		t.Fatalf("expected provided blockhash, got %s", hash)
	}
}

func TestResolveRecentBlockhashEmptyFallsBackToRPC(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	hash, err := ResolveRecentBlockhash(context.Background(), rpcClient, "")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if hash != rpcClient.Blockhash {
		t.Fatalf("expected RPC blockhash %s, got %s", rpcClient.Blockhash, hash)
	}
}

func TestResolveTokenProgramToken2022Owner(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	program, err := ResolveTokenProgram(context.Background(), rpcClient, mint, "")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if program.String() != paycore.Token2022Program {
		t.Fatalf("expected token2022 program, got %s", program)
	}
}

func TestResolveTokenProgramMintNotFound(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	mint := testutil.NewPrivateKey().PublicKey()
	// Not in MintOwners map
	if _, err := ResolveTokenProgram(context.Background(), rpcClient, mint, ""); err == nil {
		t.Fatal("expected error for mint not found")
	}
}

func TestWaitForConfirmationReturnsFailure(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signature := solana.MustSignatureFromBase58("5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv")
	rpcClient.Statuses[signature.String()] = &rpc.SignatureStatusesResult{
		Err: "boom",
	}
	if err := WaitForConfirmation(context.Background(), rpcClient, signature); err == nil {
		t.Fatal("expected confirmation failure")
	}
}

func TestSignTransactionRejectsSignerFailure(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	transfer, err := BuildSOLTransfer(payer.PublicKey(), recipient, 1000)
	if err != nil {
		t.Fatalf("transfer failed: %v", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{transfer}, testutil.NewFakeRPC().Blockhash, solana.TransactionPayer(payer.PublicKey()))
	if err != nil {
		t.Fatalf("tx failed: %v", err)
	}
	if err := SignTransaction(tx, failingSigner{key: payer.PublicKey(), err: errors.New("sign failed")}); err == nil {
		t.Fatal("expected signer failure")
	}
}

func TestSignTransactionRejectsUnexpectedSigner(t *testing.T) {
	payer := testutil.NewPrivateKey()
	other := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	transfer, err := BuildSOLTransfer(payer.PublicKey(), recipient, 1000)
	if err != nil {
		t.Fatalf("transfer failed: %v", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{transfer}, testutil.NewFakeRPC().Blockhash, solana.TransactionPayer(payer.PublicKey()))
	if err != nil {
		t.Fatalf("tx failed: %v", err)
	}
	if err := SignTransaction(tx, other); err == nil {
		t.Fatal("expected non-required signer to fail")
	}
}

func TestBuildMemoInstructionParity(t *testing.T) {
	ix, err := BuildMemoInstruction("order-123")
	if err != nil {
		t.Fatalf("memo failed: %v", err)
	}
	if ix == nil {
		t.Fatal("expected memo instruction")
	}
	data, err := ix.Data()
	if err != nil {
		t.Fatalf("memo data failed: %v", err)
	}
	if string(data) != "order-123" {
		t.Fatalf("unexpected memo data %q", string(data))
	}
}

func TestBuildMemoInstructionRejectsLongMemo(t *testing.T) {
	if _, err := BuildMemoInstruction(strings.Repeat("x", 567)); err == nil {
		t.Fatal("expected long memo to fail")
	}
}

func TestResolveRecentBlockhashRejectsInvalidProvided(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	if _, err := ResolveRecentBlockhash(context.Background(), rpcClient, "not-a-blockhash"); err == nil {
		t.Fatal("expected invalid provided blockhash to fail")
	}
}

func TestSplitAmountsRejectsPartiallyNumericAmount(t *testing.T) {
	splits := []paycore.Split{
		{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "100abc"},
	}
	if _, err := SplitAmounts(1000, splits); err == nil {
		t.Fatal("expected error for partially numeric split amount")
	}
}

func TestWaitForConfirmationReturnsContextError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signature := solana.MustSignatureFromBase58("5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv")
	rpcClient.Statuses[signature.String()] = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WaitForConfirmation(ctx, rpcClient, signature); err == nil {
		t.Fatal("expected context cancellation")
	}
}

func TestSimulateTransactionReturnsSimulationError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	rpcClient.SimulateErr = errors.New("simulate failed")
	if err := SimulateTransaction(context.Background(), rpcClient, &solana.Transaction{}); err == nil {
		t.Fatal("expected simulate error")
	}
}

func TestFetchTransactionReturnsRPCError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	rpcClient.GetTxErr = errors.New("get transaction failed")
	signature := solana.MustSignatureFromBase58("5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv")
	if _, _, err := FetchTransaction(context.Background(), rpcClient, signature); err == nil {
		t.Fatal("expected get transaction error")
	}
}

// --- merged from utils_branch_test.go ---

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

func (s signerErr) PublicKey() solana.PublicKey { return s.pub }
func (s signerErr) Sign(_ []byte) (solana.Signature, error) {
	return solana.Signature{}, errors.New("sign failed")
}

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
var _ = paycore.MemoProgram
