package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/jsonrpc"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

func errorsAs(err error, target any) bool { return errors.As(err, target) }

// fixture builds a structurally valid x402 "exact" transaction and the
// matching requirements, so each test can mutate one axis and assert
// the verifier rejects exactly that mutation.
type fixture struct {
	keys         solana.PublicKeySlice
	computeLimit solana.CompiledInstruction
	computePrice solana.CompiledInstruction
	transfer     solana.CompiledInstruction
	req          proto.TransferRequirements
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	feePayer := solana.NewWallet().PublicKey()
	authority := solana.NewWallet().PublicKey()
	source := solana.NewWallet().PublicKey()
	payTo := solana.NewWallet().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	tokenProgram := solana.MustPublicKeyFromBase58(paycore.TokenProgram)
	computeBudget := solana.MustPublicKeyFromBase58(proto.ComputeBudgetProgram)

	dest, err := solanatx.FindAssociatedTokenAddressWithProgram(payTo, mint, tokenProgram)
	if err != nil {
		t.Fatal(err)
	}

	keys := solana.PublicKeySlice{
		feePayer,      // 0
		source,        // 1
		mint,          // 2
		dest,          // 3
		authority,     // 4
		computeBudget, // 5
		tokenProgram,  // 6
	}

	const amount = uint64(1000)
	limitData := []byte{2, 0, 0, 0, 0}
	priceData := make([]byte, 9)
	priceData[0] = 3
	binary.LittleEndian.PutUint64(priceData[1:], 1000) // 1000 microLamports, under cap
	transferData := make([]byte, 10)
	transferData[0] = 12
	binary.LittleEndian.PutUint64(transferData[1:9], amount)
	transferData[9] = 6 // decimals

	return fixture{
		keys:         keys,
		computeLimit: solana.CompiledInstruction{ProgramIDIndex: 5, Data: limitData},
		computePrice: solana.CompiledInstruction{ProgramIDIndex: 5, Data: priceData},
		transfer: solana.CompiledInstruction{
			ProgramIDIndex: 6,
			Accounts:       []uint16{1, 2, 3, 4},
			Data:           transferData,
		},
		req: proto.TransferRequirements{
			PayTo:        payTo,
			Mint:         mint,
			TokenProgram: tokenProgram,
			Amount:       amount,
			FeePayer:     feePayer,
		},
	}
}

func (f fixture) tx(extra ...solana.CompiledInstruction) *solana.Transaction {
	ixs := append([]solana.CompiledInstruction{f.computeLimit, f.computePrice, f.transfer}, extra...)
	tx := &solana.Transaction{
		Message:    solana.Message{AccountKeys: f.keys, Instructions: ixs},
		Signatures: []solana.Signature{{}},
	}
	tx.Message.SetVersion(solana.MessageVersionV0)
	return tx
}

func TestVerifyAcceptsValidTransaction(t *testing.T) {
	f := newFixture(t)
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err != nil {
		t.Fatalf("expected valid tx to pass, got %v", err)
	}
}

func TestVerifyAcceptsTrailingMemo(t *testing.T) {
	f := newFixture(t)
	memoKeyIdx := uint16(len(f.keys))
	f.keys = append(f.keys, solana.MustPublicKeyFromBase58(paycore.MemoProgram))
	memo := solana.CompiledInstruction{ProgramIDIndex: memoKeyIdx, Data: []byte("/paid")}
	if err := proto.VerifyExactTransaction(f.tx(memo), f.req); err != nil {
		t.Fatalf("expected memo-trailing tx to pass, got %v", err)
	}
}

// TestVerifyAcceptsTrailingLighthouse proves a wallet-injected Lighthouse
// guard instruction in an optional slot is allowed (Phantom injects 1,
// Solflare 2), per the x402 SVM spec.
func TestVerifyAcceptsTrailingLighthouse(t *testing.T) {
	f := newFixture(t)
	lhIdx := uint16(len(f.keys))
	f.keys = append(f.keys, solana.MustPublicKeyFromBase58(proto.LighthouseProgram))
	lh := solana.CompiledInstruction{ProgramIDIndex: lhIdx, Data: []byte{0x01}}
	// Two Lighthouse instructions (Solflare-style) must also pass.
	if err := proto.VerifyExactTransaction(f.tx(lh, lh), f.req); err != nil {
		t.Fatalf("expected trailing Lighthouse instructions to pass, got %v", err)
	}
}

// TestVerifyRejectsTrailingATACreate proves a Create-ATA (Associated Token
// Program) instruction in an optional slot is rejected: the x402 SVM spec
// requires the destination ATA to pre-exist.
func TestVerifyRejectsTrailingATACreate(t *testing.T) {
	f := newFixture(t)
	ataIdx := uint16(len(f.keys))
	f.keys = append(f.keys, solana.MustPublicKeyFromBase58(paycore.AssociatedTokenProgram))
	ata := solana.CompiledInstruction{ProgramIDIndex: ataIdx, Data: []byte{1}}
	if err := proto.VerifyExactTransaction(f.tx(ata), f.req); err == nil {
		t.Error("expected rejection for trailing ATA-create instruction")
	}
}

// TestVerifyEnforcesExpectedMemoMatch proves that when the offer pins
// extra.memo the verifier requires exactly one Memo whose data equals it.
func TestVerifyEnforcesExpectedMemoMatch(t *testing.T) {
	mkMemo := func(t *testing.T, f *fixture, data string) solana.CompiledInstruction {
		idx := uint16(len(f.keys))
		f.keys = append(f.keys, solana.MustPublicKeyFromBase58(paycore.MemoProgram))
		return solana.CompiledInstruction{ProgramIDIndex: idx, Data: []byte(data)}
	}

	t.Run("matching memo passes", func(t *testing.T) {
		f := newFixture(t)
		f.req.ExpectedMemo = "pi_invoice_42"
		memo := mkMemo(t, &f, "pi_invoice_42")
		if err := proto.VerifyExactTransaction(f.tx(memo), f.req); err != nil {
			t.Fatalf("expected matching memo to pass, got %v", err)
		}
	})

	t.Run("wrong memo rejected", func(t *testing.T) {
		f := newFixture(t)
		f.req.ExpectedMemo = "pi_invoice_42"
		memo := mkMemo(t, &f, "different")
		if err := proto.VerifyExactTransaction(f.tx(memo), f.req); err == nil {
			t.Error("expected rejection for memo not matching extra.memo")
		}
	})

	t.Run("missing memo rejected", func(t *testing.T) {
		f := newFixture(t)
		f.req.ExpectedMemo = "pi_invoice_42"
		if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
			t.Error("expected rejection when extra.memo set but no memo present")
		}
	})
}

func TestVerifyRejectsTooFewInstructions(t *testing.T) {
	f := newFixture(t)
	tx := &solana.Transaction{
		Message:    solana.Message{AccountKeys: f.keys, Instructions: []solana.CompiledInstruction{f.computeLimit, f.computePrice}},
		Signatures: []solana.Signature{{}},
	}
	if err := proto.VerifyExactTransaction(tx, f.req); err == nil {
		t.Error("expected rejection for <3 instructions")
	}
}

func TestVerifyRejectsTooManyInstructions(t *testing.T) {
	f := newFixture(t)
	memoKeyIdx := uint16(len(f.keys))
	f.keys = append(f.keys, solana.MustPublicKeyFromBase58(paycore.MemoProgram))
	memo := solana.CompiledInstruction{ProgramIDIndex: memoKeyIdx, Data: []byte("x")}
	// 3 base + 5 memo = 8 instructions, over the §3.1 cap of 7.
	if err := proto.VerifyExactTransaction(f.tx(memo, memo, memo, memo, memo), f.req); err == nil {
		t.Error("expected rejection for >7 instructions")
	}
	// 3 base + 4 memo = 7 instructions is the largest static layout.
	if err := proto.VerifyExactTransaction(f.tx(memo, memo, memo, memo), f.req); err != nil {
		t.Errorf("7-instruction layout rejected: %v", err)
	}
}

func TestVerifyRejectsBadComputeLimit(t *testing.T) {
	f := newFixture(t)
	f.computeLimit.Data = []byte{99, 0, 0, 0, 0} // wrong discriminator
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection for bad compute-limit instruction")
	}
}

func TestVerifyRejectsComputePriceOverCap(t *testing.T) {
	f := newFixture(t)
	binary.LittleEndian.PutUint64(f.computePrice.Data[1:], proto.MaxComputeUnitPriceMicroLamports+1)
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection for compute price over cap")
	}
}

func TestVerifyRejectsWrongAmount(t *testing.T) {
	f := newFixture(t)
	binary.LittleEndian.PutUint64(f.transfer.Data[1:9], 999)
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection for amount mismatch")
	}
}

func TestVerifyRejectsWrongMint(t *testing.T) {
	f := newFixture(t)
	f.keys[2] = solana.MustPublicKeyFromBase58(paycore.USDTMainnetMint)
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection for mint mismatch")
	}
}

func TestVerifyRejectsWrongDestination(t *testing.T) {
	f := newFixture(t)
	f.keys[3] = solana.NewWallet().PublicKey() // not the payTo ATA
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection for recipient ATA mismatch")
	}
}

func TestVerifyRejectsFeePayerAsAuthority(t *testing.T) {
	f := newFixture(t)
	f.keys[4] = f.req.FeePayer // fee-payer moving the funds
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection when fee-payer is the transfer authority")
	}
}

func TestVerifyRejectsNonTransferThirdInstruction(t *testing.T) {
	f := newFixture(t)
	f.transfer.Data[0] = 7 // not transferChecked (discriminator 12)
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection when ix[2] is not transferChecked")
	}
}

func TestVerifyRejectsUnknownTrailingProgram(t *testing.T) {
	f := newFixture(t)
	sysIdx := uint16(len(f.keys))
	f.keys = append(f.keys, solana.MustPublicKeyFromBase58(paycore.SystemProgram))
	rogue := solana.CompiledInstruction{ProgramIDIndex: sysIdx, Data: []byte{0}}
	if err := proto.VerifyExactTransaction(f.tx(rogue), f.req); err == nil {
		t.Error("expected rejection for unknown trailing instruction program")
	}
}

func TestVerifyRejectsAccountIndexOutOfRange(t *testing.T) {
	f := newFixture(t)
	f.transfer.Accounts = []uint16{1, 2, 3, 99} // authority index past key list
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection for out-of-range account index")
	}
}

// --- VerifyAndSettle: structural rejection (no RPC) + full settle
// path through a fake RPC ---

// fakeRPC is the rpcClient test double for the broadcast + confirmation
// path. send/confirm behaviour is scripted per field.
type fakeRPC struct {
	sig        solana.Signature
	sendErr    error
	confirm    rpc.ConfirmationStatusType
	confirmErr *struct{ msg string } // non-nil => on-chain tx error
	nullStatus bool                  // no status recorded for the signature
	sends      int
	sent       string // the last base64 wire transaction handed to sendTransaction
}

func (f *fakeRPC) SendEncodedTransactionWithOpts(_ context.Context, encoded string, _ rpc.TransactionOpts) (solana.Signature, error) {
	f.sends++
	f.sent = encoded
	if f.sendErr != nil {
		return solana.Signature{}, f.sendErr
	}
	return f.sig, nil
}

func (f *fakeRPC) GetSignatureStatuses(_ context.Context, _ bool, _ ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	if f.nullStatus {
		return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{nil}}, nil
	}
	st := &rpc.SignatureStatusesResult{ConfirmationStatus: f.confirm}
	if f.confirmErr != nil {
		st.Err = f.confirmErr.msg
	}
	return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{st}}, nil
}

func (f *fakeRPC) GetLatestBlockhash(_ context.Context, _ rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return &rpc.GetLatestBlockhashResult{Value: &rpc.LatestBlockhashResult{}}, nil
}

// settleFixture builds an adapter whose operator IS the fixture
// fee-payer + recipient, a matching valid transaction signed by the client's
// transfer authority, and a credential wrapping it. Returns everything
// VerifyAndSettle needs to settle.
func settleFixture(t *testing.T, fake *fakeRPC) (*Adapter, *paykit.Gate, string) {
	t.Helper()
	a, gate, tx, _ := settleFixtureParts(t, fake)
	return a, gate, credentialFor(t, a, gate, tx)
}

// settleFixtureParts is settleFixture before the credential is encoded: the
// client-signed transaction (operator slot 0 left empty) and the authority
// key that signed slot 1, so a test can tamper with either.
func settleFixtureParts(t *testing.T, fake *fakeRPC) (*Adapter, *paykit.Gate, *solana.Transaction, solana.PrivateKey) {
	t.Helper()
	// Operator = a generated signer; payTo defaults to its pubkey.
	op := signer.Generate()
	opPub := solana.MustPublicKeyFromBase58(string(op.Pubkey()))
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	tokenProgram := solana.MustPublicKeyFromBase58(paycore.TokenProgram)
	authorityKey := solana.NewWallet().PrivateKey
	authority := authorityKey.PublicKey()
	source := solana.NewWallet().PublicKey()
	dest, err := solanatx.FindAssociatedTokenAddressWithProgram(opPub, mint, tokenProgram)
	if err != nil {
		t.Fatal(err)
	}
	computeBudget := solana.MustPublicKeyFromBase58(proto.ComputeBudgetProgram)

	keys := solana.PublicKeySlice{opPub, authority, source, mint, dest, computeBudget, tokenProgram}
	const amount = uint64(1000)
	priceData := make([]byte, 9)
	priceData[0] = 3
	binary.LittleEndian.PutUint64(priceData[1:], 1000)
	transferData := make([]byte, 10)
	transferData[0] = 12
	binary.LittleEndian.PutUint64(transferData[1:9], amount)
	transferData[9] = 6
	tx := &solana.Transaction{
		Message: solana.Message{
			AccountKeys: keys,
			Header:      solana.MessageHeader{NumRequiredSignatures: 2, NumReadonlyUnsignedAccounts: 3},
			Instructions: []solana.CompiledInstruction{
				{ProgramIDIndex: 5, Data: []byte{2, 0, 0, 0, 0}},
				{ProgramIDIndex: 5, Data: priceData},
				{ProgramIDIndex: 6, Accounts: []uint16{2, 3, 4, 1}, Data: transferData},
			},
		},
	}
	tx.Message.SetVersion(solana.MessageVersionV0)
	tx.Signatures = []solana.Signature{{}, signMessage(t, tx, authorityKey)}
	a := &Adapter{
		cfg: paykit.Config{
			Network:     paykit.SolanaLocalnet,
			Stablecoins: []paykit.Stablecoin{paykit.USDC},
			Operator:    paykit.Operator{Signer: op, Recipient: op.Pubkey()},
			X402:        paykit.X402Config{Scheme: "exact"},
		},
		signer:            op,
		rpc:               fake,
		blockhashProvider: func() (string, error) { return "BH", nil },
	}
	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}
	return a, gate, tx, authorityKey
}

func signMessage(t *testing.T, tx *solana.Transaction, key solana.PrivateKey) solana.Signature {
	t.Helper()
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := key.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func credentialFor(t *testing.T, a *Adapter, gate *paykit.Gate, tx *solana.Transaction) string {
	t.Helper()
	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	cred := proto.Credential{X402Version: proto.X402Version, Accepted: acceptedFor(a, gate), Payload: proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString(wire)}}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(credJSON)
}

func TestVerifyAndSettleHappyPath(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, sig := settleFixture(t, fake)
	pmt, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig})
	if err != nil {
		t.Fatalf("expected settle to succeed, got %v", err)
	}
	if pmt.Protocol != paykit.X402 || pmt.Transaction != sampleSig {
		t.Errorf("payment: %+v", pmt)
	}
	if pmt.SettlementHeaders[proto.SettlementHeader] != sampleSig {
		t.Error("settlement header missing")
	}
}

func TestVerifyAndSettleConfirmationError(t *testing.T) {
	fake := &fakeRPC{
		sig:        solana.MustSignatureFromBase58(sampleSig),
		confirm:    rpc.ConfirmationStatusConfirmed,
		confirmErr: &struct{ msg string }{msg: "InstructionError"},
	}
	a, gate, sig := settleFixture(t, fake)
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig})
	if err == nil {
		t.Fatal("expected settlement_failed on on-chain error")
	}
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "settlement_failed" {
		t.Errorf("expected settlement_failed, got %v", err)
	}
}

func settleCode(err error) string {
	var perr *paykit.PaymentError
	if errorsAs(err, &perr) {
		return perr.Code
	}
	return ""
}

// Only a preflight rejection proves the node was never handed the
// transaction, so only it releases the claim for a retry.
func TestVerifyAndSettlePreflightRejectionReleasesTheClaim(t *testing.T) {
	fake := &fakeRPC{sendErr: &jsonrpc.RPCError{Code: -32002, Message: "Transaction simulation failed"}}
	a, gate, sig := settleFixture(t, fake)
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); settleCode(err) != "send_failed" {
		t.Fatalf("expected send_failed, got %v", err)
	}
	fake.sendErr = nil
	fake.sig = solana.MustSignatureFromBase58(sampleSig)
	fake.confirm = rpc.ConfirmationStatusConfirmed
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); err != nil {
		t.Fatalf("retry after a preflight rejection should settle, got %v", err)
	}
	if fake.sends != 2 {
		t.Fatalf("the released transaction is broadcast again: sends=%d", fake.sends)
	}
}

// Any other send error leaves the outcome unknown: the claim is kept, the
// payer is told to retry the same payment, and the retry is reconciled from
// the chain (never re-broadcast) and granted once.
func TestVerifyAndSettleAmbiguousSendKeepsTheClaimUntilReconciled(t *testing.T) {
	fake := &fakeRPC{sendErr: context.DeadlineExceeded}
	a, gate, sig := settleFixture(t, fake)
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); settleCode(err) != paykit.CodeSettlementInProgress {
		t.Fatalf("expected settlement_in_progress, got %v", err)
	}
	// Still no status: still in progress, not a failure.
	fake.sendErr = nil
	fake.nullStatus = true
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); settleCode(err) != paykit.CodeSettlementInProgress {
		t.Fatalf("a missing status keeps it in progress, got %v", err)
	}
	fake.nullStatus = false
	fake.confirm = rpc.ConfirmationStatusConfirmed
	pmt, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig})
	if err != nil {
		t.Fatalf("the landed payment reconciles, got %v", err)
	}
	if pmt.Transaction != settledSignature(t, a, sig) {
		t.Fatalf("reconciled transaction %s", pmt.Transaction)
	}
	if fake.sends != 1 {
		t.Fatalf("a pending settlement is never re-broadcast: sends=%d", fake.sends)
	}
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); settleCode(err) != "signature_consumed" {
		t.Fatalf("granted once, got %v", err)
	}
}

// A confirmation poll that ends with no status is not proof the transaction
// never landed.
func TestVerifyAndSettleConfirmationTimeoutKeepsTheClaim(t *testing.T) {
	attempts, delay := confirmAttempts, confirmDelay
	confirmAttempts, confirmDelay = 2, time.Millisecond
	t.Cleanup(func() { confirmAttempts, confirmDelay = attempts, delay })
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), nullStatus: true}
	a, gate, sig := settleFixture(t, fake)
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); settleCode(err) != paykit.CodeSettlementInProgress {
		t.Fatalf("expected settlement_in_progress, got %v", err)
	}
	fake.nullStatus = false
	fake.confirm = rpc.ConfirmationStatusFinalized
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); err != nil {
		t.Fatalf("the landed payment reconciles, got %v", err)
	}
	if fake.sends != 1 {
		t.Fatalf("sends=%d", fake.sends)
	}
}

func TestVerifyAndSettleReplayRejected(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusFinalized}
	a, gate, sig := settleFixture(t, fake)
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); err != nil {
		t.Fatalf("first settle: %v", err)
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig})
	if err == nil {
		t.Fatal("expected signature_consumed on replay")
	}
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "signature_consumed" {
		t.Errorf("expected signature_consumed, got %v", err)
	}
}

// A payment settled through MPP on a gate sharing the store must not be
// accepted again as an x402 proof: both protocols claim the co-signed
// transaction's signature in one ledger.
func TestVerifyAndSettleRejectsSignatureConsumedByMPP(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusFinalized}
	a, gate, sig := settleFixture(t, fake)
	store := core.NewMemoryStore()
	a.cfg.MPP.Store = store
	ledger := paycore.NewConsumedSignatures(store)

	key := settledSignature(t, a, sig)
	if claimed, err := ledger.Claim(context.Background(), key); err != nil || !claimed {
		t.Fatalf("MPP-side claim: claimed=%v err=%v", claimed, err)
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "signature_consumed" {
		t.Fatalf("expected signature_consumed, got %v", err)
	}

	// Positive control: on a fresh shared store x402 settles, and its claim
	// is visible to MPP through the same ledger.
	a, gate, sig = settleFixture(t, fake)
	store = core.NewMemoryStore()
	a.cfg.MPP.Store = store
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); err != nil {
		t.Fatalf("settle: %v", err)
	}
	claimed, err := paycore.NewConsumedSignatures(store).Claim(context.Background(), settledSignature(t, a, sig))
	if err != nil || claimed {
		t.Fatalf("x402 settlement must claim the shared ledger: claimed=%v err=%v", claimed, err)
	}
}

// settledSignature is the signature the adapter claims for sig: the first
// signature of the co-signed wire transaction.
func settledSignature(t *testing.T, a *Adapter, sig string) string {
	t.Helper()
	credJSON, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	var cred proto.Credential
	if err := json.Unmarshal(credJSON, &cred); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(cred.Payload.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := solanatx.DecodeTransaction(raw)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.cosign(context.Background(), tx, raw)
	if err != nil {
		t.Fatal(err)
	}
	key, err := transactionReplayKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestTransactionReplayKeyIsTheCosignedFeePayerSignature(t *testing.T) {
	feePayer := solana.NewWallet().PrivateKey
	client := solana.NewWallet().PrivateKey
	tx := &solana.Transaction{
		Message: solana.Message{AccountKeys: solana.PublicKeySlice{feePayer.PublicKey(), client.PublicKey()}},
	}
	tx.Message.Header.NumRequiredSignatures = 2
	feePayerSig := signMessage(t, tx, feePayer)
	tx.Signatures = []solana.Signature{feePayerSig, signMessage(t, tx, client)}
	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	key, err := transactionReplayKey(wire)
	if err != nil {
		t.Fatalf("transactionReplayKey: %v", err)
	}
	if key != feePayerSig.String() {
		t.Fatalf("replay key = %s, want %s", key, feePayerSig)
	}

	// Not yet co-signed: no on-chain identity to claim.
	tx.Signatures[0] = solana.Signature{}
	wire, err = tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transactionReplayKey(wire); err == nil {
		t.Fatal("expected a transaction without its fee payer signature to be rejected")
	}
}

func TestVerifyAndSettleRejectsTransactionThatDoesNotPayGate(t *testing.T) {
	// Operator recipient != fixture payTo, so the destination ATA
	// mismatch is caught BEFORE any broadcast.
	op := signer.Generate()
	a := &Adapter{
		cfg: paykit.Config{
			Network:     paykit.SolanaLocalnet,
			Stablecoins: []paykit.Stablecoin{paykit.USDC},
			Operator:    paykit.Operator{Signer: op, Recipient: op.Pubkey()},
			X402:        paykit.X402Config{Scheme: "exact"},
		},
		signer:            op,
		rpc:               &fakeRPC{},
		blockhashProvider: func() (string, error) { return "BH", nil },
	}
	f := newFixture(t)
	wire, err := f.tx().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.001")}
	cred := proto.Credential{X402Version: proto.X402Version, Accepted: acceptedFor(a, &gate), Payload: proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString(wire)}}
	credJSON, _ := json.Marshal(cred)
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: base64.StdEncoding.EncodeToString(credJSON)})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "invalid_exact_svm_payload_recipient_mismatch" {
		t.Errorf("expected invalid_exact_svm_payload_recipient_mismatch, got %v", err)
	}
}

const sampleSig = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"
const sampleClientSig = "3APVUYY2Qcq9WwPSciQ1xicshQcsXJWhgD1x5YEMNnNnKtpaAJtRhDVMWcvePosamk3JfSKpBM8qt5ZkAQgRNSzo"

func TestRecentBlockhashUsesProviderThenRPC(t *testing.T) {
	// Provider wins when set.
	a := &Adapter{blockhashProvider: func() (string, error) { return "STUBHASH", nil }}
	if bh, err := a.recentBlockhash(); err != nil || bh != "STUBHASH" {
		t.Fatalf("provider path: bh=%q err=%v", bh, err)
	}
	// Falls back to the RPC when no provider.
	a2 := &Adapter{rpc: &fakeRPC{}}
	if _, err := a2.recentBlockhash(); err != nil {
		t.Fatalf("rpc path: %v", err)
	}
	// Errors when neither is available.
	a3 := &Adapter{}
	if _, err := a3.recentBlockhash(); err == nil {
		t.Error("expected error when no provider and no rpc")
	}
}

func TestAcceptsEntryAndCoinFallbacks(t *testing.T) {
	op := signer.Generate()
	a := &Adapter{
		cfg: paykit.Config{
			Network:     paykit.SolanaLocalnet,
			Stablecoins: []paykit.Stablecoin{paykit.USDC},
			Operator:    paykit.Operator{Signer: op, Recipient: op.Pubkey()},
			X402:        paykit.X402Config{Scheme: "exact"},
		},
		signer: op,
		rpc:    &fakeRPC{},
	}
	// No blockhash provider -> AcceptsEntry pulls it from the RPC.
	entry := a.AcceptsEntry(&paykit.Gate{Amount: paykit.MustParseUSD("0.10")}).(AcceptsEntry)
	if entry.Extra.RecentBlockhash == "" {
		t.Error("expected recentBlockhash populated from rpc")
	}
	// Gate PayTo overrides operator recipient.
	withPayTo := &paykit.Gate{Amount: paykit.MustParseUSD("0.10"), PayTo: paykit.Address("SELLER")}
	if a.payTo(withPayTo) != paykit.Address("SELLER") {
		t.Error("gate PayTo should override")
	}
	// Gate settlement preference overrides config default.
	narrowed := &paykit.Gate{Amount: paykit.MustParseUSD("0.10", paykit.USDT)}
	if a.settlementCoin(narrowed) != "USDT" {
		t.Error("gate settlement pref should win")
	}
}

func TestVerifyAndSettleRejectsUndecodableTransaction(t *testing.T) {
	op := signer.Generate()
	a := &Adapter{
		cfg:    paykit.Config{Network: paykit.SolanaLocalnet, Stablecoins: []paykit.Stablecoin{paykit.USDC}, Operator: paykit.Operator{Signer: op, Recipient: op.Pubkey()}, X402: paykit.X402Config{Scheme: "exact"}},
		signer: op,
		rpc:    &fakeRPC{},
	}
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.001")}
	cred := proto.Credential{X402Version: proto.X402Version, Accepted: acceptedFor(a, &gate), Payload: proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("not-a-tx"))}}
	credJSON, _ := json.Marshal(cred)
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: base64.StdEncoding.EncodeToString(credJSON)})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "invalid_payload" {
		t.Errorf("expected invalid_payload, got %v", err)
	}
}

// A legacy (unprefixed) transaction passes the decode boundary: the adapter
// only rejects it later, on its content, exactly like a version-0 message.
func TestVerifyAndSettleDecodesLegacyTransaction(t *testing.T) {
	op := signer.Generate()
	a := &Adapter{
		cfg:    paykit.Config{Network: paykit.SolanaLocalnet, Stablecoins: []paykit.Stablecoin{paykit.USDC}, Operator: paykit.Operator{Signer: op, Recipient: op.Pubkey()}, X402: paykit.X402Config{Scheme: "exact"}},
		signer: op,
		rpc:    &fakeRPC{},
	}
	memo, err := solanatx.BuildMemoInstruction("legacy")
	if err != nil {
		t.Fatal(err)
	}
	bh := solana.MustHashFromBase58(testutil.NewPrivateKey().PublicKey().String())
	tx, err := solana.NewTransaction([]solana.Instruction{memo}, bh, solana.TransactionPayer(testutil.NewPrivateKey().PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatal(err)
	}
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.001")}
	cred := proto.Credential{X402Version: proto.X402Version, Accepted: acceptedFor(a, &gate), Payload: proto.CredentialPayload{Transaction: encoded}}
	credJSON, _ := json.Marshal(cred)
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: base64.StdEncoding.EncodeToString(credJSON)})
	if err == nil {
		t.Fatal("a memo-only payment must still be rejected on its content")
	}
	if strings.Contains(err.Error(), "transaction decode") || strings.Contains(err.Error(), "legacy") {
		t.Fatalf("legacy message was rejected at the decode boundary: %v", err)
	}
}

func TestVerifyAndSettleRejectsBadOperatorRecipient(t *testing.T) {
	op := signer.Generate()
	a := &Adapter{
		// Recipient is not valid base58 -> transferRequirements fails.
		cfg:    paykit.Config{Network: paykit.SolanaLocalnet, Stablecoins: []paykit.Stablecoin{paykit.USDC}, Operator: paykit.Operator{Signer: op, Recipient: paykit.Address("not base58!!!")}, X402: paykit.X402Config{Scheme: "exact"}},
		signer: op,
		rpc:    &fakeRPC{},
	}
	f := newFixture(t)
	wire, _ := f.tx().MarshalBinary()
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.001")}
	cred := proto.Credential{X402Version: proto.X402Version, Accepted: acceptedFor(a, &gate), Payload: proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString(wire)}}
	credJSON, _ := json.Marshal(cred)
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: base64.StdEncoding.EncodeToString(credJSON)})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "invalid_gate" {
		t.Errorf("expected invalid_gate, got %v", err)
	}
}

func TestVerifyRejectsComputePriceWrongLength(t *testing.T) {
	f := newFixture(t)
	f.computePrice.Data = []byte{3, 0, 0} // discriminator ok, length wrong
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection for wrong-length compute price data")
	}
}

func TestVerifyRejectsTransferTooFewAccounts(t *testing.T) {
	f := newFixture(t)
	f.transfer.Accounts = []uint16{1, 2, 3} // need >= 4
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection for transferChecked with <4 accounts")
	}
}

func TestVerifyRejectsNonTokenTransferProgram(t *testing.T) {
	f := newFixture(t)
	f.keys[6] = solana.MustPublicKeyFromBase58(paycore.SystemProgram) // ix[2] program now System
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection when ix[2] program is not an SPL token program")
	}
}

func TestVerifyRejectsComputeLimitWrongProgram(t *testing.T) {
	f := newFixture(t)
	f.keys[5] = solana.MustPublicKeyFromBase58(paycore.SystemProgram) // compute ixs now point at System
	if err := proto.VerifyExactTransaction(f.tx(), f.req); err == nil {
		t.Error("expected rejection when ix[0] program is not ComputeBudget")
	}
}

func TestCosignPassthroughWhenOperatorAbsent(t *testing.T) {
	a, _, _ := settleFixture(t, &fakeRPC{})
	// A transaction whose fee payer is a random key the operator does not
	// hold: the operator has no empty signature slot, so cosign ships the
	// original wire bytes unchanged.
	payer := testutil.NewPrivateKey().PublicKey()
	memo, err := solanatx.BuildMemoInstruction("hi")
	if err != nil {
		t.Fatal(err)
	}
	bh := solana.MustHashFromBase58(testutil.NewPrivateKey().PublicKey().String())
	tx, err := solanatx.NewV0Transaction([]solana.Instruction{memo}, bh, solana.TransactionPayer(payer))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.cosign(context.Background(), tx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Error("cosign should pass the wire through untouched when the operator is not a missing signer")
	}
}

func TestTransferRequirementsRejectsUnresolvableMint(t *testing.T) {
	a, _, _ := settleFixture(t, &fakeRPC{})
	bad := &paykit.Gate{Amount: paykit.MustParseUSD("0.10", paykit.Stablecoin("@@notamint"))}
	if _, err := a.transferRequirements(bad); err == nil {
		t.Error("expected an error resolving a bogus settlement currency to a mint")
	}
}

func TestAwaitConfirmationHonorsContextCancellation(t *testing.T) {
	a, _, _ := settleFixture(t, &fakeRPC{}) // no confirmation status -> would loop
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.awaitConfirmation(ctx, solana.Signature{}); err == nil {
		t.Error("expected awaitConfirmation to return once the context is cancelled")
	}
}

// acceptedFor returns the offer this adapter advertises for gate, which a
// v2 client echoes verbatim as `accepted` (required by x402 v2).
func acceptedFor(a *Adapter, gate *paykit.Gate) *proto.AcceptsEntry {
	route := a.routeAccepts(gate)
	return &route
}

// failingPendingStore refuses writes of pending-settlement records.
type failingPendingStore struct {
	core.Store
	fail bool
}

func (s *failingPendingStore) PutIfAbsent(ctx context.Context, key string, value any) (bool, error) {
	if s.fail && strings.HasPrefix(key, pendingSettlementPrefix) {
		return false, errors.New("injected store outage")
	}
	return s.Store.PutIfAbsent(ctx, key, value)
}

// The pending record a retry reconciles is written with the claim, before
// anything is sent: written after, a store failure would strand a payment
// that may have landed (claimed, with no record to reconcile).
func TestVerifyAndSettleRecordsPendingBeforeSending(t *testing.T) {
	fake := &fakeRPC{sendErr: context.DeadlineExceeded}
	a, gate, sig := settleFixture(t, fake)
	store := &failingPendingStore{Store: core.NewMemoryStore(), fail: true}
	a.cfg.MPP.Store = store
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); settleCode(err) != "store_error" {
		t.Fatalf("expected store_error, got %v", err)
	}
	if fake.sends != 0 {
		t.Fatalf("a transaction without a recovery record was sent: sends=%d", fake.sends)
	}
	// Nothing was sent, so the claim was given back.
	store.fail = false
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); settleCode(err) != paykit.CodeSettlementInProgress {
		t.Fatalf("expected settlement_in_progress, got %v", err)
	}
	if _, found, _ := store.Get(context.Background(), pendingSettlementPrefix+settledSignature(t, a, sig)); !found {
		t.Fatal("an ambiguous send must leave a pending record")
	}
}
