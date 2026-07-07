package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
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
	return &solana.Transaction{
		Message:    solana.Message{AccountKeys: f.keys, Instructions: ixs},
		Signatures: []solana.Signature{{}},
	}
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
	// 3 base + 4 memo = 7 instructions, over the cap of 6.
	if err := proto.VerifyExactTransaction(f.tx(memo, memo, memo, memo), f.req); err == nil {
		t.Error("expected rejection for >6 instructions")
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
	sends      int
}

func (f *fakeRPC) SendEncodedTransactionWithOpts(_ context.Context, _ string, _ rpc.TransactionOpts) (solana.Signature, error) {
	f.sends++
	if f.sendErr != nil {
		return solana.Signature{}, f.sendErr
	}
	return f.sig, nil
}

func (f *fakeRPC) GetSignatureStatuses(_ context.Context, _ bool, _ ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
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
// fee-payer + recipient, a matching valid transaction, and a credential
// wrapping it. Returns everything VerifyAndSettle needs to settle.
func settleFixture(t *testing.T, fake *fakeRPC) (*Adapter, *paykit.Gate, string) {
	t.Helper()
	// Operator = a generated signer; payTo defaults to its pubkey.
	op := signer.Generate()
	opPub := solana.MustPublicKeyFromBase58(string(op.Pubkey()))
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	tokenProgram := solana.MustPublicKeyFromBase58(paycore.TokenProgram)
	authority := solana.NewWallet().PublicKey()
	source := solana.NewWallet().PublicKey()
	dest, err := solanatx.FindAssociatedTokenAddressWithProgram(opPub, mint, tokenProgram)
	if err != nil {
		t.Fatal(err)
	}
	computeBudget := solana.MustPublicKeyFromBase58(proto.ComputeBudgetProgram)

	keys := solana.PublicKeySlice{opPub, source, mint, dest, authority, computeBudget, tokenProgram}
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
			Instructions: []solana.CompiledInstruction{
				{ProgramIDIndex: 5, Data: []byte{2, 0, 0, 0, 0}},
				{ProgramIDIndex: 5, Data: priceData},
				{ProgramIDIndex: 6, Accounts: []uint16{1, 2, 3, 4}, Data: transferData},
			},
		},
		Signatures: []solana.Signature{{}, solana.MustSignatureFromBase58(sampleClientSig)},
	}
	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	cred := proto.Credential{X402Version: proto.X402Version, Payload: proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString(wire)}}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}

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
	return a, gate, base64.StdEncoding.EncodeToString(credJSON)
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

func TestVerifyAndSettleSendFailureRollsBackReplay(t *testing.T) {
	fake := &fakeRPC{sendErr: context.DeadlineExceeded}
	a, gate, sig := settleFixture(t, fake)
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); err == nil {
		t.Fatal("expected send_failed")
	}
	// Replay reservation must have been rolled back: a retry with a
	// working RPC then succeeds rather than tripping signature_consumed.
	fake.sendErr = nil
	fake.sig = solana.MustSignatureFromBase58(sampleSig)
	fake.confirm = rpc.ConfirmationStatusConfirmed
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); err != nil {
		t.Fatalf("retry after rollback should succeed, got %v", err)
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

func TestTransactionReplayKeySkipsSponsoredFeePayerSlot(t *testing.T) {
	clientSig := solana.MustSignatureFromBase58(sampleClientSig)
	tx := &solana.Transaction{Signatures: []solana.Signature{{}, clientSig}}
	key, err := transactionReplayKey(tx)
	if err != nil {
		t.Fatalf("transactionReplayKey: %v", err)
	}
	if key != sampleClientSig {
		t.Fatalf("replay key = %s, want %s", key, sampleClientSig)
	}
}

func TestTransactionReplayKeyRejectsUnsignedTransaction(t *testing.T) {
	tx := &solana.Transaction{Signatures: []solana.Signature{{}}}
	_, err := transactionReplayKey(tx)
	if err == nil {
		t.Fatal("expected unsigned transaction to be rejected")
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
	cred := proto.Credential{X402Version: proto.X402Version, Payload: proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString(wire)}}
	credJSON, _ := json.Marshal(cred)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.001")}
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
	cred := proto.Credential{X402Version: proto.X402Version, Payload: proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("not-a-tx"))}}
	credJSON, _ := json.Marshal(cred)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.001")}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: base64.StdEncoding.EncodeToString(credJSON)})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "invalid_payload" {
		t.Errorf("expected invalid_payload, got %v", err)
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
	cred := proto.Credential{X402Version: proto.X402Version, Payload: proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString(wire)}}
	credJSON, _ := json.Marshal(cred)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.001")}
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
	tx, err := solana.NewTransaction([]solana.Instruction{memo}, bh, solana.TransactionPayer(payer))
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
