package server

// Offline investigation/regression tests for the session co-signing boundary.
// Negative cases use a harmless unsupported instruction. The signer refuses to
// produce a signature, and the RPC spy has no network transport.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

var errOfflineSigningBoundary = errors.New("offline probe: signature intentionally withheld")
var errOfflineRPCBoundary = errors.New("offline probe: no broadcast transport exists")

const offlineInstructionMarker = "pay-kit-unsupported-instruction-probe"

type offlineSessionSigner struct {
	publicKey       solana.PublicKey
	calls           int
	sawMarker       bool
	expectedMessage []byte
	sawExactMessage bool
}

func (s *offlineSessionSigner) PublicKey() solana.PublicKey { return s.publicKey }

func (s *offlineSessionSigner) Sign(message []byte) (solana.Signature, error) {
	s.calls++
	s.sawMarker = bytes.Contains(message, []byte(offlineInstructionMarker))
	s.sawExactMessage = bytes.Equal(message, s.expectedMessage)
	return solana.Signature{}, errOfflineSigningBoundary
}

// All inherited RPC methods are in-memory fakes. Even if a later refactor
// reaches SendTransactionWithOpts, this override cannot submit anything.
type offlineSessionRPC struct {
	*testutil.FakeRPC
	sendAttempts int
}

func (r *offlineSessionRPC) SendTransactionWithOpts(context.Context, *solana.Transaction, rpc.TransactionOpts) (solana.Signature, error) {
	r.sendAttempts++
	return solana.Signature{}, errOfflineRPCBoundary
}

func offlineSessionOpen(t *testing.T, legacy bool, extraPosition string) (openTxFixture, *offlineSessionSigner, *offlineSessionRPC) {
	t.Helper()
	return buildOfflineSessionOpen(t, legacy, func(open solana.Instruction, operator solana.PublicKey) []solana.Instruction {
		if extraPosition == "" {
			return []solana.Instruction{open}
		}
		// An ephemeral program key with no implementation or RPC connection.
		extra := solana.NewInstruction(testutil.NewPrivateKey().PublicKey(),
			solana.AccountMetaSlice{solana.Meta(operator).SIGNER()}, []byte(offlineInstructionMarker))
		switch extraPosition {
		case "before":
			return []solana.Instruction{extra, open}
		case "after":
			return []solana.Instruction{open, extra}
		case "duplicate-open":
			return []solana.Instruction{open, open}
		default:
			t.Fatalf("unknown probe position %q", extraPosition)
			return nil
		}
	})
}

func buildOfflineSessionOpen(t *testing.T, legacy bool, instructionsFor func(solana.Instruction, solana.PublicKey) []solana.Instruction) (openTxFixture, *offlineSessionSigner, *offlineSessionRPC) {
	t.Helper()
	operator := testutil.NewPrivateKey()
	f := buildServerCompletedOpenFixture(t, operator)
	open := offlineOpenInstruction(t, f, operator.PublicKey())
	instructions := instructionsFor(open, operator.PublicKey())
	blockhash := solana.MustHashFromBase58("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
	var tx *solana.Transaction
	var err error
	if legacy {
		tx, err = solana.NewTransaction(instructions, blockhash, solana.TransactionPayer(operator.PublicKey()))
	} else {
		tx, err = solanatx.NewV0Transaction(instructions, blockhash, solana.TransactionPayer(operator.PublicKey()))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := solanatx.SignTransaction(tx, f.payer); err != nil {
		t.Fatal(err)
	}
	// Ensure the fixture exercises a real, correctly signed client message,
	// while the server/operator slot is still unsigned.
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !tx.Message.AccountKeys[0].Equals(operator.PublicKey()) || !tx.Signatures[0].IsZero() {
		t.Fatal("operator must not already have signed")
	}
	foundPayer := false
	for i, key := range tx.Message.Signers() {
		if key.Equals(f.payer.PublicKey()) {
			foundPayer = tx.Signatures[i].Verify(key, message)
		}
	}
	if !foundPayer {
		t.Fatal("client signature must be valid for the full test message")
	}
	wire, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatal(err)
	}
	f.payload.Transaction = &wire
	return f, &offlineSessionSigner{publicKey: operator.PublicKey(), expectedMessage: append([]byte(nil), message...)}, &offlineSessionRPC{FakeRPC: testutil.NewFakeRPC()}
}

func offlineOpenInstruction(t *testing.T, f openTxFixture, rentPayer solana.PublicKey) solana.Instruction {
	t.Helper()
	program := paymentchannels.ProgramPubkey()
	if f.expected.ProgramID != nil {
		program = *f.expected.ProgramID
	}
	open, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		ProgramID: program, Payer: f.payer.PublicKey(), RentPayer: rentPayer,
		Payee: f.payee, Mint: f.mint, AuthorizedSigner: f.authorized,
		Salt: openFixtureSalt, Deposit: openFixtureDeposit, GracePeriod: openFixtureGrace,
		OpenSlot: openFixtureOpenSlot, TokenProgram: solana.TokenProgramID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return open
}

func invokeOfflineSessionOpen(t *testing.T, entry string, f openTxFixture, signer *offlineSessionSigner, rpcClient *offlineSessionRPC) error {
	t.Helper()
	if entry == "direct" {
		_, err := SubmitOpenTx(context.Background(), f.expected, &f.payload, signer, rpcClient)
		return err
	}
	s := newTestSession(t, func(o *SessionOptions) {
		o.Operator = signer.PublicKey().String()
		o.Recipient = f.expected.Recipient
		o.OpenTxSubmitter = OpenTxSubmitterServer
		o.PaymentChannelPayerSigner = signer
		o.RPC = rpcClient
	})
	_, err := verifySessionAction(t, s, intents.NewOpenAction(f.payload))
	return err
}

// EfeDurmaz16's earlier PR239 proposed rejecting extras with an instruction
// count check. These regressions retain that boundary while permitting Rust's
// validated ComputeBudget wrappers.
func TestSessionCosigningRejectsUnsupportedInstructionsBeforeSigning(t *testing.T) {
	for _, encoding := range []string{"legacy", "v0"} {
		for _, position := range []string{"before", "after", "duplicate-open"} {
			for _, entry := range []string{"direct", "public-method"} {
				t.Run(encoding+"/"+position+"/"+entry, func(t *testing.T) {
					f, signer, rpcClient := offlineSessionOpen(t, encoding == "legacy", position)
					err := invokeOfflineSessionOpen(t, entry, f, signer, rpcClient)
					t.Logf("signer calls=%d, unsupported marker in signing message=%v, exact full message=%v, RPC send attempts=%d", signer.calls, signer.sawMarker, signer.sawExactMessage, rpcClient.sendAttempts)
					if rpcClient.sendAttempts != 0 {
						t.Fatal("invalid open reached the RPC boundary")
					}
					if signer.calls != 0 {
						t.Fatalf("invalid open reached operator signer before rejection: %v", err)
					}
					if err == nil {
						t.Fatal("invalid open accepted")
					}
				})
			}
		}
	}
}

func TestSessionCosigningCanonicalOpenReachesOfflineSigner(t *testing.T) {
	for _, encoding := range []string{"legacy", "v0"} {
		for _, entry := range []string{"direct", "public-method"} {
			t.Run(encoding+"/"+entry, func(t *testing.T) {
				f, signer, rpcClient := offlineSessionOpen(t, encoding == "legacy", "")
				err := invokeOfflineSessionOpen(t, entry, f, signer, rpcClient)
				if signer.calls != 1 || signer.sawMarker || !signer.sawExactMessage || rpcClient.sendAttempts != 0 ||
					(err == nil || !strings.Contains(err.Error(), errOfflineSigningBoundary.Error())) {
					t.Fatalf("valid-open control: calls=%d marker=%v RPC=%d err=%v", signer.calls, signer.sawMarker, rpcClient.sendAttempts, err)
				}
			})
		}
	}
}

func TestSessionCosigningWrongRecipientRejectedBeforeOfflineSigner(t *testing.T) {
	for _, entry := range []string{"direct", "public-method"} {
		t.Run(entry, func(t *testing.T) {
			f, signer, rpcClient := offlineSessionOpen(t, false, "")
			f.expected.Recipient = testutil.NewPrivateKey().PublicKey().String()
			err := invokeOfflineSessionOpen(t, entry, f, signer, rpcClient)
			if err == nil || signer.calls != 0 || rpcClient.sendAttempts != 0 {
				t.Fatalf("wrong-recipient control: calls=%d RPC=%d err=%v", signer.calls, rpcClient.sendAttempts, err)
			}
		})
	}
}

func TestSessionCosigningComputeBudgetPolicy(t *testing.T) {
	cases := []struct {
		name        string
		data        []byte
		withAccount bool
		valid       bool
	}{
		{"limit-at-Rust-cap", encodeUnitLimit(200_000), false, true},
		{"limit-zero", encodeUnitLimit(0), false, true},
		{"limit-over-cap", encodeUnitLimit(200_001), false, false},
		{"price-at-sponsored-Rust-cap", encodeUnitPrice(10_000), false, true},
		{"price-zero", encodeUnitPrice(0), false, true},
		{"price-over-sponsored-cap", encodeUnitPrice(10_001), false, false},
		{"empty-data", nil, false, false},
		{"short-limit", []byte{2, 1}, false, false},
		{"trailing-limit-data", append(encodeUnitLimit(1), 0), false, false},
		{"short-price", []byte{3, 1}, false, false},
		{"trailing-price-data", append(encodeUnitPrice(1), 0), false, false},
		{"unsupported-heap-operation", []byte{1, 0, 0, 0, 0}, false, false},
		{"unsupported-loaded-accounts-operation", []byte{4, 0, 0, 0, 0}, false, false},
		{"unknown-operation", []byte{255}, false, false},
		{"unexpected-accounts", encodeUnitLimit(1), true, false},
	}
	for _, tc := range cases {
		for _, legacy := range []bool{false, true} {
			for _, entry := range []string{"direct", "public-method"} {
				encoding := "v0"
				if legacy {
					encoding = "legacy"
				}
				t.Run(tc.name+"/"+encoding+"/"+entry, func(t *testing.T) {
					f, signer, rpcClient := buildOfflineSessionOpen(t, legacy, func(open solana.Instruction, operator solana.PublicKey) []solana.Instruction {
						var accounts solana.AccountMetaSlice
						if tc.withAccount {
							accounts = solana.AccountMetaSlice{solana.Meta(operator)}
						}
						budget := solana.NewInstruction(computeBudgetProgramID, accounts, tc.data)
						return []solana.Instruction{budget, open}
					})
					err := invokeOfflineSessionOpen(t, entry, f, signer, rpcClient)
					if rpcClient.sendAttempts != 0 {
						t.Fatal("offline test reached submission boundary")
					}
					if tc.valid {
						if signer.calls != 1 || !signer.sawExactMessage || err == nil || !strings.Contains(err.Error(), errOfflineSigningBoundary.Error()) {
							t.Fatalf("valid budget rejected before signer: calls=%d err=%v", signer.calls, err)
						}
					} else if signer.calls != 0 || err == nil {
						t.Fatalf("invalid budget not rejected before signer: calls=%d err=%v", signer.calls, err)
					}
				})
			}
		}
	}
}

func TestSessionCosigningRejectsTrailingOverCapBudget(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, entry := range []string{"direct", "public-method"} {
			for _, budget := range []struct {
				name string
				data []byte
			}{
				{"limit", encodeUnitLimit(200_001)},
				{"price", encodeUnitPrice(10_001)},
			} {
				t.Run(fmt.Sprintf("legacy=%v/%s/%s", legacy, entry, budget.name), func(t *testing.T) {
					f, signer, rpcClient := buildOfflineSessionOpen(t, legacy, func(open solana.Instruction, _ solana.PublicKey) []solana.Instruction {
						return []solana.Instruction{
							solana.NewInstruction(computeBudgetProgramID, nil, encodeUnitLimit(100_000)),
							open,
							solana.NewInstruction(computeBudgetProgramID, nil, budget.data),
						}
					})
					err := invokeOfflineSessionOpen(t, entry, f, signer, rpcClient)
					if err == nil || signer.calls != 0 || rpcClient.sendAttempts != 0 || !strings.Contains(err.Error(), "exceeds maximum") {
						t.Fatalf("trailing budget policy: calls=%d sends=%d err=%v", signer.calls, rpcClient.sendAttempts, err)
					}
				})
			}
		}
	}
}

func TestSessionCosigningAllowsCappedBudgetAroundOpen(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			f, signer, rpcClient := buildOfflineSessionOpen(t, legacy, func(open solana.Instruction, _ solana.PublicKey) []solana.Instruction {
				limit := solana.NewInstruction(computeBudgetProgramID, nil, encodeUnitLimit(200_000))
				price := solana.NewInstruction(computeBudgetProgramID, nil, encodeUnitPrice(10_000))
				if after {
					return []solana.Instruction{open, limit, price}
				}
				return []solana.Instruction{limit, open, price}
			})
			err := invokeOfflineSessionOpen(t, "direct", f, signer, rpcClient)
			if signer.calls != 1 || !signer.sawExactMessage || err == nil || rpcClient.sendAttempts != 0 {
				t.Fatalf("capped budget wrapper: calls=%d err=%v", signer.calls, err)
			}
		}
	}
}

func TestSessionCosigningRejectsDuplicateBudgetOperations(t *testing.T) {
	for _, budget := range []struct {
		name          string
		first, second []byte
	}{
		{"identical-limit", encodeUnitLimit(100_000), encodeUnitLimit(100_000)},
		{"different-limit", encodeUnitLimit(100_000), encodeUnitLimit(200_000)},
		{"zero-limit", encodeUnitLimit(0), encodeUnitLimit(0)},
		{"identical-price", encodeUnitPrice(5_000), encodeUnitPrice(5_000)},
		{"different-price", encodeUnitPrice(5_000), encodeUnitPrice(10_000)},
		{"zero-price", encodeUnitPrice(0), encodeUnitPrice(0)},
	} {
		for _, legacy := range []bool{false, true} {
			for _, entry := range []string{"direct", "public-method"} {
				for _, position := range []string{"before", "around", "after"} {
					t.Run(fmt.Sprintf("%s/legacy=%v/%s/%s", budget.name, legacy, entry, position), func(t *testing.T) {
						f, signer, rpcClient := buildOfflineSessionOpen(t, legacy, func(open solana.Instruction, _ solana.PublicKey) []solana.Instruction {
							first := solana.NewInstruction(computeBudgetProgramID, nil, budget.first)
							second := solana.NewInstruction(computeBudgetProgramID, nil, budget.second)
							switch position {
							case "before":
								return []solana.Instruction{first, second, open}
							case "after":
								return []solana.Instruction{open, first, second}
							default:
								return []solana.Instruction{first, open, second}
							}
						})
						err := invokeOfflineSessionOpen(t, entry, f, signer, rpcClient)
						if err == nil || !strings.Contains(err.Error(), "duplicate compute budget") || signer.calls != 0 || rpcClient.sendAttempts != 0 {
							t.Fatalf("duplicate budget: signing=%d sends=%d err=%v", signer.calls, rpcClient.sendAttempts, err)
						}
					})
				}
			}
		}
	}
}

func TestSessionCosigningRejectsOtherProgramsAndChannelOperations(t *testing.T) {
	programs := map[string]solana.PublicKey{
		"system":                    solana.SystemProgramID,
		"token":                     solana.TokenProgramID,
		"token-2022":                solana.MustPublicKeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
		"memo":                      solana.MustPublicKeyFromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
		"associated-token":          solana.SPLAssociatedTokenAccountProgramID,
		"another-channel-operation": paymentchannels.ProgramPubkey(),
	}
	for name, program := range programs {
		t.Run(name, func(t *testing.T) {
			f, signer, rpcClient := buildOfflineSessionOpen(t, false, func(open solana.Instruction, _ solana.PublicKey) []solana.Instruction {
				extra := solana.NewInstruction(program, nil, []byte(offlineInstructionMarker))
				return []solana.Instruction{open, extra}
			})
			err := invokeOfflineSessionOpen(t, "direct", f, signer, rpcClient)
			if err == nil || signer.calls != 0 || rpcClient.sendAttempts != 0 {
				t.Fatalf("unsupported operation reached signer: calls=%d err=%v", signer.calls, err)
			}
		})
	}
}

func TestSessionCosigningRejectsDuplicateOpenWithBudget(t *testing.T) {
	f, signer, rpcClient := buildOfflineSessionOpen(t, false, func(open solana.Instruction, _ solana.PublicKey) []solana.Instruction {
		budget := solana.NewInstruction(computeBudgetProgramID, nil, encodeUnitLimit(200_000))
		return []solana.Instruction{open, budget, open}
	})
	if err := invokeOfflineSessionOpen(t, "direct", f, signer, rpcClient); err == nil || signer.calls != 0 || rpcClient.sendAttempts != 0 {
		t.Fatalf("duplicate open reached signer: calls=%d err=%v", signer.calls, err)
	}
}

func TestSessionCosigningPinsProvidedSigner(t *testing.T) {
	f, signer, rpcClient := offlineSessionOpen(t, false, "")
	// The client payer is a required signer, but is not the configured operator.
	signer.publicKey = f.payer.PublicKey()
	if err := invokeOfflineSessionOpen(t, "direct", f, signer, rpcClient); err == nil || signer.calls != 0 || rpcClient.sendAttempts != 0 {
		t.Fatalf("wrong signer context invoked: calls=%d err=%v", signer.calls, err)
	}
}

func TestSessionCosigningRejectsOutOfRangeProgramIndex(t *testing.T) {
	f, signer, rpcClient := offlineSessionOpen(t, false, "after")
	tx, err := solanatx.DecodeTransactionBase64(*f.payload.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	tx.Message.Instructions[1].ProgramIDIndex = uint16(len(tx.Message.AccountKeys))
	if err := solanatx.SignTransaction(tx, f.payer); err != nil {
		t.Fatal(err)
	}
	wire, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatal(err)
	}
	f.payload.Transaction = &wire
	signer.expectedMessage, err = tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := invokeOfflineSessionOpen(t, "direct", f, signer, rpcClient); err == nil || signer.calls != 0 || rpcClient.sendAttempts != 0 {
		t.Fatalf("invalid program index reached signer: calls=%d err=%v", signer.calls, err)
	}
}

// Keep the positive signing cases funded when confirmed-channel validation is
// enabled too. This fixture is independent of the confirmed-channel PR's tests.
type cosigningChannelRPC struct {
	*testutil.FakeRPC
	channel solana.PublicKey
	account *rpc.Account
}

func (r *cosigningChannelRPC) GetAccountInfoWithOpts(ctx context.Context, account solana.PublicKey, opts *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	if !account.Equals(r.channel) {
		return r.FakeRPC.GetAccountInfoWithOpts(ctx, account, opts)
	}
	return &rpc.GetAccountInfoResult{Value: r.account}, nil
}

func newCosigningChannelRPC(t *testing.T, f openTxFixture) *cosigningChannelRPC {
	t.Helper()
	_, bump, err := paymentchannels.FindChannelPDA(f.payer.PublicKey(), f.payee, f.mint, f.authorized, openFixtureSalt, openFixtureOpenSlot)
	if err != nil {
		t.Fatal(err)
	}
	channel := pcgen.Channel{
		// The IDL assigns channel = 1; the generated discriminator enum omits
		// explicit values and must not be used for the account's wire header.
		Discriminator: 1, Version: 1, Bump: bump, Status: uint8(pcgen.ChannelStatus_Open),
		Salt: openFixtureSalt, Deposit: openFixtureDeposit, GracePeriod: openFixtureGrace,
		DistributionHash: sha256.Sum256([]byte{0, 0, 0, 0}), Payer: f.payer.PublicKey(),
		Payee: f.payee, Mint: f.mint, AuthorizedSigner: f.authorized, RentPayer: f.payer.PublicKey(),
		OpenSlot: openFixtureOpenSlot,
	}
	var data bytes.Buffer
	if err := channel.MarshalWithEncoder(bin.NewBorshEncoder(&data)); err != nil {
		t.Fatal(err)
	}
	return &cosigningChannelRPC{
		FakeRPC: testutil.NewFakeRPC(), channel: f.channel,
		account: &rpc.Account{Owner: paymentchannels.ProgramPubkey(), Data: rpc.DataBytesOrJSONFromBytes(data.Bytes())},
	}
}

func TestSessionCosigningPriceCapDependsOnSigner(t *testing.T) {
	for _, sponsored := range []bool{false, true} {
		for _, price := range []uint64{10_000, 10_001, 5_000_000, 5_000_001} {
			t.Run(fmt.Sprintf("signer=%v/price=%d", sponsored, price), func(t *testing.T) {
				f := buildOpenTxFixture(t)
				open := offlineOpenInstruction(t, f, f.payer.PublicKey())
				budget := solana.NewInstruction(computeBudgetProgramID, nil, encodeUnitPrice(price))
				tx, err := solanatx.NewV0Transaction([]solana.Instruction{budget, open}, solana.MustHashFromBase58("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"), solana.TransactionPayer(f.payer.PublicKey()))
				if err != nil {
					t.Fatal(err)
				}
				if err := solanatx.SignTransaction(tx, f.payer); err != nil {
					t.Fatal(err)
				}
				wire, err := solanatx.EncodeTransactionBase64(tx)
				if err != nil {
					t.Fatal(err)
				}
				f.payload.Transaction = &wire
				f.payload.Signature = tx.Signatures[0].String()
				var signer solanatx.Signer
				var refusingSigner *offlineSessionSigner
				cap := uint64(5_000_000)
				if sponsored {
					cap = 10_000
					if price > cap {
						refusingSigner = &offlineSessionSigner{publicKey: f.payer.PublicKey()}
						signer = refusingSigner
					} else {
						signer = f.payer
					}
				}
				fake := newCosigningChannelRPC(t, f)
				result, err := SubmitOpenTx(context.Background(), f.expected, &f.payload, signer, fake)
				if price <= cap {
					if err != nil || len(fake.Sent) != 1 || result.Signature != tx.Signatures[0].String() {
						t.Fatalf("valid price flow: sends=%d err=%v", len(fake.Sent), err)
					}
				} else if err == nil || len(fake.Sent) != 0 {
					t.Fatalf("over-cap price submitted: sends=%d err=%v", len(fake.Sent), err)
				}
				if refusingSigner != nil && refusingSigner.calls != 0 {
					t.Fatalf("over-cap price reached signer: calls=%d", refusingSigner.calls)
				}
			})
		}
	}
}

func TestSessionCosigningRejectsNonOperatorFeePayer(t *testing.T) {
	operator := testutil.NewPrivateKey()
	f := buildServerCompletedOpenFixture(t, operator)
	open := offlineOpenInstruction(t, f, operator.PublicKey())
	// The operator remains the open's rent payer but is a nonzero signer slot.
	tx, err := solanatx.NewV0Transaction([]solana.Instruction{open}, solana.MustHashFromBase58("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"), solana.TransactionPayer(f.payer.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if err := solanatx.SignTransaction(tx, f.payer); err != nil {
		t.Fatal(err)
	}
	wire, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatal(err)
	}
	f.payload.Transaction = &wire
	if _, err := VerifyOpenTx(context.Background(), f.expected, &f.payload, nil); err != nil {
		t.Fatalf("structural control: %v", err)
	}
	signer := &offlineSessionSigner{publicKey: operator.PublicKey()}
	rpcClient := &offlineSessionRPC{FakeRPC: testutil.NewFakeRPC()}
	if err := invokeOfflineSessionOpen(t, "direct", f, signer, rpcClient); err == nil || signer.calls != 0 || rpcClient.sendAttempts != 0 {
		t.Fatalf("wrong fee payer reached signer: calls=%d err=%v", signer.calls, err)
	}
}
