package server

import (
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
)

// buildSPLTransferIx is a small helper that mirrors the way the client builds
// the canonical transferChecked instruction for these allowlist tests.
func buildSPLTransferIx(t *testing.T, payer, recipient, mint solana.PublicKey, amount uint64) solana.Instruction {
	t.Helper()
	sourceATA, err := solanatx.FindAssociatedTokenAddressWithProgram(payer, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata: %v", err)
	}
	recipientATA, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find recipient ata: %v", err)
	}
	ix, err := token.NewTransferCheckedInstruction(amount, 6, sourceATA, mint, recipientATA, payer, nil).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build transfer: %v", err)
	}
	return ix
}

// TestVerifyTransfersRejectsExtraSystemInstruction is the core GO-4 regression:
// a transaction whose expected SPL transfer matches but which smuggles an
// extra System Program transfer must be rejected by the post-match allowlist.
// Before the allowlist, the extra System instruction passed silently because
// only leftover Memo Program instructions were rejected.
func TestVerifyTransfersRejectsExtraSystemInstruction(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, payer.PublicKey(), recipient, mint, 1000)
	// An unrelated System transfer the verifier never expected.
	sneaky, err := system.NewTransferInstruction(42, payer.PublicKey(), testutil.NewPrivateKey().PublicKey()).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build system transfer: %v", err)
	}
	tx := newTestTransaction(t, payer, transfer, sneaky)

	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{})
	if err == nil {
		t.Fatal("expected extra System Program instruction to be rejected")
	}
	if !strings.Contains(err.Error(), "System Program") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsExtraTokenInstruction proves an unmatched extra
// Token Program transfer (e.g. draining a different ATA) is rejected.
func TestVerifyTransfersRejectsExtraTokenInstruction(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	attacker := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, payer.PublicKey(), recipient, mint, 1000)
	// A second token transfer to an attacker-controlled recipient.
	extra := buildSPLTransferIx(t, payer.PublicKey(), attacker, mint, 5000)
	tx := newTestTransaction(t, payer, transfer, extra)

	err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{})
	if err == nil {
		t.Fatal("expected extra Token Program instruction to be rejected")
	}
	if !strings.Contains(err.Error(), "Token Program") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsUnknownProgramInstruction proves an instruction
// whose program is neither compute budget, memo, system, token, token-2022,
// nor the associated token program is rejected.
func TestVerifyTransfersRejectsUnknownProgramInstruction(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, payer.PublicKey(), recipient, mint, 1000)
	unknownProgram := testutil.NewPrivateKey().PublicKey()
	unknown := solana.NewInstruction(unknownProgram, solana.AccountMetaSlice{
		solana.Meta(payer.PublicKey()).SIGNER(),
	}, []byte{9, 9, 9})
	tx := newTestTransaction(t, payer, transfer, unknown)

	err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{})
	if err == nil {
		t.Fatal("expected unknown program instruction to be rejected")
	}
	if !strings.Contains(err.Error(), "unexpected program instruction") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersAcceptsIdempotentATACreateForRecipient proves a valid
// idempotent ATA-create funded by the fee payer for an authorized owner is
// allowed (mirrors rust validate_create_ata_idempotent_instruction). This is
// the fee-payer sponsorship flow where methodDetails.feePayerKey is pinned.
func TestVerifyTransfersAcceptsIdempotentATACreateForRecipient(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey() // transfer authority / source owner
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	createATA, err := solanatx.BuildCreateAssociatedTokenAccount(feePayer.PublicKey(), recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("build create ata: %v", err)
	}
	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)
	// Fee payer is the transaction payer (account 0) for sponsorship.
	tx := newTestTransaction(t, feePayer, createATA, transfer)

	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("expected idempotent ATA-create to be accepted: %v", err)
	}
}

// TestVerifyTransfersRejectsATACreateForNativeSOL proves an ATA-create is
// rejected entirely on a native SOL payment.
func TestVerifyTransfersRejectsATACreateForNativeSOL(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	solTransfer, err := system.NewTransferInstruction(1000, payer.PublicKey(), recipient).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build sol transfer: %v", err)
	}
	createATA, err := solanatx.BuildCreateAssociatedTokenAccount(payer.PublicKey(), recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("build create ata: %v", err)
	}
	tx := newTestTransaction(t, payer, solTransfer, createATA)

	err = verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", paycore.MethodDetails{})
	if err == nil {
		t.Fatal("expected ATA-create on native SOL to be rejected")
	}
	if !strings.Contains(err.Error(), "native SOL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsATACreateForUnauthorizedOwner proves an
// idempotent ATA-create targeting an owner who is not a payment recipient is
// rejected.
func TestVerifyTransfersRejectsATACreateForUnauthorizedOwner(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	stranger := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)
	createATA, err := solanatx.BuildCreateAssociatedTokenAccount(feePayer.PublicKey(), stranger, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("build create ata: %v", err)
	}
	tx := newTestTransaction(t, feePayer, transfer, createATA)

	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
	})
	if err == nil {
		t.Fatal("expected ATA-create for unauthorized owner to be rejected")
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// boolPtr is a tiny helper for the *bool ataCreationRequired field.
func boolPtr(b bool) *bool { return &b }

// TestVerifyTransfersRejectsMissingRequiredATACreation is the required-ATA
// regression: a fee-payer-sponsored charge with a split recipient pinned as
// ataCreationRequired=true must contain an idempotent ATA-create for that
// recipient. A transaction that carries both transfers but omits the required
// ATA-create must be rejected, mirroring the rust reference check
// "missing required ATA creation instruction for split recipient".
//
// Before the required/created tracking was ported, this transaction passed
// because the allowlist only validated ATA-creates that were PRESENT and never
// enforced that required ones existed.
func TestVerifyTransfersRejectsMissingRequiredATACreation(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey() // transfer authority / source owner
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	// total 1000 = primary 700 + split 300.
	primaryTransfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 700)
	splitTransfer := buildSPLTransferIx(t, signer.PublicKey(), splitRecipient, mint, 300)
	// No ATA-create for the split recipient even though it is required.
	tx := newTestTransaction(t, feePayer, primaryTransfer, splitTransfer)

	details := paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
		Splits: []paycore.Split{
			{
				Recipient:           splitRecipient.String(),
				Amount:              "300",
				AtaCreationRequired: boolPtr(true),
			},
		},
	}
	err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", details)
	if err == nil {
		t.Fatal("expected missing required ATA creation to be rejected")
	}
	if !strings.Contains(err.Error(), "missing required ATA creation instruction for split recipient") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), splitRecipient.String()) {
		t.Fatalf("error should name the split recipient: %v", err)
	}
}

// TestVerifyTransfersAcceptsRequiredATACreation is the pass-after companion:
// the same fee-payer-sponsored split charge succeeds once the required
// idempotent ATA-create for the split recipient is present.
func TestVerifyTransfersAcceptsRequiredATACreation(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	primaryTransfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 700)
	createSplitATA, err := solanatx.BuildCreateAssociatedTokenAccount(feePayer.PublicKey(), splitRecipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("build create ata: %v", err)
	}
	splitTransfer := buildSPLTransferIx(t, signer.PublicKey(), splitRecipient, mint, 300)
	tx := newTestTransaction(t, feePayer, primaryTransfer, createSplitATA, splitTransfer)

	details := paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
		Splits: []paycore.Split{
			{
				Recipient:           splitRecipient.String(),
				Amount:              "300",
				AtaCreationRequired: boolPtr(true),
			},
		},
	}
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", details); err != nil {
		t.Fatalf("expected required ATA-create charge to be accepted: %v", err)
	}
}

// buildATACreateIx assembles an Associated Token Program instruction with
// caller-controlled accounts and discriminator so the allowlist rejection
// branches can be exercised individually. A valid idempotent create has the
// six accounts [payer, ata, owner, mint, systemProgram, tokenProgram] and
// data == [1].
func buildATACreateIx(accounts solana.AccountMetaSlice, data []byte) solana.Instruction {
	return solana.NewInstruction(
		solana.MustPublicKeyFromBase58(paycore.AssociatedTokenProgram),
		accounts,
		data,
	)
}

// TestVerifyTransfersRejectsATACreateWrongAccountLayout proves an ATA-create
// instruction that does not carry exactly six accounts is rejected.
func TestVerifyTransfersRejectsATACreateWrongAccountLayout(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)
	ata, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find ata: %v", err)
	}
	// Five accounts instead of the required six.
	bad := buildATACreateIx(solana.AccountMetaSlice{
		solana.Meta(feePayer.PublicKey()).WRITE().SIGNER(),
		solana.Meta(ata).WRITE(),
		solana.Meta(recipient),
		solana.Meta(mint),
		solana.Meta(solana.SystemProgramID),
	}, []byte{1})
	tx := newTestTransaction(t, feePayer, transfer, bad)

	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
	})
	if err == nil {
		t.Fatal("expected wrong ATA account layout to be rejected")
	}
	if !strings.Contains(err.Error(), "account layout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsATACreatePayerMismatch proves an ATA-create whose
// funding payer is not the transaction fee payer is rejected.
func TestVerifyTransfersRejectsATACreatePayerMismatch(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)
	ata, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find ata: %v", err)
	}
	// Account 0 (payer) is the signer, but the expected payer is the fee payer.
	bad := buildATACreateIx(solana.AccountMetaSlice{
		solana.Meta(signer.PublicKey()).WRITE().SIGNER(),
		solana.Meta(ata).WRITE(),
		solana.Meta(recipient),
		solana.Meta(mint),
		solana.Meta(solana.SystemProgramID),
		solana.Meta(solana.TokenProgramID),
	}, []byte{1})
	tx := newTestTransaction(t, feePayer, transfer, bad)

	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
	})
	if err == nil {
		t.Fatal("expected ATA-create payer mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "ATA payer must match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsATACreateMintMismatch proves an ATA-create whose
// mint differs from the charge currency is rejected.
func TestVerifyTransfersRejectsATACreateMintMismatch(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	otherMint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)
	ata, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, otherMint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find ata: %v", err)
	}
	bad := buildATACreateIx(solana.AccountMetaSlice{
		solana.Meta(feePayer.PublicKey()).WRITE().SIGNER(),
		solana.Meta(ata).WRITE(),
		solana.Meta(recipient),
		solana.Meta(otherMint),
		solana.Meta(solana.SystemProgramID),
		solana.Meta(solana.TokenProgramID),
	}, []byte{1})
	tx := newTestTransaction(t, feePayer, transfer, bad)

	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
	})
	if err == nil {
		t.Fatal("expected ATA-create mint mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "mint does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsATACreateWrongSystemProgram proves an ATA-create
// whose system-program account is not the System Program is rejected.
func TestVerifyTransfersRejectsATACreateWrongSystemProgram(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)
	ata, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find ata: %v", err)
	}
	bad := buildATACreateIx(solana.AccountMetaSlice{
		solana.Meta(feePayer.PublicKey()).WRITE().SIGNER(),
		solana.Meta(ata).WRITE(),
		solana.Meta(recipient),
		solana.Meta(mint),
		solana.Meta(testutil.NewPrivateKey().PublicKey()), // not the System Program
		solana.Meta(solana.TokenProgramID),
	}, []byte{1})
	tx := newTestTransaction(t, feePayer, transfer, bad)

	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
	})
	if err == nil {
		t.Fatal("expected ATA-create wrong system program to be rejected")
	}
	if !strings.Contains(err.Error(), "System Program") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsATACreateUnsupportedTokenProgram proves an
// ATA-create whose token-program account is neither Token nor Token-2022 is
// rejected.
func TestVerifyTransfersRejectsATACreateUnsupportedTokenProgram(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)
	ata, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find ata: %v", err)
	}
	bad := buildATACreateIx(solana.AccountMetaSlice{
		solana.Meta(feePayer.PublicKey()).WRITE().SIGNER(),
		solana.Meta(ata).WRITE(),
		solana.Meta(recipient),
		solana.Meta(mint),
		solana.Meta(solana.SystemProgramID),
		solana.Meta(testutil.NewPrivateKey().PublicKey()), // not a token program
	}, []byte{1})
	tx := newTestTransaction(t, feePayer, transfer, bad)

	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
	})
	if err == nil {
		t.Fatal("expected ATA-create unsupported token program to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported token program") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsATACreateAddressMismatch proves an ATA-create
// whose target address is not the canonical ATA derived from
// owner/mint/token program is rejected.
func TestVerifyTransfersRejectsATACreateAddressMismatch(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)
	// A bogus ATA address rather than the canonical derivation.
	bad := buildATACreateIx(solana.AccountMetaSlice{
		solana.Meta(feePayer.PublicKey()).WRITE().SIGNER(),
		solana.Meta(testutil.NewPrivateKey().PublicKey()).WRITE(),
		solana.Meta(recipient),
		solana.Meta(mint),
		solana.Meta(solana.SystemProgramID),
		solana.Meta(solana.TokenProgramID),
	}, []byte{1})
	tx := newTestTransaction(t, feePayer, transfer, bad)

	err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
	})
	if err == nil {
		t.Fatal("expected ATA-create address mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "address does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsATACreateTokenProgramMismatch proves that an
// idempotent ATA-create whose token program is a valid supported program (e.g.
// Token-2022) but does not match the token program pinned by methodDetails is
// rejected. This exercises the branch:
//
//	if params.expectedTokenProgram != nil && !tokenProgram.Equals(*params.expectedTokenProgram)
//
// which validateCreateATAIdempotentInstruction evaluates after confirming the
// token program is supported but before deriving the canonical ATA address.
func TestVerifyTransfersRejectsATACreateTokenProgramMismatch(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	// The expected transfer uses Token (spl-token), but the ATA-create uses
	// Token-2022 — a supported program that is not the expected one.
	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)

	// Build an ATA-create that uses Token-2022 as its token program, while
	// the transfer (and therefore methodDetails) pins Token.
	ataToken2022, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.Token2022ProgramID)
	if err != nil {
		t.Fatalf("find ata (token-2022): %v", err)
	}
	wrongProgram := buildATACreateIx(solana.AccountMetaSlice{
		solana.Meta(feePayer.PublicKey()).WRITE().SIGNER(),
		solana.Meta(ataToken2022).WRITE(),
		solana.Meta(recipient),
		solana.Meta(mint),
		solana.Meta(solana.SystemProgramID),
		solana.Meta(solana.Token2022ProgramID), // valid but mismatches expected Token
	}, []byte{1})
	tx := newTestTransaction(t, feePayer, transfer, wrongProgram)

	// methodDetails.tokenProgram is always filled from the RPC-observed mint
	// owner by verifyTransfersAgainstChallenge, so the pinned-mismatch branch
	// is not reachable through it. Drive the branch by calling
	// validateCreateATAIdempotentInstruction directly with a pinned
	// expectedTokenProgram that differs from the ATA-create's token program.
	expectedProgram := solana.TokenProgramID
	compiled := tx.Message.Instructions[1] // the ATA-create
	params := allowlistParams{
		expectedMint:         &mint,
		expectedTokenProgram: &expectedProgram,
		allowedATAOwners:     []solana.PublicKey{recipient},
		feePayer:             &[]solana.PublicKey{feePayer.PublicKey()}[0],
	}
	_, err = validateCreateATAIdempotentInstruction(tx, compiled, params, feePayer.PublicKey())
	if err == nil {
		t.Fatal("expected token program mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "token program does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyTransfersRejectsNonIdempotentATACreate proves a Create (data [0])
// rather than CreateIdempotent (data [1]) ATA instruction is rejected.
func TestVerifyTransfersRejectsNonIdempotentATACreate(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	transfer := buildSPLTransferIx(t, signer.PublicKey(), recipient, mint, 1000)
	ata, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find ata: %v", err)
	}
	// Same accounts as an idempotent create, but the non-idempotent
	// discriminator (data == [0]).
	nonIdempotent := solana.NewInstruction(
		solana.MustPublicKeyFromBase58(paycore.AssociatedTokenProgram),
		solana.AccountMetaSlice{
			solana.Meta(feePayer.PublicKey()).WRITE().SIGNER(),
			solana.Meta(ata).WRITE(),
			solana.Meta(recipient),
			solana.Meta(mint),
			solana.Meta(solana.SystemProgramID),
			solana.Meta(solana.TokenProgramID),
		},
		[]byte{0},
	)
	tx := newTestTransaction(t, feePayer, transfer, nonIdempotent)

	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		FeePayerKey: feePayer.PublicKey().String(),
	})
	if err == nil {
		t.Fatal("expected non-idempotent ATA-create to be rejected")
	}
	if !strings.Contains(err.Error(), "idempotent") {
		t.Fatalf("unexpected error: %v", err)
	}
}
