package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
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
)

// ── Pure validation tests (no RPC) ──

func uptoRequirements() UptoRequirements {
	decimals := uint8(6)
	return UptoRequirements{
		Scheme:            UptoScheme,
		Network:           "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Amount:            "1000000",
		Asset:             "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		PayTo:             "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
		MaxTimeoutSeconds: 300,
		Extra: UptoExtra{
			Profiles:       []string{ProfilePaymentChannel},
			Decimals:       &decimals,
			TokenProgram:   paycore.TokenProgram,
			FeePayer:       "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
			ChannelProgram: paymentchannels.ProgramID,
		},
	}
}

func uptoPayload() UptoPayload {
	return UptoPayload{
		Profile:          ProfilePaymentChannel,
		From:             "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
		MaxAmount:        "1000000",
		ExpiresAt:        4102444800,
		ValidAfter:       0,
		Nonce:            "n-1",
		ChannelID:        "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
		Deposit:          "1000000",
		AuthorizedSigner: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
		OpenTransaction:  "dGVzdA==",
	}
}

func TestVerifyUptoPayloadAcceptsValid(t *testing.T) {
	err := VerifyUptoPayload(uptoPayload(), uptoRequirements(), "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 1000)
	if err != nil {
		t.Fatalf("expected valid payload to pass, got %v", err)
	}
}

func TestVerifyUptoPayloadRejectsWrongProfile(t *testing.T) {
	p := uptoPayload()
	p.Profile = "permit"
	err := VerifyUptoPayload(p, uptoRequirements(), "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 1000)
	if err == nil || !strings.Contains(err.Error(), "invalid payload type") {
		t.Fatalf("expected invalid payload type, got %v", err)
	}
}

func TestVerifyUptoPayloadRejectsMaxMismatch(t *testing.T) {
	p := uptoPayload()
	p.MaxAmount = "999999"
	err := VerifyUptoPayload(p, uptoRequirements(), "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 1000)
	if err == nil || !strings.Contains(err.Error(), "amount mismatch") {
		t.Fatalf("expected amount mismatch, got %v", err)
	}
}

func TestVerifyUptoPayloadRejectsDepositBelowCeiling(t *testing.T) {
	p := uptoPayload()
	p.Deposit = "500000"
	err := VerifyUptoPayload(p, uptoRequirements(), "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 1000)
	if err == nil || !strings.Contains(err.Error(), "must equal the authorized maximum") {
		t.Fatalf("expected deposit below ceiling, got %v", err)
	}
}

func TestVerifyUptoPayloadRejectsDepositAboveCeiling(t *testing.T) {
	p := uptoPayload()
	p.Deposit = "1000001"
	err := VerifyUptoPayload(p, uptoRequirements(), "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 1000)
	if err == nil || !strings.Contains(err.Error(), "must equal the authorized maximum") {
		t.Fatalf("expected deposit above ceiling, got %v", err)
	}
}

func TestVerifyUptoPayloadRejectsExpired(t *testing.T) {
	p := uptoPayload()
	p.ExpiresAt = 500
	err := VerifyUptoPayload(p, uptoRequirements(), "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 1000)
	if err == nil || !strings.Contains(err.Error(), "authorization expired") {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestVerifyUptoPayloadRejectsNotYetActive(t *testing.T) {
	p := uptoPayload()
	p.ValidAfter = 2000
	err := VerifyUptoPayload(p, uptoRequirements(), "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 1000)
	if err == nil || !strings.Contains(err.Error(), "not yet active") {
		t.Fatalf("expected not yet active, got %v", err)
	}
}

func TestVerifyUptoPayloadRejectsWrongSigner(t *testing.T) {
	p := uptoPayload()
	p.AuthorizedSigner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
	err := VerifyUptoPayload(p, uptoRequirements(), "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 1000)
	if err == nil || !strings.Contains(err.Error(), "authorized_signer must be the operator") {
		t.Fatalf("expected wrong signer, got %v", err)
	}
}

func TestVerifyUptoPayloadRejectsUnadvertisedProfile(t *testing.T) {
	r := uptoRequirements()
	r.Extra.Profiles = []string{"permit"}
	p := uptoPayload()
	p.Profile = "permit"
	err := VerifyUptoPayload(p, r, "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 1000)
	if err == nil {
		t.Fatal("expected unadvertised profile rejection")
	}
}

func TestAssertSettlementWithinCeiling(t *testing.T) {
	if err := AssertSettlementWithinCeiling(0, 1000000); err != nil {
		t.Fatalf("expected zero amount within ceiling to pass, got %v", err)
	}
	if err := AssertSettlementWithinCeiling(999999, 1000000); err != nil {
		t.Fatalf("expected within ceiling to pass, got %v", err)
	}
	if err := AssertSettlementWithinCeiling(1000000, 1000000); err != nil {
		t.Fatalf("expected at ceiling to pass, got %v", err)
	}
	err := AssertSettlementWithinCeiling(1000001, 1000000)
	if err == nil || !strings.Contains(err.Error(), UptoErrorSettlementExceedsAmount) {
		t.Fatalf("expected over-ceiling error, got %v", err)
	}
}

// ── Challenge / header tests ──

func newUptoEngine(t *testing.T) *X402Upto {
	t.Helper()
	signer := testutil.NewPrivateKey()
	uptoCfg := UptoConfig{
		Recipient:         signer.PublicKey().String(),
		Currency:          "USDC",
		Decimals:          6,
		Network:           paykit.SolanaLocalnet,
		RPCURL:            "http://localhost:8899",
		MaxTimeoutSeconds: 300,
		OperatorSigner:    signerSigner{signer},
		RecentBlockhashProvider: func() (string, error) {
			return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil
		},
	}
	engine, err := NewX402Upto(uptoCfg)
	if err != nil {
		t.Fatalf("NewX402Upto: %v", err)
	}
	return engine
}

func TestUptoRequirementsBuilds(t *testing.T) {
	engine := newUptoEngine(t)
	req, err := engine.UptoRequirements("1.00")
	if err != nil {
		t.Fatalf("UptoRequirements: %v", err)
	}
	if req.Scheme != UptoScheme {
		t.Fatalf("scheme = %q, want %q", req.Scheme, UptoScheme)
	}
	if req.Amount != "1000000" {
		t.Fatalf("amount = %q, want 1000000", req.Amount)
	}
	if req.PayTo == "" {
		t.Fatal("payTo is empty")
	}
	if len(req.Extra.Profiles) != 1 || req.Extra.Profiles[0] != ProfilePaymentChannel {
		t.Fatalf("profiles = %v, want [payment-channel]", req.Extra.Profiles)
	}
	if req.Extra.FeePayer == "" {
		t.Fatal("feePayer is empty")
	}
	if req.Extra.ChannelProgram == "" {
		t.Fatal("channelProgram is empty")
	}
}

func TestUptoChallengeEnvelope(t *testing.T) {
	engine := newUptoEngine(t)
	envelope, err := engine.Upto("0.10")
	if err != nil {
		t.Fatalf("Upto: %v", err)
	}
	if envelope.X402Version != X402Version {
		t.Fatalf("X402Version = %d, want %d", envelope.X402Version, X402Version)
	}
	if len(envelope.Accepts) != 1 {
		t.Fatalf("accepts = %d, want 1", len(envelope.Accepts))
	}
	if envelope.Accepts[0].Amount != "100000" {
		t.Fatalf("amount = %q, want 100000", envelope.Accepts[0].Amount)
	}
	if envelope.Accepts[0].Extra.RecentBlockhash == "" {
		t.Fatal("recentBlockhash not stamped")
	}
}

func TestUptoPaymentRequiredHeader(t *testing.T) {
	engine := newUptoEngine(t)
	name, value, err := engine.PaymentRequiredHeader("0.10")
	if err != nil {
		t.Fatalf("PaymentRequiredHeader: %v", err)
	}
	if name != PaymentRequiredHeader {
		t.Fatalf("header name = %q, want %q", name, PaymentRequiredHeader)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var env UptoRequiredEnvelope
	if err := json.Unmarshal(decoded, &env); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if env.Accepts[0].Scheme != UptoScheme {
		t.Fatalf("scheme = %q, want %q", env.Accepts[0].Scheme, UptoScheme)
	}
}

func TestParseUptoPaymentSignatureValid(t *testing.T) {
	envelope := UptoSignatureEnvelope{
		X402Version: X402Version,
		Scheme:      UptoScheme,
		Payload:     uptoPayload(),
	}
	raw, _ := json.Marshal(envelope)
	encoded := base64.StdEncoding.EncodeToString(raw)
	parsed, err := ParseUptoPaymentSignature(encoded)
	if err != nil {
		t.Fatalf("ParseUptoPaymentSignature: %v", err)
	}
	if parsed.Scheme != UptoScheme {
		t.Fatalf("scheme = %q, want %q", parsed.Scheme, UptoScheme)
	}
	if parsed.Payload.MaxAmount != "1000000" {
		t.Fatalf("maxAmount = %q, want 1000000", parsed.Payload.MaxAmount)
	}
}

func TestParseUptoPaymentSignatureAcceptsUpstreamV2Envelope(t *testing.T) {
	accepted, err := uptoRequirements().AcceptedValue()
	if err != nil {
		t.Fatalf("AcceptedValue: %v", err)
	}
	envelope := UptoSignatureEnvelope{
		X402Version: X402Version,
		Accepted:    accepted,
		Payload:     uptoPayload(),
	}
	raw, _ := json.Marshal(envelope)
	encoded := base64.StdEncoding.EncodeToString(raw)
	parsed, err := ParseUptoPaymentSignature(encoded)
	if err != nil {
		t.Fatalf("ParseUptoPaymentSignature: %v", err)
	}
	if parsed.Scheme != UptoScheme {
		t.Fatalf("scheme = %q, want %q", parsed.Scheme, UptoScheme)
	}
	if parsed.Network != uptoRequirements().Network {
		t.Fatalf("network = %q, want %q", parsed.Network, uptoRequirements().Network)
	}
}

func TestParseUptoPaymentSignatureRejectsWrongScheme(t *testing.T) {
	envelope := UptoSignatureEnvelope{X402Version: X402Version, Scheme: "exact", Payload: uptoPayload()}
	raw, _ := json.Marshal(envelope)
	encoded := base64.StdEncoding.EncodeToString(raw)
	_, err := ParseUptoPaymentSignature(encoded)
	if err == nil || !strings.Contains(err.Error(), "invalid payload type") {
		t.Fatalf("expected wrong scheme rejection, got %v", err)
	}
}

func TestParseUptoPaymentSignatureRejectsInvalidBase64(t *testing.T) {
	_, err := ParseUptoPaymentSignature("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected base64 error")
	}
}

func TestSettlementHeader(t *testing.T) {
	engine := newUptoEngine(t)
	settlement := UptoSettlementResponse{Success: true, Transaction: "sig123", Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Amount: "500"}
	name, value, err := engine.SettlementHeader(settlement)
	if err != nil {
		t.Fatalf("SettlementHeader: %v", err)
	}
	if name != PaymentResponseHeader {
		t.Fatalf("header name = %q, want %q", name, PaymentResponseHeader)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var resp UptoSettlementResponse
	if err := json.Unmarshal(decoded, &resp); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if resp.Transaction != "sig123" {
		t.Fatalf("transaction = %q, want sig123", resp.Transaction)
	}
}

// ── Charge meter tests ──

func TestChargeDefaultsToZero(t *testing.T) {
	c := paykit.NewCharge(1_000_000)
	if c.SettledBaseUnits() != 0 {
		t.Fatalf("expected 0, got %d", c.SettledBaseUnits())
	}
}

func TestChargeRecordsAmount(t *testing.T) {
	c := paykit.NewCharge(1_000_000)
	c.Charge(400_000)
	if c.SettledBaseUnits() != 400_000 {
		t.Fatalf("expected 400000, got %d", c.SettledBaseUnits())
	}
}

func TestChargeClampsAboveCeiling(t *testing.T) {
	c := paykit.NewCharge(1_000_000)
	c.Charge(2_000_000)
	if c.SettledBaseUnits() != 1_000_000 {
		t.Fatalf("expected 1000000 (clamped), got %d", c.SettledBaseUnits())
	}
}

func TestChargeMaxBaseUnits(t *testing.T) {
	c := paykit.NewCharge(1_000_000)
	if c.MaxBaseUnits() != 1_000_000 {
		t.Fatalf("expected 1000000, got %d", c.MaxBaseUnits())
	}
}

// ── Gate validation tests ──

func TestGateUsageKindRejectsFees(t *testing.T) {
	gate := paykit.Gate{
		Amount:   paykit.MustParseUSD("1.00"),
		Kind:     paykit.GateUsage,
		FeeOnTop: paykit.Fees{paykit.Address("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"): paykit.MustParseUSD("0.10")},
	}
	err := gate.Validate()
	if err == nil {
		t.Fatal("expected usage gate with fees to fail")
	}
}

func TestGateUsageKindRejectsNonX402Accept(t *testing.T) {
	gate := paykit.Gate{
		Amount: paykit.MustParseUSD("1.00"),
		Kind:   paykit.GateUsage,
		Accept: []paykit.Protocol{paykit.MPP},
	}
	err := gate.Validate()
	if err == nil {
		t.Fatal("expected usage gate with MPP accept to fail")
	}
}

func TestGateUsageKindAcceptsX402Only(t *testing.T) {
	gate := paykit.Gate{
		Amount: paykit.MustParseUSD("1.00"),
		Kind:   paykit.GateUsage,
		Accept: []paykit.Protocol{paykit.X402},
	}
	if err := gate.Validate(); err != nil {
		t.Fatalf("expected usage gate with x402 to pass, got %v", err)
	}
}

func TestGateDefaultsKindToFixed(t *testing.T) {
	gate := paykit.Gate{Amount: paykit.MustParseUSD("1.00")}
	if err := gate.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if gate.Kind != paykit.GateFixed {
		t.Fatalf("kind = %q, want fixed", gate.Kind)
	}
}

// ── Open instruction validation tests ──

func TestValidateUptoOpenInstructionAcceptsWellFormed(t *testing.T) {
	payer := testutil.NewPrivateKey().PublicKey()
	payee := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	operator := testutil.NewPrivateKey().PublicKey()
	params := paymentchannels.OpenChannelParams{
		Payer: payer, RentPayer: operator, Payee: payee, Mint: mint, AuthorizedSigner: operator,
		Salt: 7, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	channel, _, err := paymentchannels.FindChannelPDA(payer, payee, mint, operator, 7)
	if err != nil {
		t.Fatalf("FindChannelPDA: %v", err)
	}
	ix, err := paymentchannels.BuildOpenInstruction(params)
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(payer))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	err = validateUptoOpenInstruction(tx, paymentchannels.ProgramPubkey(), operator, operator, payer, payee, mint, solana.TokenProgramID, channel)
	if err != nil {
		t.Fatalf("expected valid open to pass, got %v", err)
	}
}

func TestValidateUptoOpenInstructionRejectsWrongRentPayer(t *testing.T) {
	payer := testutil.NewPrivateKey().PublicKey()
	payee := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	operator := testutil.NewPrivateKey().PublicKey()
	wrongRentPayer := testutil.NewPrivateKey().PublicKey()
	params := paymentchannels.OpenChannelParams{
		Payer: payer, RentPayer: wrongRentPayer, Payee: payee, Mint: mint, AuthorizedSigner: operator,
		Salt: 7, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	channel, _, _ := paymentchannels.FindChannelPDA(payer, payee, mint, operator, 7)
	ix, err := paymentchannels.BuildOpenInstruction(params)
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(wrongRentPayer))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	err = validateUptoOpenInstruction(tx, paymentchannels.ProgramPubkey(), operator, operator, payer, payee, mint, solana.TokenProgramID, channel)
	if err == nil || !strings.Contains(err.Error(), "rent_payer mismatch") {
		t.Fatalf("expected rent_payer mismatch, got %v", err)
	}
}

func TestValidateUptoOpenInstructionRejectsForeignProgram(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	system := solana.SystemProgramID
	evil := solana.NewInstruction(system, solana.AccountMetaSlice{}, []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	tx, err := solana.NewTransaction([]solana.Instruction{evil}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(operator))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	err = validateUptoOpenInstruction(tx, paymentchannels.ProgramPubkey(), operator, operator, operator, operator, operator, solana.TokenProgramID, operator)
	if err == nil || !strings.Contains(err.Error(), "unexpected program") {
		t.Fatalf("expected foreign program rejection, got %v", err)
	}
}

func TestValidateUptoOpenInstructionRejectsExtraInstructions(t *testing.T) {
	payer := testutil.NewPrivateKey().PublicKey()
	payee := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	operator := testutil.NewPrivateKey().PublicKey()
	params := paymentchannels.OpenChannelParams{
		Payer: payer, RentPayer: operator, Payee: payee, Mint: mint, AuthorizedSigner: operator,
		Salt: 7, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	channel, _, _ := paymentchannels.FindChannelPDA(payer, payee, mint, operator, 7)
	ix, _ := paymentchannels.BuildOpenInstruction(params)
	extra := solana.NewInstruction(solana.SystemProgramID, solana.AccountMetaSlice{}, nil)
	tx, err := solana.NewTransaction([]solana.Instruction{ix, extra}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(payer))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	err = validateUptoOpenInstruction(tx, paymentchannels.ProgramPubkey(), operator, operator, payer, payee, mint, solana.TokenProgramID, channel)
	if err == nil || !strings.Contains(err.Error(), "exactly one instruction") {
		t.Fatalf("expected extra instruction rejection, got %v", err)
	}
}

func TestValidateUptoOpenInstructionRejectsWrongPayee(t *testing.T) {
	payer := testutil.NewPrivateKey().PublicKey()
	payee := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	operator := testutil.NewPrivateKey().PublicKey()
	params := paymentchannels.OpenChannelParams{
		Payer: payer, RentPayer: operator, Payee: payee, Mint: mint, AuthorizedSigner: operator,
		Salt: 7, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	channel, _, _ := paymentchannels.FindChannelPDA(payer, payee, mint, operator, 7)
	ix, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(payer))
	wrongPayee := testutil.NewPrivateKey().PublicKey()
	err := validateUptoOpenInstruction(tx, paymentchannels.ProgramPubkey(), operator, operator, payer, wrongPayee, mint, solana.TokenProgramID, channel)
	if err == nil || !strings.Contains(err.Error(), "payee mismatch") {
		t.Fatalf("expected payee mismatch, got %v", err)
	}
}

func TestValidateUptoOpenInstructionRejectsWrongTokenProgram(t *testing.T) {
	payer := testutil.NewPrivateKey().PublicKey()
	payee := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	operator := testutil.NewPrivateKey().PublicKey()
	params := paymentchannels.OpenChannelParams{
		Payer: payer, RentPayer: operator, Payee: payee, Mint: mint, AuthorizedSigner: operator,
		Salt: 7, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	channel, _, _ := paymentchannels.FindChannelPDA(payer, payee, mint, operator, 7)
	ix, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(payer))

	err := validateUptoOpenInstruction(tx, paymentchannels.ProgramPubkey(), operator, operator, payer, payee, mint, solana.Token2022ProgramID, channel)
	if err == nil || (!strings.Contains(err.Error(), "payer_token_account mismatch") && !strings.Contains(err.Error(), "token_program mismatch")) {
		t.Fatalf("expected token program binding rejection, got %v", err)
	}
}

// ── Engine VerifyOpen / SettleActual with fake RPC ──

// signerSigner wraps a solana.PrivateKey to satisfy paykit.Signer.
type signerSigner struct {
	priv solana.PrivateKey
}

func (s signerSigner) Pubkey() string { return s.priv.PublicKey().String() }
func (s signerSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	sig, err := s.priv.Sign(msg)
	if err != nil {
		return nil, err
	}
	return sig[:], nil
}
func (s signerSigner) IsDemo() bool { return false }

// uptoTestRPC wraps FakeRPC with channel-account support.
type uptoTestRPC struct {
	*testutil.FakeRPC
	channels map[string][]byte
}

func newUptoTestRPC() *uptoTestRPC {
	return &uptoTestRPC{
		FakeRPC:  testutil.NewFakeRPC(),
		channels: map[string][]byte{},
	}
}

func (r *uptoTestRPC) GetAccountInfoWithOpts(_ context.Context, account solana.PublicKey, _ *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	if data, ok := r.channels[account.String()]; ok {
		return &rpc.GetAccountInfoResult{
			Value: &rpc.Account{
				Owner: paymentchannels.ProgramPubkey(),
				Data:  rpc.DataBytesOrJSONFromBytes(data),
			},
		}, nil
	}
	return r.FakeRPC.GetAccountInfoWithOpts(context.Background(), account, nil)
}

func (r *uptoTestRPC) addChannel(channelID solana.PublicKey, channel *pcgen.Channel) {
	buf := new(bytesBuffer)
	enc := bin.NewBorshEncoder(buf)
	if err := channel.MarshalWithEncoder(enc); err != nil {
		panic(err)
	}
	r.channels[channelID.String()] = buf.Bytes()
}

type bytesBuffer struct{ data []byte }

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}
func (b *bytesBuffer) Bytes() []byte { return b.data }

func encodeChannel(channel *pcgen.Channel) []byte {
	buf := new(bytesBuffer)
	enc := bin.NewBorshEncoder(buf)
	if err := channel.MarshalWithEncoder(enc); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func TestUptoVerifyOpenAndSettle(t *testing.T) {
	// Build operator signer + payer.
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()

	// Build the channel open instruction.
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

	// Build the transaction with the open instruction.
	blockhash := solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h")
	tx, err := solana.NewTransaction([]solana.Instruction{openIx}, blockhash, solana.TransactionPayer(operatorKey.PublicKey()))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	// Sign as payer.
	if err := solanatx.SignTransaction(tx, payerSigner{payerKey}); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBase64, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("EncodeTransactionBase64: %v", err)
	}

	// Build the fake RPC with the channel account.
	fakeRPC := newUptoTestRPC()
	distHash := emptyDistributionHash()
	var distHashArr [32]byte
	copy(distHashArr[:], distHash)
	channelAccount := &pcgen.Channel{
		Discriminator:    uint8(pcgen.AccountDiscriminator_Channel),
		Version:          0,
		Bump:             0,
		Status:           uint8(pcgen.ChannelStatus_Open),
		Salt:             salt,
		Deposit:          1_000_000,
		GracePeriod:      900,
		DistributionHash: distHashArr,
		Payer:            payerKey.PublicKey(),
		Payee:            payee,
		AuthorizedSigner: operatorKey.PublicKey(),
		RentPayer:        operatorKey.PublicKey(),
		Mint:             mint,
	}
	fakeRPC.addChannel(channel, channelAccount)

	// Build the upto engine.
	uptoCfg := UptoConfig{
		Recipient:               payee.String(),
		Currency:                "USDC",
		Decimals:                6,
		Network:                 paykit.SolanaLocalnet,
		RPCURL:                  "http://localhost:8899",
		MaxTimeoutSeconds:       300,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return blockhash.String(), nil },
	}
	engine, err := NewX402Upto(uptoCfg)
	if err != nil {
		t.Fatalf("NewX402Upto: %v", err)
	}
	engine.SetRPCForTests(fakeRPC)

	// Build the payment signature header.
	envelope := UptoSignatureEnvelope{
		X402Version: X402Version,
		Scheme:      UptoScheme,
		Network:     "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Payload: UptoPayload{
			Profile:          ProfilePaymentChannel,
			From:             payerKey.PublicKey().String(),
			MaxAmount:        "1000000",
			ExpiresAt:        time.Now().Add(1 * time.Hour).Unix(),
			ValidAfter:       0,
			Nonce:            "n-1",
			ChannelID:        channel.String(),
			Deposit:          "1000000",
			AuthorizedSigner: operatorKey.PublicKey().String(),
			OpenTransaction:  txBase64,
		},
	}
	raw, _ := json.Marshal(envelope)
	header := base64.StdEncoding.EncodeToString(raw)

	// VerifyOpen.
	verified, err := engine.VerifyOpen(context.Background(), header, "1.00")
	if err != nil {
		t.Fatalf("VerifyOpen: %v", err)
	}
	if !verified.ChannelID.Equals(channel) {
		t.Fatalf("channelID = %s, want %s", verified.ChannelID, channel)
	}
	if verified.MaxAmount != 1_000_000 {
		t.Fatalf("maxAmount = %d, want 1000000", verified.MaxAmount)
	}

	// SettleActual.
	settlement, err := engine.SettleActual(context.Background(), verified, 500_000)
	if err != nil {
		t.Fatalf("SettleActual: %v", err)
	}
	if !settlement.Success {
		t.Fatal("expected settlement success")
	}
	if settlement.Amount != "500000" {
		t.Fatalf("amount = %q, want 500000", settlement.Amount)
	}
	if settlement.Transaction == "" {
		t.Fatal("transaction is empty")
	}
	if len(fakeRPC.Sent) != 2 {
		t.Fatalf("sent transactions = %d, want 2 (open + settlement)", len(fakeRPC.Sent))
	}
	settlementTx := fakeRPC.Sent[1]
	if len(settlementTx.Message.Instructions) != 5 {
		t.Fatalf("settlement instructions = %d, want 5", len(settlementTx.Message.Instructions))
	}
	if got := settlementTx.Message.Instructions[1].Data[0]; got != 4 {
		t.Fatalf("settlement instruction discriminator = %d, want settle_and_finalize(4)", got)
	}
	if got := settlementTx.Message.Instructions[1].Data[1]; got != 1 {
		t.Fatalf("settle_and_finalize hasVoucher = %d, want 1", got)
	}
	for _, idx := range []int{2, 3} {
		if program := settlementTx.Message.AccountKeys[settlementTx.Message.Instructions[idx].ProgramIDIndex]; !program.Equals(solana.SPLAssociatedTokenAccountProgramID) {
			t.Fatalf("instruction %d program = %s, want ATA program", idx, program)
		}
		if got := settlementTx.Message.Instructions[idx].Data[0]; got != 1 {
			t.Fatalf("instruction %d discriminator = %d, want create idempotent ATA(1)", idx, got)
		}
	}
	if got := settlementTx.Message.Instructions[4].Data[0]; got != 7 {
		t.Fatalf("distribute instruction discriminator = %d, want distribute(7)", got)
	}
}

func TestUptoVerifyOpenRejectsClientFeePayer(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	openIx, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(payerKey.PublicKey()))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	if err := solanatx.SignTransaction(tx, payerSigner{payerKey}); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)
	fakeRPC := newUptoTestRPC()
	engine, _ := NewX402Upto(UptoConfig{
		Recipient: payee.String(), Currency: "USDC", Decimals: 6, Network: paykit.SolanaLocalnet,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	engine.SetRPCForTests(fakeRPC)
	envelope := UptoSignatureEnvelope{
		X402Version: X402Version,
		Scheme:      UptoScheme,
		Network:     "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Payload: UptoPayload{
			Profile:          ProfilePaymentChannel,
			From:             payerKey.PublicKey().String(),
			MaxAmount:        "1000000",
			ExpiresAt:        time.Now().Add(time.Hour).Unix(),
			ChannelID:        channel.String(),
			Deposit:          "1000000",
			AuthorizedSigner: operatorKey.PublicKey().String(),
			OpenTransaction:  txBase64,
		},
	}
	raw, _ := json.Marshal(envelope)
	_, err = engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "fee payer must be the advertised operator") {
		t.Fatalf("expected fee payer rejection, got %v", err)
	}
	if len(fakeRPC.Sent) != 0 {
		t.Fatalf("broadcasted rejected open transaction: %d sends", len(fakeRPC.Sent))
	}
}

func TestUptoVerifyOpenRejectsInFlightReplay(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(operatorKey.PublicKey()))
	solanatx.SignTransaction(tx, payerSigner{payerKey})
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)

	fakeRPC := newUptoTestRPC()
	distHash := emptyDistributionHash()
	var distHashArr2 [32]byte
	copy(distHashArr2[:], distHash)
	fakeRPC.addChannel(channel, &pcgen.Channel{
		Discriminator: uint8(pcgen.AccountDiscriminator_Channel), Status: uint8(pcgen.ChannelStatus_Open),
		Salt: salt, Deposit: 1_000_000, DistributionHash: distHashArr2,
		Payer: payerKey.PublicKey(), Payee: payee,
		AuthorizedSigner: operatorKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Mint: mint,
	})

	engine, _ := NewX402Upto(UptoConfig{
		Recipient: payee.String(), Currency: "USDC", Decimals: 6, Network: paykit.SolanaLocalnet,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	engine.SetRPCForTests(fakeRPC)

	envelope := UptoSignatureEnvelope{
		X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Payload: UptoPayload{
			Profile: ProfilePaymentChannel, From: payerKey.PublicKey().String(),
			MaxAmount: "1000000", ExpiresAt: time.Now().Add(time.Hour).Unix(),
			ChannelID: channel.String(), Deposit: "1000000",
			AuthorizedSigner: operatorKey.PublicKey().String(), OpenTransaction: txBase64,
		},
	}
	raw, _ := json.Marshal(envelope)
	header := base64.StdEncoding.EncodeToString(raw)

	// First open succeeds.
	verified, err := engine.VerifyOpen(context.Background(), header, "1.00")
	if err != nil {
		t.Fatalf("first VerifyOpen: %v", err)
	}
	// In-flight: the guard hasn't been released (verified is still alive).
	// A concurrent open for the same channel must be rejected.
	_, err = engine.VerifyOpen(context.Background(), header, "1.00")
	if err == nil || !strings.Contains(err.Error(), "already being processed") {
		t.Fatalf("expected in-flight rejection, got %v", err)
	}
	// Release the guard by settling.
	_, _ = engine.SettleActual(context.Background(), verified, 1)
}

func TestUptoVerifiedOpenReleaseClearsInFlightGuard(t *testing.T) {
	engine := &X402Upto{inFlight: map[string]struct{}{}}
	channelID := testutil.NewPrivateKey().PublicKey()
	key := channelID.String()
	engine.inFlight[key] = struct{}{}
	verified := &UptoVerifiedOpen{
		ChannelID: channelID,
		guard:     &uptoInFlightGuard{engine: engine, key: key},
	}

	verified.Release()
	if _, ok := engine.inFlight[key]; ok {
		t.Fatal("Release did not clear in-flight channel guard")
	}
	verified.Release()
	if len(engine.inFlight) != 0 {
		t.Fatalf("Release should be idempotent, in-flight entries = %d", len(engine.inFlight))
	}
}

// ── Error path tests for coverage ──

func TestNewX402UptoRejectsEmptyRecipient(t *testing.T) {
	signer := testutil.NewPrivateKey()
	_, err := NewX402Upto(UptoConfig{Recipient: "", OperatorSigner: signerSigner{signer}, Network: paykit.SolanaLocalnet})
	if err == nil || !strings.Contains(err.Error(), "recipient is required") {
		t.Fatalf("expected recipient required, got %v", err)
	}
}

func TestNewX402UptoRejectsInvalidRecipient(t *testing.T) {
	signer := testutil.NewPrivateKey()
	_, err := NewX402Upto(UptoConfig{Recipient: "not-a-pubkey", OperatorSigner: signerSigner{signer}, Network: paykit.SolanaLocalnet})
	if err == nil || !strings.Contains(err.Error(), "invalid recipient pubkey") {
		t.Fatalf("expected invalid recipient pubkey, got %v", err)
	}
}

func TestNewX402UptoAcceptsRecipientDifferentFromOperator(t *testing.T) {
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	engine, err := NewX402Upto(UptoConfig{
		Recipient:      recipient.String(),
		OperatorSigner: signerSigner{signer},
		Network:        paykit.SolanaLocalnet,
	})
	if err != nil {
		t.Fatalf("NewX402Upto with distinct recipient: %v", err)
	}
	req, err := engine.UptoRequirements("1.00")
	if err != nil {
		t.Fatalf("UptoRequirements: %v", err)
	}
	if req.PayTo != recipient.String() {
		t.Fatalf("payTo = %s, want %s", req.PayTo, recipient)
	}
	if req.Extra.FeePayer != signer.PublicKey().String() {
		t.Fatalf("feePayer = %s, want %s", req.Extra.FeePayer, signer.PublicKey())
	}
}

func TestNewX402UptoRejectsNilSigner(t *testing.T) {
	_, err := NewX402Upto(UptoConfig{Recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", Network: paykit.SolanaLocalnet})
	if err == nil || !strings.Contains(err.Error(), "operator signer is required") {
		t.Fatalf("expected operator signer required, got %v", err)
	}
}

func TestUptoRequirementsRejectsNativeSOL(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine, err := NewX402Upto(UptoConfig{
		Recipient: signer.PublicKey().String(), Currency: "SOL",
		OperatorSigner: signerSigner{signer}, Network: paykit.SolanaLocalnet,
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	if err != nil {
		t.Fatalf("NewX402Upto: %v", err)
	}
	_, err = engine.UptoRequirements("1.00")
	if err == nil || !strings.Contains(err.Error(), "SPL token") {
		t.Fatalf("expected SOL rejection, got %v", err)
	}
}

func TestUptoRejectsBadAmount(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	_, err := engine.UptoRequirements("not-a-number")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestUptoPaymentRequiredHeaderRejectsBadAmount(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	_, _, err := engine.PaymentRequiredHeader("not-a-number")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUptoResourceIncludedWhenSet(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine, _ := NewX402Upto(UptoConfig{
		Recipient: signer.PublicKey().String(), Currency: "USDC", Decimals: 6,
		Network: paykit.SolanaLocalnet, Resource: "/usage",
		OperatorSigner:          signerSigner{signer},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	env, err := engine.Upto("0.10")
	if err != nil {
		t.Fatalf("Upto: %v", err)
	}
	if env.Resource == nil || env.Resource.URL != "/usage" {
		t.Fatalf("resource = %+v, want URL=/usage", env.Resource)
	}
}

func TestSettleActualRejectsNilOpen(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	_, err := engine.SettleActual(context.Background(), nil, 100)
	if err == nil || !strings.Contains(err.Error(), "verified open is required") {
		t.Fatalf("expected nil open rejection, got %v", err)
	}
}

func TestSettleActualRejectsOverCeiling(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	open := &UptoVerifiedOpen{MaxAmount: 100}
	_, err := engine.SettleActual(context.Background(), open, 200)
	if err == nil || !strings.Contains(err.Error(), UptoErrorSettlementExceedsAmount) {
		t.Fatalf("expected over-ceiling, got %v", err)
	}
}

func TestVerifyOpenRejectsInvalidBase64(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	_, err := engine.VerifyOpen(context.Background(), "!!!not-base64!!!", "1.00")
	if err == nil {
		t.Fatal("expected base64 error")
	}
}

func TestVerifyOpenRejectsInvalidJSON(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	encoded := base64.StdEncoding.EncodeToString([]byte("not-json"))
	_, err := engine.VerifyOpen(context.Background(), encoded, "1.00")
	if err == nil {
		t.Fatal("expected JSON error")
	}
}

func TestVerifyOpenRejectsWrongScheme(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: "exact", Payload: uptoPayload()}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "invalid payload type") {
		t.Fatalf("expected wrong scheme, got %v", err)
	}
}

func TestVerifyOpenRejectsMissingOpenTransaction(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	payload := uptoPayload()
	payload.OpenTransaction = ""
	payload.AuthorizedSigner = engine.Operator()
	payload.ChannelID = signer.PublicKey().String()
	payload.From = signer.PublicKey().String()
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Payload: payload}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "requires openTransaction") {
		t.Fatalf("expected missing openTransaction, got %v", err)
	}
}

func TestVerifyOpenRejectsInvalidOpenTransactionBase64(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	payload := uptoPayload()
	payload.OpenTransaction = "!!!not-base64!!!"
	payload.ChannelID = signer.PublicKey().String()
	payload.From = signer.PublicKey().String()
	payload.AuthorizedSigner = engine.Operator()
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Payload: payload}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "invalid transaction") {
		t.Fatalf("expected invalid transaction, got %v", err)
	}
}

func TestUptoAcceptedValue(t *testing.T) {
	req := uptoRequirements()
	raw, err := req.AcceptedValue()
	if err != nil {
		t.Fatalf("AcceptedValue: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty accepted value")
	}
}

func TestUptoPayloadParseErrors(t *testing.T) {
	p := UptoPayload{MaxAmount: "abc"}
	if _, err := p.ParsedMaxAmount(); err == nil {
		t.Fatal("expected maxAmount parse error")
	}
	p = UptoPayload{Deposit: "xyz"}
	if _, err := p.ParsedDeposit(); err == nil {
		t.Fatal("expected deposit parse error")
	}
}

func TestUptoRequirementsMaxAmountError(t *testing.T) {
	r := UptoRequirements{Amount: "abc"}
	if _, err := r.MaxAmount(); err == nil {
		t.Fatal("expected amount parse error")
	}
}

func TestValidateUptoOpenInstructionRejectsNonOpenDiscriminator(t *testing.T) {
	payer := testutil.NewPrivateKey().PublicKey()
	evil := solana.NewInstruction(paymentchannels.ProgramPubkey(), solana.AccountMetaSlice{}, []byte{99})
	tx, _ := solana.NewTransaction([]solana.Instruction{evil}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(payer))
	err := validateUptoOpenInstruction(tx, paymentchannels.ProgramPubkey(), payer, payer, payer, payer, payer, solana.TokenProgramID, payer)
	if err == nil || !strings.Contains(err.Error(), "not a channel-open") {
		t.Fatalf("expected non-open discriminator rejection, got %v", err)
	}
}

func TestSignPaykitTransactionRejectsWrongSigner(t *testing.T) {
	signer := testutil.NewPrivateKey()
	// Build a transaction with a different fee payer so the signer is not
	// in the signer list.
	otherKey := testutil.NewPrivateKey().PublicKey()
	evil := solana.NewInstruction(solana.SystemProgramID, solana.AccountMetaSlice{}, []byte{0})
	tx, err := solana.NewTransaction([]solana.Instruction{evil}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(otherKey))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	err = signPaykitTransaction(context.Background(), tx, signerSigner{signer})
	if err == nil || !strings.Contains(err.Error(), "not required by transaction") {
		t.Fatalf("expected not-required error, got %v", err)
	}
}

// ── Helpers ──

func newUptoEngineWithSigner(t *testing.T, signer solana.PrivateKey) *X402Upto {
	t.Helper()
	engine, err := NewX402Upto(UptoConfig{
		Recipient: signer.PublicKey().String(), Currency: "USDC", Decimals: 6,
		Network: paykit.SolanaLocalnet, RPCURL: "http://localhost:8899",
		OperatorSigner:          signerSigner{signer},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	if err != nil {
		t.Fatalf("NewX402Upto: %v", err)
	}
	return engine
}

// ── Original helpers ──

// TestUptoVerifyOpenRejectsChannelNotOpen exercises the channel-status check.
func TestUptoVerifyOpenRejectsChannelNotOpen(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(operatorKey.PublicKey()))
	solanatx.SignTransaction(tx, payerSigner{payerKey})
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)
	distHash := emptyDistributionHash()
	var distHashArr [32]byte
	copy(distHashArr[:], distHash)
	fakeRPC := newUptoTestRPC()
	fakeRPC.addChannel(channel, &pcgen.Channel{
		Discriminator: uint8(pcgen.AccountDiscriminator_Channel), Status: uint8(pcgen.ChannelStatus_Finalized),
		Salt: salt, Deposit: 1_000_000, DistributionHash: distHashArr,
		Payer: payerKey.PublicKey(), Payee: payee, AuthorizedSigner: operatorKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Mint: mint,
	})
	engine, _ := NewX402Upto(UptoConfig{
		Recipient: payee.String(), Currency: "USDC", Decimals: 6, Network: paykit.SolanaLocalnet,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	engine.SetRPCForTests(fakeRPC)
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Payload: UptoPayload{
		Profile: ProfilePaymentChannel, From: payerKey.PublicKey().String(), MaxAmount: "1000000",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), ChannelID: channel.String(), Deposit: "1000000",
		AuthorizedSigner: operatorKey.PublicKey().String(), OpenTransaction: txBase64,
	}}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "not open after broadcast") {
		t.Fatalf("expected channel not open, got %v", err)
	}
}

// TestUptoVerifyOpenRejectsMintMismatch exercises the on-chain mint binding.
func TestUptoVerifyOpenRejectsMintMismatch(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	wrongMint := testutil.NewPrivateKey().PublicKey()
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(operatorKey.PublicKey()))
	solanatx.SignTransaction(tx, payerSigner{payerKey})
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)
	distHash := emptyDistributionHash()
	var distHashArr [32]byte
	copy(distHashArr[:], distHash)
	fakeRPC := newUptoTestRPC()
	fakeRPC.addChannel(channel, &pcgen.Channel{
		Discriminator: uint8(pcgen.AccountDiscriminator_Channel), Status: uint8(pcgen.ChannelStatus_Open),
		Salt: salt, Deposit: 1_000_000, DistributionHash: distHashArr,
		Payer: payerKey.PublicKey(), Payee: payee, AuthorizedSigner: operatorKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Mint: wrongMint,
	})
	engine, _ := NewX402Upto(UptoConfig{
		Recipient: payee.String(), Currency: "USDC", Decimals: 6, Network: paykit.SolanaLocalnet,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	engine.SetRPCForTests(fakeRPC)
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Payload: UptoPayload{
		Profile: ProfilePaymentChannel, From: payerKey.PublicKey().String(), MaxAmount: "1000000",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), ChannelID: channel.String(), Deposit: "1000000",
		AuthorizedSigner: operatorKey.PublicKey().String(), OpenTransaction: txBase64,
	}}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "mint mismatch") {
		t.Fatalf("expected mint mismatch, got %v", err)
	}
}

// TestUptoVerifyOpenRejectsWrongPayer exercises the on-chain payer binding.
func TestUptoVerifyOpenRejectsWrongPayer(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(operatorKey.PublicKey()))
	solanatx.SignTransaction(tx, payerSigner{payerKey})
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)
	distHash := emptyDistributionHash()
	var distHashArr [32]byte
	copy(distHashArr[:], distHash)
	fakeRPC := newUptoTestRPC()
	fakeRPC.addChannel(channel, &pcgen.Channel{
		Discriminator: uint8(pcgen.AccountDiscriminator_Channel), Status: uint8(pcgen.ChannelStatus_Open),
		Salt: salt, Deposit: 1_000_000, DistributionHash: distHashArr,
		Payer: testutil.NewPrivateKey().PublicKey(), Payee: payee, AuthorizedSigner: operatorKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Mint: mint,
	})
	engine, _ := NewX402Upto(UptoConfig{
		Recipient: payee.String(), Currency: "USDC", Decimals: 6, Network: paykit.SolanaLocalnet,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	engine.SetRPCForTests(fakeRPC)
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Payload: UptoPayload{
		Profile: ProfilePaymentChannel, From: payerKey.PublicKey().String(), MaxAmount: "1000000",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), ChannelID: channel.String(), Deposit: "1000000",
		AuthorizedSigner: operatorKey.PublicKey().String(), OpenTransaction: txBase64,
	}}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "does not match payload.from") {
		t.Fatalf("expected payer mismatch, got %v", err)
	}
}

// TestUptoVerifyOpenRejectsWrongRentPayer exercises the on-chain rent-payer binding.
func TestUptoVerifyOpenRejectsWrongRentPayer(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(operatorKey.PublicKey()))
	solanatx.SignTransaction(tx, payerSigner{payerKey})
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)
	distHash := emptyDistributionHash()
	var distHashArr [32]byte
	copy(distHashArr[:], distHash)
	fakeRPC := newUptoTestRPC()
	fakeRPC.addChannel(channel, &pcgen.Channel{
		Discriminator: uint8(pcgen.AccountDiscriminator_Channel), Status: uint8(pcgen.ChannelStatus_Open),
		Salt: salt, Deposit: 1_000_000, DistributionHash: distHashArr,
		Payer: payerKey.PublicKey(), Payee: payee, AuthorizedSigner: operatorKey.PublicKey(), RentPayer: testutil.NewPrivateKey().PublicKey(), Mint: mint,
	})
	engine, _ := NewX402Upto(UptoConfig{
		Recipient: payee.String(), Currency: "USDC", Decimals: 6, Network: paykit.SolanaLocalnet,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	engine.SetRPCForTests(fakeRPC)
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Payload: UptoPayload{
		Profile: ProfilePaymentChannel, From: payerKey.PublicKey().String(), MaxAmount: "1000000",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), ChannelID: channel.String(), Deposit: "1000000",
		AuthorizedSigner: operatorKey.PublicKey().String(), OpenTransaction: txBase64,
	}}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "rent_payer is not the operator") {
		t.Fatalf("expected rent_payer mismatch, got %v", err)
	}
}

// TestUptoVerifyOpenRejectsDepositBelowMax exercises the on-chain deposit binding.
func TestUptoVerifyOpenRejectsDepositMismatch(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(operatorKey.PublicKey()))
	solanatx.SignTransaction(tx, payerSigner{payerKey})
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)
	distHash := emptyDistributionHash()
	var distHashArr [32]byte
	copy(distHashArr[:], distHash)
	fakeRPC := newUptoTestRPC()
	fakeRPC.addChannel(channel, &pcgen.Channel{
		Discriminator: uint8(pcgen.AccountDiscriminator_Channel), Status: uint8(pcgen.ChannelStatus_Open),
		Salt: salt, Deposit: 500_000, DistributionHash: distHashArr,
		Payer: payerKey.PublicKey(), Payee: payee, AuthorizedSigner: operatorKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Mint: mint,
	})
	engine, _ := NewX402Upto(UptoConfig{
		Recipient: payee.String(), Currency: "USDC", Decimals: 6, Network: paykit.SolanaLocalnet,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	engine.SetRPCForTests(fakeRPC)
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Payload: UptoPayload{
		Profile: ProfilePaymentChannel, From: payerKey.PublicKey().String(), MaxAmount: "1000000",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), ChannelID: channel.String(), Deposit: "1000000",
		AuthorizedSigner: operatorKey.PublicKey().String(), OpenTransaction: txBase64,
	}}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "must equal authorized maximum") {
		t.Fatalf("expected deposit mismatch, got %v", err)
	}
}

// TestUptoFetchChannelRejectsMissingAccount exercises the fetchChannel error path.
func TestUptoFetchChannelRejectsMissingAccount(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(operatorKey.PublicKey()))
	solanatx.SignTransaction(tx, payerSigner{payerKey})
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)
	fakeRPC := newUptoTestRPC() // no channel account added
	engine, _ := NewX402Upto(UptoConfig{
		Recipient: payee.String(), Currency: "USDC", Decimals: 6, Network: paykit.SolanaLocalnet,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	engine.SetRPCForTests(fakeRPC)
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Payload: UptoPayload{
		Profile: ProfilePaymentChannel, From: payerKey.PublicKey().String(), MaxAmount: "1000000",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), ChannelID: channel.String(), Deposit: "1000000",
		AuthorizedSigner: operatorKey.PublicKey().String(), OpenTransaction: txBase64,
	}}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil || !strings.Contains(err.Error(), "channel account fetch") {
		t.Fatalf("expected channel fetch error, got %v", err)
	}
}

func TestUptoSettleActualAllowsZeroAmount(t *testing.T) {
	operatorKey := testutil.NewPrivateKey()
	payerKey := testutil.NewPrivateKey()
	payee := operatorKey.PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	salt := uint64(7)
	channel, _, _ := paymentchannels.FindChannelPDA(payerKey.PublicKey(), payee, mint, operatorKey.PublicKey(), salt)
	params := paymentchannels.OpenChannelParams{
		Payer: payerKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Payee: payee, Mint: mint, AuthorizedSigner: operatorKey.PublicKey(),
		Salt: salt, Deposit: 1_000_000, GracePeriod: 900,
		TokenProgram: solana.TokenProgramID, ProgramID: paymentchannels.ProgramPubkey(),
	}
	openIx, _ := paymentchannels.BuildOpenInstruction(params)
	tx, _ := solana.NewTransaction([]solana.Instruction{openIx}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(operatorKey.PublicKey()))
	solanatx.SignTransaction(tx, payerSigner{payerKey})
	txBase64, _ := solanatx.EncodeTransactionBase64(tx)
	distHash := emptyDistributionHash()
	var distHashArr [32]byte
	copy(distHashArr[:], distHash)
	fakeRPC := newUptoTestRPC()
	fakeRPC.addChannel(channel, &pcgen.Channel{
		Discriminator: uint8(pcgen.AccountDiscriminator_Channel), Status: uint8(pcgen.ChannelStatus_Open),
		Salt: salt, Deposit: 1_000_000, DistributionHash: distHashArr,
		Payer: payerKey.PublicKey(), Payee: payee, AuthorizedSigner: operatorKey.PublicKey(), RentPayer: operatorKey.PublicKey(), Mint: mint,
	})
	engine, _ := NewX402Upto(UptoConfig{
		Recipient: payee.String(), Currency: "USDC", Decimals: 6, Network: paykit.SolanaLocalnet,
		OperatorSigner:          signerSigner{operatorKey},
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	})
	engine.SetRPCForTests(fakeRPC)
	env := UptoSignatureEnvelope{X402Version: X402Version, Scheme: UptoScheme, Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Payload: UptoPayload{
		Profile: ProfilePaymentChannel, From: payerKey.PublicKey().String(), MaxAmount: "1000000",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), ChannelID: channel.String(), Deposit: "1000000",
		AuthorizedSigner: operatorKey.PublicKey().String(), OpenTransaction: txBase64,
	}}
	raw, _ := json.Marshal(env)
	verified, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err != nil {
		t.Fatalf("VerifyOpen: %v", err)
	}
	settlement, err := engine.SettleActual(context.Background(), verified, 0)
	if err != nil {
		t.Fatalf("SettleActual zero amount: %v", err)
	}
	if settlement.Amount != "0" {
		t.Fatalf("amount = %q, want 0", settlement.Amount)
	}
	if settlement.Transaction == "" {
		t.Fatal("transaction is empty")
	}
	if len(fakeRPC.Sent) != 2 {
		t.Fatalf("sent transactions = %d, want 2 (open + settlement)", len(fakeRPC.Sent))
	}
	settlementTx := fakeRPC.Sent[1]
	if len(settlementTx.Message.Instructions) != 4 {
		t.Fatalf("zero settlement instructions = %d, want 4", len(settlementTx.Message.Instructions))
	}
	if got := settlementTx.Message.Instructions[0].Data[0]; got != 4 {
		t.Fatalf("zero settlement discriminator = %d, want settle_and_finalize(4)", got)
	}
	if got := settlementTx.Message.Instructions[0].Data[1]; got != 0 {
		t.Fatalf("zero settlement hasVoucher = %d, want 0", got)
	}
	for _, idx := range []int{1, 2} {
		if program := settlementTx.Message.AccountKeys[settlementTx.Message.Instructions[idx].ProgramIDIndex]; !program.Equals(solana.SPLAssociatedTokenAccountProgramID) {
			t.Fatalf("instruction %d program = %s, want ATA program", idx, program)
		}
		if got := settlementTx.Message.Instructions[idx].Data[0]; got != 1 {
			t.Fatalf("instruction %d discriminator = %d, want create idempotent ATA(1)", idx, got)
		}
	}
	if got := settlementTx.Message.Instructions[3].Data[0]; got != 7 {
		t.Fatalf("zero settlement distribute discriminator = %d, want distribute(7)", got)
	}
}

type payerSigner struct{ priv solana.PrivateKey }

func (s payerSigner) PublicKey() solana.PublicKey { return s.priv.PublicKey() }
func (s payerSigner) Sign(msg []byte) (solana.Signature, error) {
	return s.priv.Sign(msg)
}
