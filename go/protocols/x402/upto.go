package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

const (
	uptoScheme                       = "upto"
	profilePaymentChannel            = "payment-channel"
	uptoErrorSettlementExceedsAmount = "invalid_upto_svm_payload_settlement_exceeds_amount"
)

// UptoExtra is the extra object on an x402 upto payment requirement.
type UptoExtra struct {
	Profiles        []string `json:"profiles,omitempty"`
	Decimals        *uint8   `json:"decimals,omitempty"`
	TokenProgram    string   `json:"tokenProgram,omitempty"`
	Facilitator     string   `json:"facilitator"`
	ProgramID       string   `json:"programId,omitempty"`
	RecentBlockhash string   `json:"recentBlockhash,omitempty"`
	ValidAfter      *int64   `json:"validAfter,omitempty"`
}

// UptoRequirements is the accepted object for the x402 upto scheme.
type UptoRequirements struct {
	Scheme            string    `json:"scheme"`
	Network           string    `json:"network"`
	Amount            string    `json:"amount"`
	Asset             string    `json:"asset"`
	PayTo             string    `json:"payTo"`
	MaxTimeoutSeconds uint64    `json:"maxTimeoutSeconds"`
	Extra             UptoExtra `json:"extra"`
}

// MaxAmount parses the authorized maximum in token base units.
func (r UptoRequirements) MaxAmount() (uint64, error) {
	max, err := strconv.ParseUint(r.Amount, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid upto amount %q: %w", r.Amount, err)
	}
	return max, nil
}

// AcceptedValue returns the canonical accepted-object JSON value.
func (r UptoRequirements) AcceptedValue() (json.RawMessage, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("upto requirement serialization failed: %w", err)
	}
	return raw, nil
}

// UptoRequiredEnvelope is the payment-required challenge for x402 upto.
type UptoRequiredEnvelope struct {
	X402Version int                `json:"x402Version"`
	Resource    *ResourceRef       `json:"resource,omitempty"`
	Accepts     []UptoRequirements `json:"accepts"`
	Error       string             `json:"error,omitempty"`
}

// UptoPayload is the client authorization carried in PAYMENT-SIGNATURE.payload.
type UptoPayload struct {
	Profile          string `json:"profile"`
	From             string `json:"from"`
	MaxAmount        string `json:"maxAmount"`
	ExpiresAt        int64  `json:"expiresAt"`
	ValidAfter       int64  `json:"validAfter"`
	Nonce            string `json:"nonce"`
	ChannelID        string `json:"channelId"`
	Deposit          string `json:"deposit"`
	AuthorizedSigner string `json:"authorizedSigner"`
	OpenTransaction  string `json:"openTransaction,omitempty"`
	Signature        string `json:"signature,omitempty"`
}

// ParsedMaxAmount parses maxAmount in token base units.
func (p UptoPayload) ParsedMaxAmount() (uint64, error) {
	max, err := strconv.ParseUint(p.MaxAmount, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid upto maxAmount %q: %w", p.MaxAmount, err)
	}
	return max, nil
}

// ParsedDeposit parses deposit in token base units.
func (p UptoPayload) ParsedDeposit() (uint64, error) {
	deposit, err := strconv.ParseUint(p.Deposit, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid upto deposit %q: %w", p.Deposit, err)
	}
	return deposit, nil
}

// UptoSignatureEnvelope is the PAYMENT-SIGNATURE envelope for x402 upto.
type UptoSignatureEnvelope struct {
	X402Version int             `json:"x402Version"`
	Scheme      string          `json:"scheme"`
	Network     string          `json:"network,omitempty"`
	Accepted    json.RawMessage `json:"accepted,omitempty"`
	Payload     UptoPayload     `json:"payload"`
}

// UptoSettlementResponse is the PAYMENT-RESPONSE settlement result.
type UptoSettlementResponse struct {
	Success     bool   `json:"success"`
	ErrorReason string `json:"errorReason,omitempty"`
	Payer       string `json:"payer,omitempty"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
	Amount      string `json:"amount"`
}

// VerifyUptoPayload validates the payload against the route-pinned requirement.
func VerifyUptoPayload(payload UptoPayload, requirements UptoRequirements, operator string, now int64) error {
	if payload.Profile != profilePaymentChannel {
		return fmt.Errorf("invalid payload type: %s", payload.Profile)
	}
	advertised := false
	for _, profile := range requirements.Extra.Profiles {
		if profile == payload.Profile {
			advertised = true
			break
		}
	}
	if !advertised {
		return fmt.Errorf("profile %s not advertised by the server", payload.Profile)
	}
	max, err := requirements.MaxAmount()
	if err != nil {
		return err
	}
	signedMax, err := payload.ParsedMaxAmount()
	if err != nil {
		return err
	}
	if signedMax != max {
		return fmt.Errorf("amount mismatch: expected %d, got %d", max, signedMax)
	}
	deposit, err := payload.ParsedDeposit()
	if err != nil {
		return err
	}
	if deposit < max {
		return fmt.Errorf("channel deposit %d is below the authorized maximum %d", deposit, max)
	}
	if now < payload.ValidAfter {
		return fmt.Errorf("authorization not yet active (validAfter %d > now %d)", payload.ValidAfter, now)
	}
	if now > payload.ExpiresAt {
		return fmt.Errorf("authorization expired (expiresAt %d < now %d)", payload.ExpiresAt, now)
	}
	if payload.AuthorizedSigner != operator {
		return errors.New("voucher authorized_signer must be the operator for the payment-channel profile")
	}
	return nil
}

// AssertSettlementWithinCeiling enforces actual <= max at settlement.
func AssertSettlementWithinCeiling(actual, max uint64) error {
	if actual > max {
		return errors.New(uptoErrorSettlementExceedsAmount)
	}
	return nil
}

// UptoVerifiedOpen is a confirmed channel open carried into settlement.
type UptoVerifiedOpen struct {
	ChannelID    solana.PublicKey
	Payer        solana.PublicKey
	Mint         solana.PublicKey
	TokenProgram solana.PublicKey
	ProgramID    solana.PublicKey
	Deposit      uint64
	MaxAmount    uint64
	ExpiresAt    int64
	Network      string
	guard        *uptoInFlightGuard
}

// UptoConfig configures the x402 upto server engine.
type UptoConfig struct {
	Recipient               string
	Currency                string
	Decimals                uint8
	Network                 paykit.Network
	RPCURL                  string
	Resource                string
	Description             string
	MaxTimeoutSeconds       uint64
	TokenProgram            string
	ProgramID               string
	OperatorSigner          paykit.Signer
	RecentBlockhashProvider func() (string, error)
}

// X402Upto is the server-side x402 upto payment-channel engine.
type X402Upto struct {
	cfg      UptoConfig
	rpc      solanatx.RPCClient
	operator solana.PublicKey
	inFlight map[string]struct{}
	mu       sync.Mutex
}

type uptoInFlightGuard struct {
	engine *X402Upto
	key    string
}

func (g *uptoInFlightGuard) release() {
	if g == nil || g.engine == nil {
		return
	}
	g.engine.mu.Lock()
	delete(g.engine.inFlight, g.key)
	g.engine.mu.Unlock()
	g.engine = nil
}

// NewX402Upto creates an x402 upto server engine.
func NewX402Upto(cfg UptoConfig) (*X402Upto, error) {
	if cfg.Recipient == "" {
		return nil, errors.New("recipient is required")
	}
	if cfg.Currency == "" {
		cfg.Currency = "USDC"
	}
	if cfg.Decimals == 0 {
		cfg.Decimals = stablecoinDecimals
	}
	if cfg.MaxTimeoutSeconds == 0 {
		cfg.MaxTimeoutSeconds = defaultMaxTimeoutSeconds
	}
	if cfg.OperatorSigner == nil {
		return nil, errors.New("operator signer is required")
	}
	operator, err := solana.PublicKeyFromBase58(string(cfg.OperatorSigner.Pubkey()))
	if err != nil {
		return nil, fmt.Errorf("operator pubkey: %w", err)
	}
	if _, err := solana.PublicKeyFromBase58(cfg.Recipient); err != nil {
		return nil, fmt.Errorf("invalid recipient pubkey: %w", err)
	}
	rpcURL := cfg.RPCURL
	if rpcURL == "" {
		rpcURL = cfg.Network.DefaultRPCURL()
	}
	return &X402Upto{cfg: cfg, rpc: rpc.New(rpcURL), operator: operator, inFlight: map[string]struct{}{}}, nil
}

// SetRPCForTests replaces the RPC client for deterministic tests.
func (u *X402Upto) SetRPCForTests(rpcClient solanatx.RPCClient) {
	u.rpc = rpcClient
}

// Operator returns the operator/facilitator public key.
func (u *X402Upto) Operator() string { return u.operator.String() }

// UptoRequirements builds the route-pinned upto requirement for maxAmount.
func (u *X402Upto) UptoRequirements(maxAmount string) (UptoRequirements, error) {
	coin := u.cfg.Currency
	label := u.cfg.Network.MintsLabel()
	mint := paycore.ResolveMint(coin, label)
	if mint == "" {
		return UptoRequirements{}, errors.New("upto requires an SPL token (not native SOL)")
	}
	baseUnits, err := parseDecimalUnits(maxAmount, u.cfg.Decimals)
	if err != nil {
		return UptoRequirements{}, err
	}
	programID := u.cfg.ProgramID
	if programID == "" {
		programID = paymentchannels.ProgramID
	}
	tokenProgram := u.cfg.TokenProgram
	if tokenProgram == "" {
		tokenProgram = paycore.DefaultTokenProgramForCurrency(coin, label)
	}
	decimals := u.cfg.Decimals
	return UptoRequirements{
		Scheme:            uptoScheme,
		Network:           u.cfg.Network.CAIP2(),
		Amount:            baseUnits,
		Asset:             mint,
		PayTo:             u.cfg.Recipient,
		MaxTimeoutSeconds: u.cfg.MaxTimeoutSeconds,
		Extra: UptoExtra{
			Profiles:     []string{profilePaymentChannel},
			Decimals:     &decimals,
			TokenProgram: tokenProgram,
			Facilitator:  u.Operator(),
			ProgramID:    programID,
		},
	}, nil
}

// Upto builds the full payment-required envelope for an upto challenge.
func (u *X402Upto) Upto(maxAmount string) (UptoRequiredEnvelope, error) {
	req, err := u.UptoRequirements(maxAmount)
	if err != nil {
		return UptoRequiredEnvelope{}, err
	}
	blockhash, err := u.recentBlockhash()
	if err != nil {
		return UptoRequiredEnvelope{}, fmt.Errorf("failed to fetch recent blockhash: %w", err)
	}
	req.Extra.RecentBlockhash = blockhash
	var resource *ResourceRef
	if u.cfg.Resource != "" {
		resource = &ResourceRef{Type: "http", URL: u.cfg.Resource}
	}
	return UptoRequiredEnvelope{X402Version: x402Version, Resource: resource, Accepts: []UptoRequirements{req}}, nil
}

// PaymentRequiredHeader returns the PAYMENT-REQUIRED header value.
func (u *X402Upto) PaymentRequiredHeader(maxAmount string) (string, string, error) {
	envelope, err := u.Upto(maxAmount)
	if err != nil {
		return "", "", err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return "", "", err
	}
	return paymentRequiredHeader, base64.StdEncoding.EncodeToString(raw), nil
}

// SettlementHeader returns the PAYMENT-RESPONSE header value.
func (u *X402Upto) SettlementHeader(settlement UptoSettlementResponse) (string, string, error) {
	raw, err := json.Marshal(settlement)
	if err != nil {
		return "", "", err
	}
	return paymentResponseHeader, base64.StdEncoding.EncodeToString(raw), nil
}

// ParseUptoPaymentSignature decodes a PAYMENT-SIGNATURE header.
func ParseUptoPaymentSignature(header string) (UptoSignatureEnvelope, error) {
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return UptoSignatureEnvelope{}, fmt.Errorf("invalid 402 response: %w", err)
	}
	var envelope UptoSignatureEnvelope
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		return UptoSignatureEnvelope{}, fmt.Errorf("invalid 402 response: %w", err)
	}
	if envelope.Scheme != uptoScheme {
		return UptoSignatureEnvelope{}, fmt.Errorf("invalid payload type: %s", envelope.Scheme)
	}
	return envelope, nil
}

// VerifyOpen validates, broadcasts, confirms, and binds a payment-channel open.
func (u *X402Upto) VerifyOpen(ctx context.Context, header, maxAmount string) (*UptoVerifiedOpen, error) {
	envelope, err := ParseUptoPaymentSignature(header)
	if err != nil {
		return nil, err
	}
	req, err := u.UptoRequirements(maxAmount)
	if err != nil {
		return nil, err
	}
	payload := envelope.Payload
	if err := VerifyUptoPayload(payload, req, u.Operator(), time.Now().Unix()); err != nil {
		return nil, err
	}
	programID, err := solana.PublicKeyFromBase58(firstNonEmpty(req.Extra.ProgramID, paymentchannels.ProgramID))
	if err != nil {
		return nil, fmt.Errorf("invalid programId: %w", err)
	}
	expectedMint, err := solana.PublicKeyFromBase58(req.Asset)
	if err != nil {
		return nil, fmt.Errorf("invalid mint: %w", err)
	}
	expectedPayee, err := solana.PublicKeyFromBase58(u.cfg.Recipient)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient: %w", err)
	}
	channelID, err := solana.PublicKeyFromBase58(payload.ChannelID)
	if err != nil {
		return nil, fmt.Errorf("invalid channelId: %w", err)
	}
	payer, err := solana.PublicKeyFromBase58(payload.From)
	if err != nil {
		return nil, fmt.Errorf("invalid payer: %w", err)
	}
	max, err := payload.ParsedMaxAmount()
	if err != nil {
		return nil, err
	}
	guard, err := u.reserveChannel(channelID)
	if err != nil {
		return nil, err
	}
	release := true
	defer func() {
		if release {
			guard.release()
		}
	}()
	if payload.OpenTransaction == "" {
		return nil, errors.New("payment-channel profile requires openTransaction (pull)")
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.OpenTransaction)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}
	if err := validateUptoOpenInstruction(tx, programID, u.operator, payer, expectedPayee, expectedMint, channelID); err != nil {
		return nil, err
	}
	if signerIsRequired(tx, u.operator) {
		if err := signPaykitTransaction(ctx, tx, u.cfg.OperatorSigner); err != nil {
			return nil, fmt.Errorf("fee payer signing failed: %w", err)
		}
	}
	if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() {
		return nil, errors.New("open transaction is missing the fee-payer signature")
	}
	sig, err := solanatx.SendTransaction(ctx, u.rpc, tx)
	if err != nil {
		return nil, fmt.Errorf("open broadcast failed: %w", err)
	}
	if err := solanatx.WaitForConfirmation(ctx, u.rpc, sig); err != nil {
		return nil, fmt.Errorf("open confirmation failed: %w", err)
	}
	channel, err := u.fetchChannel(ctx, channelID)
	if err != nil {
		return nil, err
	}
	if channel.Status != uint8(pcgen.ChannelStatus_Open) {
		return nil, errors.New("channel is not open after broadcast")
	}
	if !channel.Mint.Equals(expectedMint) {
		return nil, fmt.Errorf("token mint mismatch: expected %s, got %s", expectedMint, channel.Mint)
	}
	if !channel.Payee.Equals(expectedPayee) {
		return nil, fmt.Errorf("recipient mismatch: expected %s, got %s", expectedPayee, channel.Payee)
	}
	if !bytes.Equal(channel.DistributionHash[:], emptyDistributionHash()) {
		return nil, errors.New("x402 upto currently supports only empty-recipient payment channels")
	}
	if !channel.AuthorizedSigner.Equals(u.operator) {
		return nil, errors.New("channel authorized_signer is not the operator")
	}
	if channel.Deposit < max {
		return nil, fmt.Errorf("on-chain deposit %d below authorized maximum %d", channel.Deposit, max)
	}
	if !channel.Payer.Equals(payer) {
		return nil, fmt.Errorf("channel payer %s does not match payload.from %s", channel.Payer, payer)
	}
	tokenProgram, err := solana.PublicKeyFromBase58(req.Extra.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("invalid token program: %w", err)
	}
	release = false
	return &UptoVerifiedOpen{
		ChannelID: channelID, Payer: payer, Mint: expectedMint, TokenProgram: tokenProgram,
		ProgramID: programID, Deposit: channel.Deposit, MaxAmount: max, ExpiresAt: payload.ExpiresAt,
		Network: req.Network, guard: guard,
	}, nil
}

// SettleActual settles a metered actual amount against a verified open.
func (u *X402Upto) SettleActual(ctx context.Context, open *UptoVerifiedOpen, actual uint64) (UptoSettlementResponse, error) {
	if open == nil {
		return UptoSettlementResponse{}, errors.New("verified open is required")
	}
	defer open.guard.release()
	if err := AssertSettlementWithinCeiling(actual, open.MaxAmount); err != nil {
		return UptoSettlementResponse{}, err
	}
	var voucherSignature *[64]byte
	if actual > 0 {
		message, err := paymentchannels.VoucherMessageBytes(open.ChannelID, actual, open.ExpiresAt)
		if err != nil {
			return UptoSettlementResponse{}, err
		}
		sigBytes, err := u.cfg.OperatorSigner.Sign(ctx, message)
		if err != nil {
			return UptoSettlementResponse{}, fmt.Errorf("voucher signing failed: %w", err)
		}
		if len(sigBytes) != 64 {
			return UptoSettlementResponse{}, fmt.Errorf("voucher signature length %d, want 64", len(sigBytes))
		}
		var fixed [64]byte
		copy(fixed[:], sigBytes)
		voucherSignature = &fixed
	}
	instructions, err := paymentchannels.BuildSettleAndFinalizeInstructions(paymentchannels.SettleAndFinalizeParams{
		Merchant: u.operator, Channel: open.ChannelID, AuthorizedSigner: u.operator,
		Signature: voucherSignature, CumulativeAmount: actual, ExpiresAt: open.ExpiresAt, ProgramID: open.ProgramID,
	})
	if err != nil {
		return UptoSettlementResponse{}, err
	}
	payee, err := solana.PublicKeyFromBase58(u.cfg.Recipient)
	if err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("invalid recipient: %w", err)
	}
	distribute, err := paymentchannels.BuildDistributeInstruction(paymentchannels.DistributeParams{
		Channel: open.ChannelID, Payer: open.Payer, Payee: payee, Treasury: paymentchannels.TreasuryOwner(),
		Mint: open.Mint, TokenProgram: open.TokenProgram, ProgramID: open.ProgramID,
	})
	if err != nil {
		return UptoSettlementResponse{}, err
	}
	instructions = append(instructions, distribute)
	blockhash, err := u.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("blockhash fetch failed: %w", err)
	}
	if blockhash == nil || blockhash.Value == nil {
		return UptoSettlementResponse{}, errors.New("blockhash fetch failed: empty response")
	}
	tx, err := solana.NewTransaction(instructions, blockhash.Value.Blockhash, solana.TransactionPayer(u.operator))
	if err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("build settlement transaction: %w", err)
	}
	if err := signPaykitTransaction(ctx, tx, u.cfg.OperatorSigner); err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("settle signing failed: %w", err)
	}
	signature, err := solanatx.SendTransaction(ctx, u.rpc, tx)
	if err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("settle broadcast failed: %w", err)
	}
	if err := solanatx.WaitForConfirmation(ctx, u.rpc, signature); err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("settle confirmation failed: %w", err)
	}
	return UptoSettlementResponse{Success: true, Payer: open.Payer.String(), Transaction: signature.String(), Network: open.Network, Amount: strconv.FormatUint(actual, 10)}, nil
}

func (u *X402Upto) reserveChannel(channelID solana.PublicKey) (*uptoInFlightGuard, error) {
	key := channelID.String()
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.inFlight[key]; ok {
		return nil, errors.New("channel is already being processed (concurrent request)")
	}
	u.inFlight[key] = struct{}{}
	return &uptoInFlightGuard{engine: u, key: key}, nil
}

func (u *X402Upto) fetchChannel(ctx context.Context, channelID solana.PublicKey) (*pcgen.Channel, error) {
	info, err := u.rpc.GetAccountInfoWithOpts(ctx, channelID, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentConfirmed, Encoding: solana.EncodingBase64})
	if err != nil {
		return nil, fmt.Errorf("channel account fetch failed: %w", err)
	}
	if info == nil || info.Value == nil || info.Value.Data == nil {
		return nil, errors.New("channel account fetch failed: missing account data")
	}
	data := info.Value.Data.GetBinary()
	if len(data) == 0 {
		return nil, errors.New("channel account fetch failed: empty account data")
	}
	channel := new(pcgen.Channel)
	if err := channel.UnmarshalWithDecoder(bin.NewBorshDecoder(data)); err != nil {
		return nil, fmt.Errorf("channel decode failed: %w", err)
	}
	return channel, nil
}

func (u *X402Upto) recentBlockhash() (string, error) {
	if u.cfg.RecentBlockhashProvider != nil {
		return u.cfg.RecentBlockhashProvider()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := u.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return "", err
	}
	if out == nil || out.Value == nil {
		return "", errors.New("empty blockhash response")
	}
	return out.Value.Blockhash.String(), nil
}

func validateUptoOpenInstruction(tx *solana.Transaction, programID, operator, payer, payee, mint, channelID solana.PublicKey) error {
	keys := tx.Message.AccountKeys
	instructions := tx.Message.Instructions
	if len(instructions) != 1 {
		return fmt.Errorf("open transaction must contain exactly one instruction, found %d", len(instructions))
	}
	ix := instructions[0]
	if int(ix.ProgramIDIndex) >= len(keys) {
		return errors.New("open instruction program id out of range")
	}
	if !keys[ix.ProgramIDIndex].Equals(programID) {
		return errors.New("open transaction targets an unexpected program")
	}
	if len(ix.Data) == 0 || ix.Data[0] != 1 {
		return errors.New("open transaction is not a channel-open instruction")
	}
	accountAt := func(pos int) (solana.PublicKey, bool) {
		if pos >= len(ix.Accounts) || int(ix.Accounts[pos]) >= len(keys) {
			return solana.PublicKey{}, false
		}
		return keys[ix.Accounts[pos]], true
	}
	expect := func(pos int, want solana.PublicKey, label string) error {
		got, ok := accountAt(pos)
		if !ok || !got.Equals(want) {
			if !ok {
				return fmt.Errorf("open transaction %s mismatch: expected %s, got <none>", label, want)
			}
			return fmt.Errorf("open transaction %s mismatch: expected %s, got %s", label, want, got)
		}
		return nil
	}
	if err := expect(0, payer, "payer"); err != nil {
		return err
	}
	if err := expect(1, payee, "payee"); err != nil {
		return err
	}
	if err := expect(2, mint, "mint"); err != nil {
		return err
	}
	if err := expect(3, operator, "authorized_signer"); err != nil {
		return err
	}
	if err := expect(4, channelID, "channel"); err != nil {
		return err
	}
	return nil
}

func signerIsRequired(tx *solana.Transaction, key solana.PublicKey) bool {
	for _, signer := range tx.Message.Signers() {
		if signer.Equals(key) {
			return true
		}
	}
	return false
}

func signPaykitTransaction(ctx context.Context, tx *solana.Transaction, signer paykit.Signer) error {
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		return err
	}
	sigBytes, err := signer.Sign(ctx, message)
	if err != nil {
		return err
	}
	if len(sigBytes) != 64 {
		return fmt.Errorf("signature length %d, want 64", len(sigBytes))
	}
	pubkey, err := solana.PublicKeyFromBase58(string(signer.Pubkey()))
	if err != nil {
		return err
	}
	signers := tx.Message.Signers()
	if len(tx.Signatures) != len(signers) {
		tx.Signatures = make([]solana.Signature, len(signers))
	}
	for i, key := range signers {
		if key.Equals(pubkey) {
			var sig solana.Signature
			copy(sig[:], sigBytes)
			tx.Signatures[i] = sig
			return nil
		}
	}
	return fmt.Errorf("signer %s is not required by transaction", pubkey)
}

func parseDecimalUnits(amount string, decimals uint8) (string, error) {
	price, err := paykit.ParseUSD(amount)
	if err != nil {
		return "", err
	}
	return price.Amount().Shift(int32(decimals)).Truncate(0).String(), nil
}

func emptyDistributionHash() []byte {
	// blake3(0u32.to_le_bytes()) — the distribution hash for zero recipients,
	// matching Rust solana_pay_core::payment_channels::distribution_hash(&[]).
	return []byte{236, 43, 208, 59, 248, 107, 147, 95, 163, 77, 113, 173, 126, 187, 4, 159, 31, 16, 248, 125, 52, 62, 82, 21, 17, 216, 249, 230, 98, 86, 32, 205}
}
