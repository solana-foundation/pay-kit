package x402

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/shopspring/decimal"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

type uptoNetwork interface {
	DefaultRPCURL() string
	MintsLabel() string
	CAIP2() string
}

type uptoSigner interface {
	Pubkey() string
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

const (
	UptoScheme                       = "upto"
	UptoAssetTransferMethod          = "payment-channel"
	UptoErrorSettlementExceedsAmount = "invalid_upto_svm_payload_settlement_exceeds_amount"
	DefaultUptoWithdrawDelaySeconds  = 900
)

// UptoExtra is the extra object on an x402 upto payment requirement.
type UptoExtra struct {
	Decimals             *uint8 `json:"decimals,omitempty"`
	TokenProgram         string `json:"tokenProgram,omitempty"`
	FeePayer             string `json:"feePayer"`
	ReceiverAuthorizer   string `json:"receiverAuthorizer"`
	WithdrawDelay        uint32 `json:"withdrawDelay"`
	RecentBlockhash      string `json:"recentBlockhash,omitempty"`
	LastValidBlockHeight string `json:"lastValidBlockHeight,omitempty"`
	// RecentSlot is the current slot pre-fetched by the server alongside
	// recentBlockhash (decimal u64 string). The client uses it as the channel
	// open_slot (a PDA seed and open arg); clients never fetch it themselves.
	RecentSlot string `json:"recentSlot,omitempty"`
	ValidAfter *int64 `json:"validAfter,omitempty"`
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
	From             string `json:"from"`
	MaxAmount        string `json:"maxAmount"`
	ExpiresAt        int64  `json:"expiresAt"`
	ValidAfter       int64  `json:"validAfter"`
	Nonce            string `json:"nonce"`
	ChannelID        string `json:"channelId"`
	Deposit          string `json:"deposit"`
	AuthorizedSigner string `json:"authorizedSigner"`
	OpenSlot         string `json:"openSlot"`
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
	Scheme      string          `json:"scheme,omitempty"`
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
func VerifyUptoPayload(payload UptoPayload, requirements UptoRequirements, receiverAuthorizer string, now int64) error {
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
	if deposit != max {
		return fmt.Errorf("channel deposit %d must equal the authorized maximum %d", deposit, max)
	}
	if now < payload.ValidAfter {
		return fmt.Errorf("authorization not yet active (validAfter %d > now %d)", payload.ValidAfter, now)
	}
	if payload.ExpiresAt == 0 || now >= payload.ExpiresAt {
		return fmt.Errorf("authorization expired (expiresAt %d < now %d)", payload.ExpiresAt, now)
	}
	if payload.AuthorizedSigner != receiverAuthorizer {
		return errors.New("voucher authorized_signer must be the advertised receiver authorizer")
	}
	return nil
}

// AssertSettlementWithinCeiling enforces actual <= max at settlement.
func AssertSettlementWithinCeiling(actual, max uint64) error {
	if actual > max {
		return errors.New(UptoErrorSettlementExceedsAmount)
	}
	return nil
}

// UptoVerifiedOpen is a confirmed channel open carried into settlement.
type UptoVerifiedOpen struct {
	ChannelID    solana.PublicKey
	Payer        solana.PublicKey
	Payee        solana.PublicKey
	RentPayer    solana.PublicKey
	Mint         solana.PublicKey
	TokenProgram solana.PublicKey
	ProgramID    solana.PublicKey
	Distribution []paymentchannels.Distribution
	Deposit      uint64
	MaxAmount    uint64
	ExpiresAt    int64
	Network      string
	guard        *uptoInFlightGuard
}

// Release frees the in-flight reservation for a verified open. It is
// idempotent because direct engine callers and PayKit middleware may both
// release the same handle after settlement.
func (o *UptoVerifiedOpen) Release() {
	if o == nil {
		return
	}
	o.guard.release()
}

// UptoConfig configures the x402 upto server engine.
type UptoConfig struct {
	Recipient         string
	Currency          string
	Decimals          uint8
	Network           uptoNetwork
	RPCURL            string
	Resource          string
	Description       string
	MaxTimeoutSeconds uint64
	TokenProgram      string
	ChannelProgram    string
	// FeePayerSigner is the transaction fee payer, channel rent payer, and
	// zero-share channel payee. It signs settle_and_seal (lifecycle
	// authority) and can always seal an abandoned channel with
	// has_voucher = 0 to recover its rent.
	FeePayerSigner uptoSigner
	// ReceiverAuthorizerSigner is the channel authorized_signer: it signs
	// only the Ed25519 vouchers (payment authority). Defaults to
	// FeePayerSigner for self-facilitation.
	ReceiverAuthorizerSigner uptoSigner
	WithdrawDelay            uint32
	RecentBlockhashProvider  func() (string, error)
	// RecentSlotProvider overrides the current-slot fetch for the challenge's
	// extra.recentSlot (deterministic tests). Nil fetches via the RPC client's
	// getSlot.
	RecentSlotProvider func() (uint64, error)
}

// X402Upto is the server-side x402 upto payment-channel engine.
type X402Upto struct {
	cfg                UptoConfig
	rpc                solanatx.RPCClient
	feePayer           solana.PublicKey
	receiverAuthorizer solana.PublicKey
	inFlight           map[string]struct{}
	mu                 sync.Mutex
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
		cfg.Decimals = StablecoinDecimals
	}
	if cfg.MaxTimeoutSeconds == 0 {
		cfg.MaxTimeoutSeconds = DefaultMaxTimeoutSeconds
	}
	if cfg.WithdrawDelay == 0 {
		cfg.WithdrawDelay = DefaultUptoWithdrawDelaySeconds
	}
	if cfg.FeePayerSigner == nil {
		return nil, errors.New("fee payer signer is required")
	}
	if cfg.ReceiverAuthorizerSigner == nil {
		cfg.ReceiverAuthorizerSigner = cfg.FeePayerSigner
	}
	feePayer, err := solana.PublicKeyFromBase58(cfg.FeePayerSigner.Pubkey())
	if err != nil {
		return nil, fmt.Errorf("fee payer pubkey: %w", err)
	}
	receiverAuthorizer, err := solana.PublicKeyFromBase58(cfg.ReceiverAuthorizerSigner.Pubkey())
	if err != nil {
		return nil, fmt.Errorf("receiver authorizer pubkey: %w", err)
	}
	if _, err := solana.PublicKeyFromBase58(cfg.Recipient); err != nil {
		return nil, fmt.Errorf("invalid recipient pubkey: %w", err)
	}
	rpcURL := cfg.RPCURL
	if rpcURL == "" {
		rpcURL = cfg.Network.DefaultRPCURL()
	}
	return &X402Upto{
		cfg:                cfg,
		rpc:                rpc.New(rpcURL),
		feePayer:           feePayer,
		receiverAuthorizer: receiverAuthorizer,
		inFlight:           map[string]struct{}{},
	}, nil
}

// SetRPCForTests replaces the RPC client for deterministic tests.
func (u *X402Upto) SetRPCForTests(rpcClient solanatx.RPCClient) {
	u.rpc = rpcClient
}

// FeePayer returns the transaction fee payer, channel rent payer, and
// zero-share channel payee public key. Holding the payee seat gives it
// lifecycle authority: it can always settle_and_seal with has_voucher = 0 to
// recover its rent, but cannot settle a nonzero amount or redirect funds —
// those need the receiver authorizer's voucher and the sealed distribution.
func (u *X402Upto) FeePayer() string { return u.feePayer.String() }

// ReceiverAuthorizer returns the voucher signer public key (the channel
// authorized_signer). It signs only the Ed25519 voucher, never transactions.
func (u *X402Upto) ReceiverAuthorizer() string { return u.receiverAuthorizer.String() }

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
	tokenProgram := u.cfg.TokenProgram
	if tokenProgram == "" {
		tokenProgram = paycore.DefaultTokenProgramForCurrency(coin, label)
	}
	decimals := u.cfg.Decimals
	return UptoRequirements{
		Scheme:            UptoScheme,
		Network:           u.cfg.Network.CAIP2(),
		Amount:            baseUnits,
		Asset:             mint,
		PayTo:             u.cfg.Recipient,
		MaxTimeoutSeconds: u.cfg.MaxTimeoutSeconds,
		Extra: UptoExtra{
			Decimals:           &decimals,
			TokenProgram:       tokenProgram,
			FeePayer:           u.FeePayer(),
			ReceiverAuthorizer: u.ReceiverAuthorizer(),
			WithdrawDelay:      u.cfg.WithdrawDelay,
		},
	}, nil
}

// Upto builds the full payment-required envelope for an upto challenge. The
// server pre-fetches both the recent blockhash and the current slot (the
// channel openSlot) into extra so the client never needs an RPC handle.
func (u *X402Upto) Upto(maxAmount string) (UptoRequiredEnvelope, error) {
	req, err := u.UptoRequirements(maxAmount)
	if err != nil {
		return UptoRequiredEnvelope{}, err
	}
	blockhash, recentSlot, err := u.recentLifetime()
	if err != nil {
		return UptoRequiredEnvelope{}, fmt.Errorf("failed to fetch recent blockhash: %w", err)
	}
	req.Extra.RecentBlockhash = blockhash
	req.Extra.RecentSlot = strconv.FormatUint(recentSlot, 10)
	var resource *ResourceRef
	if u.cfg.Resource != "" {
		resource = &ResourceRef{Type: "http", URL: u.cfg.Resource}
	}
	return UptoRequiredEnvelope{X402Version: X402Version, Resource: resource, Accepts: []UptoRequirements{req}}, nil
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
	return PaymentRequiredHeader, base64.StdEncoding.EncodeToString(raw), nil
}

// SettlementHeader returns the PAYMENT-RESPONSE header value.
func (u *X402Upto) SettlementHeader(settlement UptoSettlementResponse) (string, string, error) {
	raw, err := json.Marshal(settlement)
	if err != nil {
		return "", "", err
	}
	return PaymentResponseHeader, base64.StdEncoding.EncodeToString(raw), nil
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
	if envelope.Scheme == "" && len(envelope.Accepted) > 0 {
		var accepted UptoRequirements
		if err := json.Unmarshal(envelope.Accepted, &accepted); err != nil {
			return UptoSignatureEnvelope{}, fmt.Errorf("invalid accepted requirements: %w", err)
		}
		envelope.Scheme = accepted.Scheme
		envelope.Network = accepted.Network
	}
	if envelope.Scheme != UptoScheme {
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
	if err := VerifyUptoPayload(payload, req, u.ReceiverAuthorizer(), time.Now().Unix()); err != nil {
		return nil, err
	}
	// Phase 3 step 2: confirm network matches the advertised requirements.
	if envelope.Network != req.Network {
		return nil, fmt.Errorf("network mismatch: payload %q, expected %q", envelope.Network, req.Network)
	}
	programID, err := solana.PublicKeyFromBase58(firstNonEmpty(u.cfg.ChannelProgram, paymentchannels.ProgramID))
	if err != nil {
		return nil, fmt.Errorf("invalid channel program: %w", err)
	}
	expectedMint, err := solana.PublicKeyFromBase58(req.Asset)
	if err != nil {
		return nil, fmt.Errorf("invalid mint: %w", err)
	}
	// The fee payer (facilitator) holds the channel payee seat with a
	// zero-share distribution; the receiver authorizer is only the
	// authorized voucher signer.
	expectedPayee := u.feePayer
	expectedDistribution, err := u.distribution()
	if err != nil {
		return nil, err
	}
	tokenProgram, err := solana.PublicKeyFromBase58(req.Extra.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("invalid token program: %w", err)
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
		return nil, errors.New("payment-channel asset transfer method requires openTransaction (pull)")
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.OpenTransaction)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}
	// The challenged recentSlot at verify time: fetched fresh, so the
	// transaction's openSlot (stamped from the earlier challenge) must sit
	// at-or-before it inside the program freshness window. A failed fetch
	// skips the window check (nil); the PDA bind below still holds and the
	// program enforces the window at broadcast.
	var challengedSlot *uint64
	if _, slot, slotErr := u.recentLifetime(); slotErr == nil {
		challengedSlot = &slot
	}
	if err := validateUptoOpenInstruction(
		tx,
		programID,
		u.feePayer,
		u.receiverAuthorizer,
		payer,
		expectedPayee,
		expectedMint,
		tokenProgram,
		channelID,
		max,
		u.cfg.WithdrawDelay,
		payload.Nonce,
		payload.OpenSlot,
		challengedSlot,
	); err != nil {
		return nil, err
	}
	if !transactionFeePayerIs(tx, u.feePayer) {
		return nil, errors.New("open transaction fee payer must be the advertised fee payer")
	}
	if err := signPaykitTransaction(ctx, tx, u.cfg.FeePayerSigner); err != nil {
		return nil, fmt.Errorf("fee payer signing failed: %w", err)
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
		return nil, fmt.Errorf("channel payee mismatch: expected fee payer %s, got %s", expectedPayee, channel.Payee)
	}
	expectedDistributionHash := distributionHash(expectedDistribution)
	if !bytes.Equal(channel.DistributionHash[:], expectedDistributionHash[:]) {
		return nil, errors.New("channel distribution does not match the expected recipient split")
	}
	if !channel.AuthorizedSigner.Equals(u.receiverAuthorizer) {
		return nil, errors.New("channel authorized_signer is not the receiver authorizer")
	}
	if !channel.RentPayer.Equals(u.feePayer) {
		return nil, errors.New("channel rent_payer is not the fee payer")
	}
	if channel.GracePeriod != u.cfg.WithdrawDelay {
		return nil, fmt.Errorf("channel withdraw delay %d does not match advertised %d", channel.GracePeriod, u.cfg.WithdrawDelay)
	}
	if channel.Deposit != max {
		return nil, fmt.Errorf("on-chain deposit %d must equal authorized maximum %d", channel.Deposit, max)
	}
	if !channel.Payer.Equals(payer) {
		return nil, fmt.Errorf("channel payer %s does not match payload.from %s", channel.Payer, payer)
	}
	release = false
	return &UptoVerifiedOpen{
		ChannelID: channelID, Payer: payer, Payee: expectedPayee, RentPayer: channel.RentPayer, Mint: expectedMint,
		TokenProgram: tokenProgram, ProgramID: programID, Distribution: expectedDistribution,
		Deposit: channel.Deposit, MaxAmount: max, ExpiresAt: payload.ExpiresAt,
		Network: req.Network, guard: guard,
	}, nil
}

// SettleActual settles a metered actual amount against a verified open.
func (u *X402Upto) SettleActual(ctx context.Context, open *UptoVerifiedOpen, actual uint64) (UptoSettlementResponse, error) {
	if open == nil {
		return UptoSettlementResponse{}, errors.New("verified open is required")
	}
	defer open.Release()
	if err := AssertSettlementWithinCeiling(actual, open.MaxAmount); err != nil {
		return UptoSettlementResponse{}, err
	}
	var instructions []solana.Instruction
	if actual == 0 {
		var err error
		instructions, err = paymentchannels.BuildSettleAndSealInstructions(paymentchannels.SettleAndSealParams{
			Payee: u.feePayer, Channel: open.ChannelID, AuthorizedSigner: u.receiverAuthorizer,
			Signature: nil, CumulativeAmount: 0, ExpiresAt: open.ExpiresAt, ProgramID: open.ProgramID,
		})
		if err != nil {
			return UptoSettlementResponse{}, err
		}
	} else {
		message, err := paymentchannels.VoucherMessageBytes(open.ChannelID, actual, open.ExpiresAt)
		if err != nil {
			return UptoSettlementResponse{}, err
		}
		sigBytes, err := u.cfg.ReceiverAuthorizerSigner.Sign(ctx, message)
		if err != nil {
			return UptoSettlementResponse{}, fmt.Errorf("voucher signing failed: %w", err)
		}
		if len(sigBytes) != 64 {
			return UptoSettlementResponse{}, fmt.Errorf("voucher signature length %d, want 64", len(sigBytes))
		}
		var voucherSignature [64]byte
		copy(voucherSignature[:], sigBytes)
		instructions, err = paymentchannels.BuildSettleAndSealInstructions(paymentchannels.SettleAndSealParams{
			Payee: u.feePayer, Channel: open.ChannelID, AuthorizedSigner: u.receiverAuthorizer,
			Signature: &voucherSignature, CumulativeAmount: actual, ExpiresAt: open.ExpiresAt, ProgramID: open.ProgramID,
		})
		if err != nil {
			return UptoSettlementResponse{}, err
		}
	}
	payee := open.Payee
	if payee.IsZero() {
		payee = u.feePayer
	}
	distribute, err := paymentchannels.BuildDistributeInstruction(paymentchannels.DistributeParams{
		Channel: open.ChannelID, Payer: open.Payer, RentPayer: open.RentPayer, Payee: payee, Treasury: paymentchannels.TreasuryOwner(),
		Mint: open.Mint, Recipients: open.Distribution, TokenProgram: open.TokenProgram, ProgramID: open.ProgramID,
	})
	if err != nil {
		return UptoSettlementResponse{}, err
	}
	createPayeeATA, err := solanatx.BuildCreateAssociatedTokenAccount(u.feePayer, payee, open.Mint, open.TokenProgram)
	if err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("build payee ATA create: %w", err)
	}
	createTreasuryATA, err := solanatx.BuildCreateAssociatedTokenAccount(u.feePayer, paymentchannels.TreasuryOwner(), open.Mint, open.TokenProgram)
	if err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("build treasury ATA create: %w", err)
	}
	instructions = append(instructions, createPayeeATA, createTreasuryATA, distribute)
	for _, entry := range open.Distribution {
		createRecipientATA, err := solanatx.BuildCreateAssociatedTokenAccount(u.feePayer, entry.Recipient, open.Mint, open.TokenProgram)
		if err != nil {
			return UptoSettlementResponse{}, fmt.Errorf("build recipient ATA create: %w", err)
		}
		instructions = append(instructions[:len(instructions)-1], createRecipientATA, distribute)
	}
	blockhash, err := u.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("blockhash fetch failed: %w", err)
	}
	if blockhash == nil || blockhash.Value == nil {
		return UptoSettlementResponse{}, errors.New("blockhash fetch failed: empty response")
	}
	tx, err := solana.NewTransaction(instructions, blockhash.Value.Blockhash, solana.TransactionPayer(u.feePayer))
	if err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("build settlement transaction: %w", err)
	}
	// settle_and_seal is signed by the fee payer (the channel payee); the
	// receiver authorizer signs only the Ed25519 voucher above.
	if err := signPaykitTransaction(ctx, tx, u.cfg.FeePayerSigner); err != nil {
		return UptoSettlementResponse{}, fmt.Errorf("fee payer signing failed: %w", err)
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

// distribution returns the sealed recipient split: always the explicit
// single-entry 100% payTo split. The payee seat is held by the facilitator
// (fee payer) with a zero implicit remainder, so all settled funds must be
// assigned to the recipient through the recipients list.
func (u *X402Upto) distribution() ([]paymentchannels.Distribution, error) {
	recipient, err := solana.PublicKeyFromBase58(u.cfg.Recipient)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient: %w", err)
	}
	return []paymentchannels.Distribution{{
		Recipient: recipient,
		Bps:       10_000,
	}}, nil
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

// recentLifetime returns the challenge lifetime pair: a recent blockhash and
// the current slot (the channel open_slot advertised as extra.recentSlot).
// One getLatestBlockhash call supplies both — the response context already
// carries the slot — unless the config providers override them.
func (u *X402Upto) recentLifetime() (string, uint64, error) {
	if u.cfg.RecentBlockhashProvider != nil {
		blockhash, err := u.cfg.RecentBlockhashProvider()
		if err != nil {
			return "", 0, err
		}
		if u.cfg.RecentSlotProvider == nil {
			return "", 0, errors.New("RecentSlotProvider is required when RecentBlockhashProvider is set")
		}
		slot, err := u.cfg.RecentSlotProvider()
		if err != nil {
			return "", 0, err
		}
		return blockhash, slot, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := u.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return "", 0, err
	}
	if out == nil || out.Value == nil {
		return "", 0, errors.New("empty blockhash response")
	}
	return out.Value.Blockhash.String(), out.Context.Slot, nil
}

// openSlotWindow is the program's openSlot freshness window (slots): open
// requires openSlot <= clock.slot and clock.slot - openSlot <= 1500. Applied
// pre-broadcast against the challenged extra.recentSlot so a stale or forged
// slot fails before the fee payer co-signs.
const openSlotWindow = 1500

func validateUptoOpenInstruction(
	tx *solana.Transaction,
	programID, rentPayer, authorizedSigner, payer, payee, mint, tokenProgram, channelID solana.PublicKey,
	maxAmount uint64,
	withdrawDelay uint32,
	payloadNonce string,
	payloadOpenSlot string,
	recentSlot *uint64,
) error {
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
	if err := expect(1, rentPayer, "rent_payer"); err != nil {
		return err
	}
	if err := expect(2, payee, "payee"); err != nil {
		return err
	}
	if err := expect(3, mint, "mint"); err != nil {
		return err
	}
	if err := expect(4, authorizedSigner, "authorized_signer"); err != nil {
		return err
	}
	if err := expect(5, channelID, "channel"); err != nil {
		return err
	}
	payerToken, _, err := solana.FindAssociatedTokenAddressWithProgram(payer, mint, tokenProgram)
	if err != nil {
		return fmt.Errorf("derive payer token account: %w", err)
	}
	channelToken, _, err := solana.FindAssociatedTokenAddressWithProgram(channelID, mint, tokenProgram)
	if err != nil {
		return fmt.Errorf("derive channel token account: %w", err)
	}
	if err := expect(6, payerToken, "payer_token_account"); err != nil {
		return err
	}
	if err := expect(7, channelToken, "channel_token_account"); err != nil {
		return err
	}
	if err := expect(8, tokenProgram, "token_program"); err != nil {
		return err
	}
	if err := expect(9, solana.SystemProgramID, "system_program"); err != nil {
		return err
	}
	if err := expect(10, solana.SysVarRentPubkey, "rent_sysvar"); err != nil {
		return err
	}
	if err := expect(11, solana.SPLAssociatedTokenAccountProgramID, "associated_token_program"); err != nil {
		return err
	}
	eventAuthority, _, err := paymentchannels.FindEventAuthorityPDAForProgram(programID)
	if err != nil {
		return err
	}
	if err := expect(12, eventAuthority, "event_authority"); err != nil {
		return err
	}
	if err := expect(13, programID, "self_program"); err != nil {
		return err
	}

	// openArgs layout:
	// [discriminator u8][salt u64][deposit u64][grace u32][openSlot u64][recipients].
	if len(ix.Data) < 1+8+8+4+8 {
		return fmt.Errorf("open instruction data too short (%d bytes)", len(ix.Data))
	}
	salt := binary.LittleEndian.Uint64(ix.Data[1:9])
	deposit := binary.LittleEndian.Uint64(ix.Data[9:17])
	gracePeriod := binary.LittleEndian.Uint32(ix.Data[17:21])
	openSlot := binary.LittleEndian.Uint64(ix.Data[21:29])
	if payloadNonce != strconv.FormatUint(salt, 10) {
		return fmt.Errorf("open salt %d does not match payload nonce %q", salt, payloadNonce)
	}
	if payloadOpenSlot != strconv.FormatUint(openSlot, 10) {
		return fmt.Errorf("open slot %d does not match payload openSlot %q", openSlot, payloadOpenSlot)
	}
	if gracePeriod != withdrawDelay {
		return fmt.Errorf("open withdraw delay %d must equal the advertised withdrawDelay %d", gracePeriod, withdrawDelay)
	}

	// Slot-addressed channel invariant: the channel account must be the PDA
	// actually derived with the args' salt + openSlot, not just any account
	// the payload named.
	derived, _, err := paymentchannels.FindChannelPDAForProgram(payer, payee, mint, authorizedSigner, salt, openSlot, programID)
	if err != nil {
		return fmt.Errorf("derive channel PDA: %w", err)
	}
	if !derived.Equals(channelID) {
		return fmt.Errorf("open channel PDA %s != derived %s", channelID, derived)
	}
	if deposit != maxAmount {
		return fmt.Errorf("open deposit %d must equal the authorized maximum %d", deposit, maxAmount)
	}
	if recentSlot != nil {
		if openSlot > *recentSlot {
			return fmt.Errorf("open openSlot %d is ahead of the challenged recentSlot %d", openSlot, *recentSlot)
		}
		if *recentSlot-openSlot > openSlotWindow {
			return fmt.Errorf(
				"open openSlot %d is outside the %d-slot freshness window of the challenged recentSlot %d",
				openSlot, openSlotWindow, *recentSlot,
			)
		}
	}
	return nil
}

func transactionFeePayerIs(tx *solana.Transaction, key solana.PublicKey) bool {
	return tx != nil && len(tx.Message.AccountKeys) > 0 && tx.Message.AccountKeys[0].Equals(key)
}

func signPaykitTransaction(ctx context.Context, tx *solana.Transaction, signer uptoSigner) error {
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
	pubkey, err := solana.PublicKeyFromBase58(signer.Pubkey())
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
	d, err := decimal.NewFromString(amount)
	if err != nil {
		return "", fmt.Errorf("invalid amount %q: %w", amount, err)
	}
	return d.Shift(int32(decimals)).Truncate(0).String(), nil
}

func distributionHash(recipients []paymentchannels.Distribution) [32]byte {
	hasher := sha256.New()
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], uint32(len(recipients)))
	_, _ = hasher.Write(count[:])
	for _, recipient := range recipients {
		_, _ = hasher.Write(recipient.Recipient.Bytes())
		var bps [2]byte
		binary.LittleEndian.PutUint16(bps[:], recipient.Bps)
		_, _ = hasher.Write(bps[:])
	}
	var out [32]byte
	copy(out[:], hasher.Sum(nil))
	return out
}

func emptyDistributionHash() []byte { return EmptyDistributionHash[:] }

var EmptyDistributionHash = [32]byte{223, 63, 97, 152, 4, 169, 47, 219, 64, 87, 25, 45, 196, 61, 215, 72, 234, 119, 138, 220, 82, 188, 73, 140, 232, 5, 36, 192, 20, 184, 17, 25}
