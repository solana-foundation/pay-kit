// Client-side helpers for payment-channel open transactions.
//
// These builders turn a parsed session challenge (SessionRequest) into the
// on-chain open transaction and the matching open action payload, applying the
// cross-SDK defaults: fee payer = challenge operator, deposit = challenge cap,
// grace period 900 seconds, random u64 salt, token program resolved from the
// challenge currency (Token-2022 for PYUSD/USDG/CASH), and the
// PendingServerSignature placeholder while the operator broadcasts.
package client

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// DefaultGracePeriodSeconds is the default payment-channel close grace period,
// shared across the language SDK clients.
const DefaultGracePeriodSeconds uint32 = 900

// PendingServerSignature is the placeholder open signature used while the
// operator still needs to submit the server-broadcast open transaction. It is
// the base58 form of an all-zero 64-byte signature (64 ones).
const PendingServerSignature = "1111111111111111111111111111111111111111111111111111111111111111"

// PaymentChannelOpen is a fully derived payment-channel open: every channel
// parameter resolved from the challenge plus the resulting channel PDA.
type PaymentChannelOpen struct {
	// ChannelID is the channel PDA derived from payer, payee, mint,
	// authorized signer, and salt against ProgramID.
	ChannelID solana.PublicKey

	// Payer is the wallet that funds the escrow deposit.
	Payer solana.PublicKey

	// Payee is the channel beneficiary, parsed from the challenge recipient.
	Payee solana.PublicKey

	// Mint is the SPL token mint, resolved from the challenge currency and
	// network.
	Mint solana.PublicKey

	// AuthorizedSigner is the ephemeral session key whose Ed25519 signatures
	// authorize the channel's cumulative vouchers.
	AuthorizedSigner solana.PublicKey

	// RentPayer is the operator / fee payer that funds the channel rent and
	// co-signs the open as fee payer while gasless. It is derived from the
	// challenge operator and is NOT a channel-PDA seed, so it never affects
	// the derived ChannelID.
	RentPayer solana.PublicKey

	// Salt is the random u64 that makes the channel PDA unique per open.
	Salt uint64

	// Deposit is the escrow deposit in token base units; it defaults to the
	// challenge cap.
	Deposit uint64

	// GracePeriod is the close grace period in seconds (default 900).
	GracePeriod uint32

	// Recipients are the settlement distribution splits derived from the
	// challenge splits; empty means no splits.
	Recipients []paymentchannels.Distribution

	// TokenProgram is the program owning Mint (Token, or Token-2022 for
	// PYUSD/USDG/CASH).
	TokenProgram solana.PublicKey

	// ProgramID is the payment-channels program the open targets; defaults
	// to the canonical program unless the challenge pins one.
	ProgramID solana.PublicKey
}

// OpenChannelParams converts the derived open into instruction-builder params.
func (o PaymentChannelOpen) OpenChannelParams() paymentchannels.OpenChannelParams {
	return paymentchannels.OpenChannelParams{
		Payer:            o.Payer,
		Payee:            o.Payee,
		Mint:             o.Mint,
		AuthorizedSigner: o.AuthorizedSigner,
		RentPayer:        o.RentPayer,
		Salt:             o.Salt,
		Deposit:          o.Deposit,
		GracePeriod:      o.GracePeriod,
		Recipients:       o.Recipients,
		TokenProgram:     o.TokenProgram,
		ProgramID:        o.ProgramID,
	}
}

// OpenPayload builds the open action payload carrying the derived channel
// parameters with the given submission mode and confirmation signature.
func (o PaymentChannelOpen) OpenPayload(mode intents.SessionMode, signature string) intents.OpenPayload {
	return intents.OpenPayloadPaymentChannelWithMode(
		mode,
		o.ChannelID.String(),
		strconv.FormatUint(o.Deposit, 10),
		o.Payer.String(),
		o.Payee.String(),
		o.Mint.String(),
		o.Salt,
		o.GracePeriod,
		o.AuthorizedSigner.String(),
		signature,
	)
}

// PaymentChannelOpenTransaction is a partially signed open transaction ready
// for the operator to fee-payer sign and broadcast.
type PaymentChannelOpenTransaction struct {
	// ChannelID is the derived channel PDA the transaction opens.
	ChannelID solana.PublicKey

	// Transaction is the standard base64 (with padding) wire encoding of the
	// payer-signed legacy transaction, for OpenPayload.Transaction.
	Transaction string
}

// PaymentChannelOpenOptions overrides the challenge-derived open defaults.
// Every field is optional; the zero value applies the cross-SDK defaults.
type PaymentChannelOpenOptions struct {
	// Deposit overrides the escrow deposit. Defaults to the challenge cap.
	Deposit *uint64

	// GracePeriod overrides the close grace period. Defaults to
	// DefaultGracePeriodSeconds.
	GracePeriod *uint32

	// ProgramID overrides the payment-channels program. Defaults to the
	// challenge programId, falling back to the canonical program.
	ProgramID *solana.PublicKey

	// Recipients overrides the distribution splits. nil derives them from the
	// challenge splits; a non-nil empty slice means no splits.
	Recipients []paymentchannels.Distribution

	// Salt overrides the channel salt. Defaults to a random u64.
	Salt *uint64

	// TokenProgram overrides the token program. Defaults to the program
	// resolved from the challenge currency (Token-2022 for PYUSD/USDG/CASH).
	TokenProgram *solana.PublicKey
}

// DerivePaymentChannelOpen resolves every open parameter from a session
// challenge: mint and token program from the currency, payee from the
// recipient, deposit from the cap, splits, program id, grace period 900s, and
// a random salt, then derives the channel PDA.
func DerivePaymentChannelOpen(
	request intents.SessionRequest,
	payer, authorizedSigner solana.PublicKey,
	options PaymentChannelOpenOptions,
) (PaymentChannelOpen, error) {
	network := ""
	if request.Network != nil {
		network = *request.Network
	}

	mintAddress := paycore.ResolveMint(request.Currency, network)
	if mintAddress == "" {
		return PaymentChannelOpen{}, fmt.Errorf("session payment channels require an SPL token")
	}
	mint, err := parseSessionPubkey(mintAddress, "mint")
	if err != nil {
		return PaymentChannelOpen{}, err
	}
	payee, err := parseSessionPubkey(request.Recipient, "recipient")
	if err != nil {
		return PaymentChannelOpen{}, err
	}
	rentPayer, err := parseSessionPubkey(request.Operator, "operator")
	if err != nil {
		return PaymentChannelOpen{}, err
	}

	deposit := uint64(0)
	if options.Deposit != nil {
		deposit = *options.Deposit
	} else {
		deposit, err = strconv.ParseUint(request.Cap, 10, 64)
		if err != nil {
			return PaymentChannelOpen{}, fmt.Errorf("invalid session cap: %w", err)
		}
	}

	gracePeriod := DefaultGracePeriodSeconds
	if options.GracePeriod != nil {
		gracePeriod = *options.GracePeriod
	}

	programID := paymentchannels.ProgramPubkey()
	switch {
	case options.ProgramID != nil:
		programID = *options.ProgramID
	case request.ProgramID != nil:
		programID, err = parseSessionPubkey(*request.ProgramID, "programId")
		if err != nil {
			return PaymentChannelOpen{}, err
		}
	}

	var tokenProgram solana.PublicKey
	if options.TokenProgram != nil {
		tokenProgram = *options.TokenProgram
	} else {
		tokenProgram, err = parseSessionPubkey(
			paycore.DefaultTokenProgramForCurrency(request.Currency, network), "token program")
		if err != nil {
			return PaymentChannelOpen{}, err
		}
	}

	recipients := options.Recipients
	if recipients == nil {
		recipients, err = parseSessionSplits(request.Splits)
		if err != nil {
			return PaymentChannelOpen{}, err
		}
	}

	salt := uint64(0)
	if options.Salt != nil {
		salt = *options.Salt
	} else {
		salt, err = randomSalt()
		if err != nil {
			return PaymentChannelOpen{}, err
		}
	}

	channelID, _, err := paymentchannels.FindChannelPDAForProgram(
		payer, payee, mint, authorizedSigner, salt, programID)
	if err != nil {
		return PaymentChannelOpen{}, err
	}

	return PaymentChannelOpen{
		ChannelID:        channelID,
		Payer:            payer,
		Payee:            payee,
		Mint:             mint,
		AuthorizedSigner: authorizedSigner,
		RentPayer:        rentPayer,
		Salt:             salt,
		Deposit:          deposit,
		GracePeriod:      gracePeriod,
		Recipients:       recipients,
		TokenProgram:     tokenProgram,
		ProgramID:        programID,
	}, nil
}

// BuildOpenPaymentChannelTransactionParams carries the inputs for
// BuildOpenPaymentChannelTransaction.
type BuildOpenPaymentChannelTransactionParams struct {
	// Request is the parsed session challenge.
	Request intents.SessionRequest

	// Signer is the payer wallet; it partially signs the open transaction.
	Signer solanatx.Signer

	// AuthorizedSigner is the ephemeral session voucher key.
	AuthorizedSigner solana.PublicKey

	// FeePayer overrides the transaction fee payer. Defaults to the challenge
	// operator, which completes the signature and broadcasts.
	FeePayer *solana.PublicKey

	// RecentBlockhash is the base58 blockhash for the transaction lifetime.
	// Empty echoes the challenge recentBlockhash.
	RecentBlockhash string

	// Options overrides the challenge-derived open defaults.
	Options PaymentChannelOpenOptions
}

// BuildOpenPaymentChannelTransaction derives the open from the challenge and
// assembles the legacy open transaction with the operator as fee payer,
// partially signed by the payer, base64-encoded for OpenPayload.Transaction.
func BuildOpenPaymentChannelTransaction(params BuildOpenPaymentChannelTransactionParams) (PaymentChannelOpenTransaction, error) {
	operator, err := parseSessionPubkey(params.Request.Operator, "operator")
	if err != nil {
		return PaymentChannelOpenTransaction{}, err
	}
	feePayer := operator
	if params.FeePayer != nil {
		feePayer = *params.FeePayer
	}
	if !feePayer.Equals(operator) {
		return PaymentChannelOpenTransaction{}, fmt.Errorf(
			"FeePayer must equal the challenge operator: the gasless server records rentPayer == operator and rejects any other fee payer")
	}
	open, err := DerivePaymentChannelOpen(
		params.Request, params.Signer.PublicKey(), params.AuthorizedSigner, params.Options)
	if err != nil {
		return PaymentChannelOpenTransaction{}, err
	}
	blockhash, err := resolveChallengeBlockhash(params.Request, params.RecentBlockhash)
	if err != nil {
		return PaymentChannelOpenTransaction{}, err
	}
	return buildOpenPaymentChannelTx(open, params.Signer, feePayer, blockhash)
}

// PaymentChannelSessionOpen bundles a derived open, the live session tracking
// it, and the open action ready to serialize into a credential.
type PaymentChannelSessionOpen struct {
	// Open holds the fully derived channel parameters, including the channel
	// PDA the session settles against.
	Open PaymentChannelOpen

	// Session is the live tracker that signs cumulative vouchers for the
	// opened channel.
	Session *ActiveSession

	// Action is the open session action, ready to serialize into the payment
	// credential sent back to the server.
	Action intents.SessionAction
}

// PaymentChannelSessionOpenOptions configures CreatePaymentChannelSessionOpener.
type PaymentChannelSessionOpenOptions struct {
	// Open overrides the challenge-derived open defaults.
	Open PaymentChannelOpenOptions

	// Signature is the open confirmation signature. Defaults to
	// PendingServerSignature when the operator broadcasts.
	Signature *string

	// Cumulative resumes the session watermark. Defaults to zero.
	Cumulative *uint64

	// ExpiresAt sets the voucher expiry. Defaults to
	// intents.DefaultSessionExpiresAt.
	ExpiresAt *int64
}

// ServerOpenedPaymentChannelSessionOpenOptions configures
// CreateServerOpenedPaymentChannelSessionOpener.
type ServerOpenedPaymentChannelSessionOpenOptions struct {
	// Open overrides the challenge-derived open defaults.
	Open PaymentChannelOpenOptions

	// Payer overrides the channel payer. Defaults to the challenge operator,
	// which funds the escrow when it opens the channel server-side.
	Payer *solana.PublicKey

	// Signature is the open confirmation signature. Defaults to
	// PendingServerSignature.
	Signature *string

	// Cumulative resumes the session watermark. Defaults to zero.
	Cumulative *uint64

	// ExpiresAt sets the voucher expiry. Defaults to
	// intents.DefaultSessionExpiresAt.
	ExpiresAt *int64
}

// CreatePaymentChannelSessionOpener derives a pull/clientVoucher channel open
// from the challenge, builds the payer-signed open transaction against the
// challenge recentBlockhash, and returns the active session plus the open
// action carrying the transaction for the operator to broadcast.
func CreatePaymentChannelSessionOpener(
	request intents.SessionRequest,
	payerSigner solanatx.Signer,
	sessionSigner VoucherSigner,
	recentBlockhash string,
	options PaymentChannelSessionOpenOptions,
) (PaymentChannelSessionOpen, error) {
	if err := ensureClientVoucherPull(request); err != nil {
		return PaymentChannelSessionOpen{}, err
	}
	authorizedSigner := sessionSigner.PublicKey()
	feePayer, err := parseSessionPubkey(request.Operator, "operator")
	if err != nil {
		return PaymentChannelSessionOpen{}, err
	}
	open, err := DerivePaymentChannelOpen(request, payerSigner.PublicKey(), authorizedSigner, options.Open)
	if err != nil {
		return PaymentChannelSessionOpen{}, err
	}
	blockhash, err := resolveChallengeBlockhash(request, recentBlockhash)
	if err != nil {
		return PaymentChannelSessionOpen{}, err
	}
	tx, err := buildOpenPaymentChannelTx(open, payerSigner, feePayer, blockhash)
	if err != nil {
		return PaymentChannelSessionOpen{}, err
	}
	session := newConfiguredSession(open.ChannelID, sessionSigner, options.Cumulative, options.ExpiresAt)
	signature := PendingServerSignature
	if options.Signature != nil {
		signature = *options.Signature
	}
	action := intents.NewOpenAction(
		open.OpenPayload(intents.SessionModePull, signature).WithTransaction(tx.Transaction))

	return PaymentChannelSessionOpen{Open: open, Session: session, Action: action}, nil
}

// CreateServerOpenedPaymentChannelSessionOpener derives a pull/clientVoucher
// channel open the operator funds and broadcasts entirely server-side: no
// transaction is attached and the signature defaults to
// PendingServerSignature.
func CreateServerOpenedPaymentChannelSessionOpener(
	request intents.SessionRequest,
	sessionSigner VoucherSigner,
	options ServerOpenedPaymentChannelSessionOpenOptions,
) (PaymentChannelSessionOpen, error) {
	if err := ensureClientVoucherPull(request); err != nil {
		return PaymentChannelSessionOpen{}, err
	}
	var payer solana.PublicKey
	if options.Payer != nil {
		payer = *options.Payer
	} else {
		var err error
		payer, err = parseSessionPubkey(request.Operator, "operator")
		if err != nil {
			return PaymentChannelSessionOpen{}, err
		}
	}
	authorizedSigner := sessionSigner.PublicKey()
	open, err := DerivePaymentChannelOpen(request, payer, authorizedSigner, options.Open)
	if err != nil {
		return PaymentChannelSessionOpen{}, err
	}
	session := newConfiguredSession(open.ChannelID, sessionSigner, options.Cumulative, options.ExpiresAt)
	signature := PendingServerSignature
	if options.Signature != nil {
		signature = *options.Signature
	}
	action := intents.NewOpenAction(open.OpenPayload(intents.SessionModePull, signature))

	return PaymentChannelSessionOpen{Open: open, Session: session, Action: action}, nil
}

// NewEphemeralSessionSigner generates a fresh in-memory keypair to use as a
// session authorizedSigner. Session voucher keys are ephemeral by design: they
// authorize spend only within one channel's deposit, so generating one per
// session is the production path.
func NewEphemeralSessionSigner() (VoucherSigner, error) {
	key, err := solana.NewRandomPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate session signer: %w", err)
	}
	return key, nil
}

// buildOpenPaymentChannelTx assembles the single-instruction legacy open
// transaction with the given fee payer and partially signs it with the payer
// wallet, leaving the fee-payer slot zeroed for the operator.
func buildOpenPaymentChannelTx(
	open PaymentChannelOpen,
	payerSigner solanatx.Signer,
	feePayer solana.PublicKey,
	recentBlockhash solana.Hash,
) (PaymentChannelOpenTransaction, error) {
	openParams := open.OpenChannelParams()
	// OpenChannelParams already sets RentPayer to the challenge operator. Pin
	// it to the actual fee payer in scope so a caller-supplied FeePayer that
	// funds rent (and co-signs as fee payer) stays the recorded rentPayer;
	// when feePayer is the operator this is a no-op.
	openParams.RentPayer = feePayer
	ix, err := paymentchannels.BuildOpenInstruction(openParams)
	if err != nil {
		return PaymentChannelOpenTransaction{}, err
	}
	tx, err := solana.NewTransaction(
		[]solana.Instruction{ix},
		recentBlockhash,
		solana.TransactionPayer(feePayer),
	)
	if err != nil {
		return PaymentChannelOpenTransaction{}, fmt.Errorf("build payment-channel open transaction: %w", err)
	}
	if err := solanatx.SignTransaction(tx, payerSigner); err != nil {
		return PaymentChannelOpenTransaction{}, fmt.Errorf("payment-channel open signing failed: %w", err)
	}
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		return PaymentChannelOpenTransaction{}, fmt.Errorf("payment-channel open tx serialization failed: %w", err)
	}
	return PaymentChannelOpenTransaction{ChannelID: open.ChannelID, Transaction: encoded}, nil
}

// ensureClientVoucherPull rejects challenges that do not advertise pull mode
// with the clientVoucher strategy, the only combination these openers serve.
func ensureClientVoucherPull(request intents.SessionRequest) error {
	pull := false
	for _, mode := range request.Modes {
		if mode == intents.SessionModePull {
			pull = true
			break
		}
	}
	if !pull {
		return fmt.Errorf("session challenge does not advertise pull mode")
	}
	if request.PullVoucherStrategy == nil ||
		*request.PullVoucherStrategy != intents.SessionPullVoucherStrategyClientVoucher {
		return fmt.Errorf("session challenge does not advertise pull + clientVoucher")
	}
	return nil
}

// newConfiguredSession creates the opener's ActiveSession with the optional
// resumed cumulative and voucher expiry applied.
func newConfiguredSession(
	channelID solana.PublicKey,
	signer VoucherSigner,
	cumulative *uint64,
	expiresAt *int64,
) *ActiveSession {
	watermark := uint64(0)
	if cumulative != nil {
		watermark = *cumulative
	}
	expiry := intents.DefaultSessionExpiresAt
	if expiresAt != nil {
		expiry = *expiresAt
	}
	return NewActiveSessionWithWatermark(channelID, signer, watermark, expiry)
}

// resolveChallengeBlockhash parses the explicit blockhash, falling back to the
// challenge recentBlockhash so server-prefetched lifetimes are echoed into the
// open transaction without a second RPC round-trip.
func resolveChallengeBlockhash(request intents.SessionRequest, explicit string) (solana.Hash, error) {
	raw := explicit
	if raw == "" && request.RecentBlockhash != nil {
		raw = *request.RecentBlockhash
	}
	if raw == "" {
		return solana.Hash{}, fmt.Errorf("session open requires a recent blockhash: none provided and the challenge omits recentBlockhash")
	}
	hash, err := solana.HashFromBase58(raw)
	if err != nil {
		return solana.Hash{}, fmt.Errorf("invalid recent blockhash %q: %w", raw, err)
	}
	return hash, nil
}

// parseSessionSplits converts challenge splits into instruction distributions.
func parseSessionSplits(splits []intents.SessionSplit) ([]paymentchannels.Distribution, error) {
	recipients := make([]paymentchannels.Distribution, 0, len(splits))
	for _, split := range splits {
		recipient, err := parseSessionPubkey(split.Recipient, "split recipient")
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, paymentchannels.Distribution{
			Recipient: recipient,
			Bps:       split.BPS,
		})
	}
	return recipients, nil
}

// parseSessionPubkey parses a base58 pubkey with a labeled error.
func parseSessionPubkey(value, label string) (solana.PublicKey, error) {
	key, err := solana.PublicKeyFromBase58(value)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("invalid %s: %w", label, err)
	}
	return key, nil
}

// randomSalt draws a random u64 channel salt from the system CSPRNG.
func randomSalt() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("generate channel salt: %w", err)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}
