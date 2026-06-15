package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	token2022 "github.com/gagliardetto/solana-go/programs/token-2022"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

const (
	defaultRealm    = "MPP Payment"
	secretKeyEnvVar = "MPP_SECRET_KEY"
	consumedPrefix  = "solana-charge:consumed:"

	// maxSplits caps the number of secondary recipients per charge.
	// Matches the limit enforced by every other server SDK (see the
	// rust reference in rust/src/server/charge.rs and the typescript
	// fixture in typescript/packages/mpp/src/server/Charge.ts).
	maxSplits = 8

	// Compute budget caps mirror the Rust reference and the TypeScript
	// server fixture. A credential whose transaction sets a compute unit
	// limit or microlamport price above these caps is rejected before
	// broadcast so the on-chain settlement cannot be steered into a
	// pathological resource footprint.
	maxComputeUnitLimit              uint32 = 200_000
	maxComputeUnitPriceMicroLamports uint64 = 5_000_000
)

// computeBudgetProgramID is the on-chain ID of the ComputeBudget program.
var computeBudgetProgramID = solana.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")

// Config controls server-side challenge generation and credential verification.
type Config struct {
	Recipient      string
	Currency       string
	Decimals       uint8
	Network        string
	RPCURL         string
	SecretKey      string
	Realm          string
	HTML           bool
	FeePayerSigner solanatx.Signer
	Store          core.Store
	RPC            solanatx.RPCClient
}

// ChargeOptions customize challenge generation.
type ChargeOptions struct {
	Description string
	ExternalID  string
	Expires     string
	FeePayer    bool
	// Splits are additional payment transfers embedded in methodDetails.
	Splits []paycore.Split
}

// Mpp is the server-side Solana charge handler.
type Mpp struct {
	rpc            solanatx.RPCClient
	secretKey      string
	realm          string
	recipient      solana.PublicKey
	currency       string
	decimals       uint8
	network        string
	rpcURL         string
	html           bool
	feePayerSigner solanatx.Signer
	store          core.Store
}

// New creates a new server-side handler.
func New(config Config) (*Mpp, error) {
	if strings.TrimSpace(config.Recipient) == "" {
		return nil, core.NewError(core.ErrCodeInvalidConfig, "recipient is required")
	}
	recipient, err := solana.PublicKeyFromBase58(config.Recipient)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeInvalidConfig, "invalid recipient pubkey", err)
	}
	if config.SecretKey == "" {
		config.SecretKey = os.Getenv(secretKeyEnvVar)
	}
	if config.SecretKey == "" {
		return nil, core.NewError(core.ErrCodeInvalidConfig, "missing secret key")
	}
	if config.Currency == "" {
		config.Currency = "USDC"
	}
	if config.Decimals == 0 {
		config.Decimals = 6
	}
	if config.Network == "" {
		config.Network = "mainnet-beta"
	}
	if config.Realm == "" {
		config.Realm = DetectRealm()
	}
	rpcURL := config.RPCURL
	if rpcURL == "" {
		rpcURL = paycore.DefaultRPCURL(config.Network)
	}
	if config.RPC == nil {
		config.RPC = rpc.New(rpcURL)
	}
	if config.Store == nil {
		config.Store = core.NewMemoryStore()
	}
	return &Mpp{
		rpc:            config.RPC,
		secretKey:      config.SecretKey,
		realm:          config.Realm,
		recipient:      recipient,
		currency:       config.Currency,
		decimals:       config.Decimals,
		network:        config.Network,
		rpcURL:         rpcURL,
		html:           config.HTML,
		feePayerSigner: config.FeePayerSigner,
		store:          config.Store,
	}, nil
}

// Charge creates a charge challenge from a human-readable amount.
func (m *Mpp) Charge(ctx context.Context, amount string) (core.PaymentChallenge, error) {
	return m.ChargeWithOptions(ctx, amount, ChargeOptions{})
}

// validateChargeOptions rejects an ataCreationRequired split when the
// configured currency is SOL or is a stablecoin symbol rather than a raw
// SPL mint address, matching rust validate_charge_options
// (charge.rs:307-335). Idempotent ATA creation is only meaningful for an
// SPL token whose mint is known to the verifier.
func (m *Mpp) validateChargeOptions(options ChargeOptions) error {
	hasATACreation := false
	for _, split := range options.Splits {
		if split.AtaCreationRequired != nil && *split.AtaCreationRequired {
			hasATACreation = true
			break
		}
	}
	if !hasATACreation {
		return nil
	}
	if isNativeSOL(m.currency) {
		return core.NewError(core.ErrCodeInvalidPayload, "ataCreationRequired requires an SPL token currency")
	}
	// resolve_stablecoin_mint(currency) == currency means the currency is
	// already a raw mint address (symbols resolve to a different mint).
	if paycore.ResolveMint(m.currency, m.network) != m.currency {
		return core.NewError(core.ErrCodeInvalidPayload, "ataCreationRequired requires currency to be an SPL token mint address")
	}
	if _, err := solana.PublicKeyFromBase58(m.currency); err != nil {
		return core.NewError(core.ErrCodeInvalidPayload, fmt.Sprintf("ataCreationRequired requires a valid SPL token mint address: %v", err))
	}
	return nil
}

// ChargeWithOptions creates a challenge with optional fields.
func (m *Mpp) ChargeWithOptions(ctx context.Context, amount string, options ChargeOptions) (core.PaymentChallenge, error) {
	if err := m.validateChargeOptions(options); err != nil {
		return core.PaymentChallenge{}, err
	}
	baseUnits, err := intents.ParseUnits(amount, m.decimals)
	if err != nil {
		return core.PaymentChallenge{}, err
	}
	details := paycore.MethodDetails{
		Network: m.network,
	}
	if !isNativeSOL(m.currency) {
		details.Decimals = &m.decimals
		if paycore.StablecoinSymbol(m.currency) != "" {
			details.TokenProgram = paycore.DefaultTokenProgramForCurrency(m.currency, m.network)
		}
	}
	if options.FeePayer || m.feePayerSigner != nil {
		enabled := true
		details.FeePayer = &enabled
		if m.feePayerSigner != nil {
			details.FeePayerKey = m.feePayerSigner.PublicKey().String()
		}
	}
	if len(options.Splits) > 0 {
		details.Splits = options.Splits
	}
	if out, err := m.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed); err == nil && out != nil && out.Value != nil {
		details.RecentBlockhash = out.Value.Blockhash.String()
	}
	request, err := core.NewBase64URLJSONValue(intents.ChargeRequest{
		Amount:        baseUnits,
		Currency:      m.currency,
		Recipient:     m.recipient.String(),
		Description:   options.Description,
		ExternalID:    options.ExternalID,
		MethodDetails: details,
	})
	if err != nil {
		return core.PaymentChallenge{}, err
	}
	expires := options.Expires
	if expires == "" {
		expires = core.Minutes(5)
	}
	return core.NewChallengeWithSecretFull(
		m.secretKey,
		m.realm,
		core.NewMethodName("solana"),
		core.NewIntentName("charge"),
		request,
		expires,
		"",
		options.Description,
		nil,
	), nil
}

// VerifyCredential verifies either a transaction payload or a signature payload.
//
// This is the simple API and is appropriate for servers that only gate a single
// route. Servers that gate multiple routes at different prices on the same
// secret key MUST use VerifyCredentialWithExpected so the route's expected
// amount is compared to the credential's claimed amount; otherwise a
// credential issued for a cheaper route can be replayed at an expensive one.
//
// Even on the simple API, a Tier-2 pinned-field check enforces that the
// credential's method/intent/realm/currency/recipient match this Mpp's
// configuration — so cross-route replay across instances with different
// recipients/currencies is blocked, and only the per-call amount remains
// unpinned (which is what VerifyCredentialWithExpected covers).
func (m *Mpp) VerifyCredential(ctx context.Context, credential core.PaymentCredential) (core.Receipt, error) {
	request, details, payload, err := m.verifyChallengeAndDecode(credential)
	if err != nil {
		return core.Receipt{}, err
	}
	return m.verifyPayload(ctx, credential, request, details, payload)
}

// VerifyCredentialWithExpected verifies a credential against the route's
// expected charge request. The amount, currency, and recipient on the
// credential's claimed challenge must match `expected`; afterward, settlement
// (transaction broadcast and on-chain checks) runs against `expected` —
// not against the credential's claims — so a credential built for a different
// route's request cannot succeed even if its other fields line up.
func (m *Mpp) VerifyCredentialWithExpected(
	ctx context.Context,
	credential core.PaymentCredential,
	expected intents.ChargeRequest,
) (core.Receipt, error) {
	credRequest, _, payload, err := m.verifyChallengeAndDecode(credential)
	if err != nil {
		return core.Receipt{}, err
	}
	if credRequest.Amount != expected.Amount {
		return core.Receipt{}, core.NewError(
			core.ErrCodeAmountMismatch,
			fmt.Sprintf("amount mismatch: credential has %s but endpoint expects %s",
				credRequest.Amount, expected.Amount),
		)
	}
	if credRequest.Currency != expected.Currency {
		return core.Receipt{}, core.NewError(
			core.ErrCodeChallengeRouteMismatch,
			fmt.Sprintf("currency mismatch: credential has %s but endpoint expects %s",
				credRequest.Currency, expected.Currency),
		)
	}
	if credRequest.Recipient != expected.Recipient {
		return core.Receipt{}, core.NewError(
			core.ErrCodeRecipientMismatch,
			"recipient mismatch: credential was issued for a different recipient",
		)
	}
	expectedDetails, err := decodeMethodDetails(expected.MethodDetails)
	if err != nil {
		return core.Receipt{}, err
	}
	return m.verifyPayload(ctx, credential, expected, expectedDetails, payload)
}

// verifyChallengeAndDecode runs Tier-1 (HMAC + expiry) and Tier-2 (pinned-field
// backstop) checks, then returns the credential-decoded request, method
// details, and payload for downstream settlement.
func (m *Mpp) verifyChallengeAndDecode(
	credential core.PaymentCredential,
) (intents.ChargeRequest, paycore.MethodDetails, paycore.CredentialPayload, error) {
	challenge := core.PaymentChallenge{
		ID:      credential.Challenge.ID,
		Realm:   credential.Challenge.Realm,
		Method:  credential.Challenge.Method,
		Intent:  credential.Challenge.Intent,
		Request: credential.Challenge.Request,
		Expires: credential.Challenge.Expires,
		Digest:  credential.Challenge.Digest,
		Opaque:  credential.Challenge.Opaque,
	}
	if !challenge.Verify(m.secretKey) {
		return intents.ChargeRequest{}, paycore.MethodDetails{}, paycore.CredentialPayload{},
			core.NewError(core.ErrCodeChallengeMismatch, "challenge ID mismatch")
	}
	if challenge.IsExpired(time.Now()) {
		return intents.ChargeRequest{}, paycore.MethodDetails{}, paycore.CredentialPayload{},
			core.NewError(core.ErrCodeChallengeExpired, fmt.Sprintf("challenge expired at %s", challenge.Expires))
	}
	var request intents.ChargeRequest
	if err := challenge.Request.Decode(&request); err != nil {
		return intents.ChargeRequest{}, paycore.MethodDetails{}, paycore.CredentialPayload{}, err
	}
	if err := m.verifyPinnedFields(credential, request); err != nil {
		return intents.ChargeRequest{}, paycore.MethodDetails{}, paycore.CredentialPayload{}, err
	}
	details, err := decodeMethodDetails(request.MethodDetails)
	if err != nil {
		return intents.ChargeRequest{}, paycore.MethodDetails{}, paycore.CredentialPayload{}, err
	}
	var payload paycore.CredentialPayload
	if err := credential.PayloadAs(&payload); err != nil {
		return intents.ChargeRequest{}, paycore.MethodDetails{}, paycore.CredentialPayload{}, err
	}
	return request, details, payload, nil
}

// verifyPinnedFields is the Tier-2 backstop. After Tier-1 (HMAC) confirms the
// challenge was issued by this server, this compares fields that are fixed at
// Mpp construction time. The HMAC ID is computed using the server's own realm
// (not the echoed one), so a tampered echoed realm/method/intent would
// otherwise pass HMAC and reach settlement unflagged. Currency and recipient
// live inside the HMAC'd request bytes, but pinning them here catches
// cross-instance replay where two Mpps share a secret but differ in
// recipient/currency.
func (m *Mpp) verifyPinnedFields(credential core.PaymentCredential, request intents.ChargeRequest) error {
	const methodName = "solana"
	if string(credential.Challenge.Method) != methodName {
		return core.NewError(core.ErrCodeChallengeRouteMismatch,
			fmt.Sprintf("credential method %q does not match this server (expected %q)",
				credential.Challenge.Method, methodName))
	}
	if !credential.Challenge.Intent.IsCharge() {
		return core.NewError(core.ErrCodeChallengeRouteMismatch,
			fmt.Sprintf("credential intent %q is not a charge", credential.Challenge.Intent))
	}
	if credential.Challenge.Realm != m.realm {
		return core.NewError(core.ErrCodeChallengeRouteMismatch,
			fmt.Sprintf("credential realm %q does not match this server (expected %q)",
				credential.Challenge.Realm, m.realm))
	}
	if request.Currency != m.currency {
		return core.NewError(core.ErrCodeChallengeRouteMismatch,
			fmt.Sprintf("credential currency %q does not match this server (expected %q)",
				request.Currency, m.currency))
	}
	if request.Recipient != m.recipient.String() {
		return core.NewError(core.ErrCodeRecipientMismatch,
			"credential recipient does not match this server")
	}
	return nil
}

func decodeMethodDetails(value any) (paycore.MethodDetails, error) {
	if value == nil {
		return paycore.MethodDetails{}, nil
	}
	var details paycore.MethodDetails
	raw, err := json.Marshal(value)
	if err != nil {
		return paycore.MethodDetails{}, err
	}
	if err := json.Unmarshal(raw, &details); err != nil {
		return paycore.MethodDetails{}, err
	}
	return details, nil
}

func (m *Mpp) verifyPayload(
	ctx context.Context,
	credential core.PaymentCredential,
	request intents.ChargeRequest,
	details paycore.MethodDetails,
	payload paycore.CredentialPayload,
) (core.Receipt, error) {
	switch payload.Type {
	case "transaction":
		return m.verifyTransaction(ctx, credential, request, details, payload)
	case "signature":
		if details.FeePayer != nil && *details.FeePayer {
			return core.Receipt{}, core.NewError(core.ErrCodeInvalidPayload, `type="signature" credentials cannot be used with fee sponsorship`)
		}
		return m.verifySignature(ctx, credential, request, details, payload)
	default:
		return core.Receipt{}, core.NewError(core.ErrCodeInvalidPayload, "missing or invalid payload type")
	}
}

func (m *Mpp) verifyTransaction(
	ctx context.Context,
	credential core.PaymentCredential,
	request intents.ChargeRequest,
	details paycore.MethodDetails,
	payload paycore.CredentialPayload,
) (core.Receipt, error) {
	if payload.Transaction == "" {
		return core.Receipt{}, core.NewError(core.ErrCodeMissingTransaction, "missing transaction data in credential payload")
	}
	if err := validateSplitsCount(details.Splits); err != nil {
		return core.Receipt{}, err
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		return core.Receipt{}, err
	}
	// Accept legacy and v0 transactions with only static account keys, but
	// reject a v0 message carrying address lookup tables: the verifier
	// cannot resolve ALT-referenced accounts locally, so a transfer hidden
	// behind a lookup table could not be checked. Mirrors rust
	// reject_address_lookup_tables (charge.rs:1213-1225), called from the
	// pre-broadcast verification path.
	if len(tx.Message.AddressTableLookups) > 0 {
		return core.Receipt{}, core.NewError(core.ErrCodeInvalidPayload, "v0 transactions with address lookup tables are not supported")
	}
	if err := validateComputeBudgetInstructions(tx); err != nil {
		return core.Receipt{}, err
	}
	// Reject up-front if the client signed against the wrong network
	// (e.g. mainnet keypair pointed at a sandbox-configured server, or
	// vice versa). Cheaper and clearer than letting the broadcast fail
	// with a confusing "transaction not found" error from the verifier.
	if err := CheckNetworkBlockhash(m.network, tx.Message.RecentBlockhash.String()); err != nil {
		return core.Receipt{}, err
	}
	// Verify the transaction's transfer instructions BEFORE the server co-signs
	// or broadcasts. The on-chain `verifyOnChain` check still runs after
	// confirmation as defense-in-depth, but inspecting the decoded instructions
	// up-front prevents a malformed or tampered credential from spending the
	// fee payer's lamports on a doomed broadcast. Mirrors the Rust reference
	// (`verify_versioned_transaction_pre_broadcast` in
	// rust/src/server/charge.rs).
	amount, err := request.ParseAmount()
	if err != nil {
		return core.Receipt{}, err
	}
	if err := verifyTransfersAgainstChallenge(tx, amount, request.Currency, m.recipient, request.ExternalID, details); err != nil {
		return core.Receipt{}, err
	}
	if m.feePayerSigner != nil {
		if err := solanatx.SignTransaction(tx, m.feePayerSigner); err != nil {
			return core.Receipt{}, err
		}
	}
	if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() {
		return core.Receipt{}, core.NewError(core.ErrCodeMissingSignature, "transaction is missing a primary signature")
	}
	consumedKey := consumedPrefix + tx.Signatures[0].String()
	inserted, err := m.store.PutIfAbsent(ctx, consumedKey, true)
	if err != nil {
		return core.Receipt{}, err
	}
	if !inserted {
		return core.Receipt{}, core.NewError(core.ErrCodeSignatureConsumed, "transaction signature already consumed")
	}
	cleanupConsumed := true
	defer func() {
		if cleanupConsumed {
			// Detach cancellation but keep trace/values so rollback still
			// runs when the caller's context is already canceled.
			_ = m.store.Delete(context.WithoutCancel(ctx), consumedKey)
		}
	}()
	if err := solanatx.SimulateTransaction(ctx, m.rpc, tx); err != nil {
		return core.Receipt{}, core.WrapError(core.ErrCodeSimulationFailed, "simulate transaction", err)
	}
	signature, err := solanatx.SendTransaction(ctx, m.rpc, tx)
	if err != nil {
		return core.Receipt{}, core.WrapError(core.ErrCodeRPC, "send transaction", err)
	}
	// The RPC accepted the broadcast. From here the transaction may land
	// on-chain even if confirmation polling or the on-chain re-verification
	// below times out. Pin the replay marker NOW so a confirmation/verify
	// timeout does not let the deferred rollback delete it and reopen the
	// same credential for a second submission while the original lands and
	// double-pays. Mirrors the rust reference, which consumes the signature
	// after broadcast and never deletes it on a confirmation timeout.
	cleanupConsumed = false
	if err := solanatx.WaitForConfirmation(ctx, m.rpc, signature); err != nil {
		return core.Receipt{}, core.WrapError(core.ErrCodeTransactionFailed, "confirm transaction", err)
	}
	if err := m.verifyOnChain(ctx, signature, request, details); err != nil {
		return core.Receipt{}, err
	}
	return successReceipt(signature.String(), credential.Challenge.ID, request.ExternalID), nil
}

func (m *Mpp) verifySignature(
	ctx context.Context,
	credential core.PaymentCredential,
	request intents.ChargeRequest,
	details paycore.MethodDetails,
	payload paycore.CredentialPayload,
) (core.Receipt, error) {
	if payload.Signature == "" {
		return core.Receipt{}, core.NewError(core.ErrCodeMissingSignature, "missing signature in credential payload")
	}
	signature, err := solana.SignatureFromBase58(payload.Signature)
	if err != nil {
		return core.Receipt{}, err
	}
	// Push mode references an already-landed transaction, so verify it
	// on-chain BEFORE consuming the replay marker, and never delete the
	// marker once consumed. Mirrors rust verify_push -> consume_signature
	// (charge.rs:563-595): a verify failure must not burn the marker
	// (nothing was committed), and a successful verify must consume it
	// durably so the same landed signature cannot be replayed.
	if err := m.verifyOnChain(ctx, signature, request, details); err != nil {
		return core.Receipt{}, err
	}
	inserted, err := m.store.PutIfAbsent(ctx, consumedPrefix+payload.Signature, true)
	if err != nil {
		return core.Receipt{}, err
	}
	if !inserted {
		return core.Receipt{}, core.NewError(core.ErrCodeSignatureConsumed, "transaction signature already consumed")
	}
	return successReceipt(payload.Signature, credential.Challenge.ID, request.ExternalID), nil
}

func (m *Mpp) verifyOnChain(ctx context.Context, signature solana.Signature, request intents.ChargeRequest, details paycore.MethodDetails) error {
	tx, meta, err := solanatx.FetchTransaction(ctx, m.rpc, signature)
	if err != nil {
		return core.WrapError(core.ErrCodeTransactionNotFound, "transaction not found or not yet confirmed", err)
	}
	if meta != nil && meta.Err != nil {
		return core.NewError(core.ErrCodeTransactionFailed, fmt.Sprintf("transaction failed on-chain: %v", meta.Err))
	}
	amount, err := request.ParseAmount()
	if err != nil {
		return err
	}
	return verifyTransfersAgainstChallenge(tx, amount, request.Currency, m.recipient, request.ExternalID, details)
}

func verifyTransfersAgainstChallenge(tx *solana.Transaction, amount uint64, currency string, recipient solana.PublicKey, externalID string, details paycore.MethodDetails) error {
	expected, err := buildExpectedTransfers(amount, recipient, details)
	if err != nil {
		return err
	}
	matched := make([]bool, len(tx.Message.Instructions))
	if isNativeSOL(currency) {
		for _, want := range expected {
			found := false
			for index, compiled := range tx.Message.Instructions {
				if matched[index] {
					continue
				}
				programID, err := resolveProgramID(tx, compiled.ProgramIDIndex)
				if err != nil {
					return err
				}
				if !programID.Equals(solana.SystemProgramID) {
					continue
				}
				accounts, err := compiled.ResolveInstructionAccounts(&tx.Message)
				if err != nil {
					return err
				}
				decoded, err := system.DecodeInstruction(accounts, []byte(compiled.Data))
				if err != nil {
					continue
				}
				transfer, ok := decoded.Impl.(*system.Transfer)
				if !ok || transfer.Lamports == nil {
					continue
				}
				if transfer.GetRecipientAccount().PublicKey.Equals(want.recipient) && *transfer.Lamports == want.amount {
					// The configured fee payer must not fund the SOL payment
					// transfer, matching rust verify_sol_transfer_instructions
					// (charge.rs:1525-1528). Hard reject, not skip.
					if fp := feePayerKey(details); fp != nil && transfer.GetFundingAccount().PublicKey.Equals(*fp) {
						return core.NewError(core.ErrCodeInvalidPayload, "fee payer cannot fund the SOL payment transfer")
					}
					matched[index] = true
					found = true
					break
				}
			}
			if !found {
				return core.NewError(core.ErrCodeNoTransfer, fmt.Sprintf("no matching SOL transfer for %s", want.recipient))
			}
		}
		if err := verifyMemoInstructions(tx, matched, externalID, details.Splits); err != nil {
			return err
		}
		// Native SOL payments never carry a token mint, so ATA-create
		// instructions are not allowed and there is no token program to pin.
		return validateInstructionAllowlist(tx, matched, allowlistParams{})
	}
	resolvedMint := paycore.ResolveMint(currency, details.Network)
	// ataCreationRequired splits demand a raw SPL mint-address currency:
	// when any split required an ATA-create but the currency resolved to a
	// different mint (i.e. it was a symbol), reject, matching the rust
	// verify guard (charge.rs:1120-1124).
	requiredOwners, err := requiredATAOwners(details.Splits)
	if err != nil {
		return err
	}
	if len(requiredOwners) > 0 && currency != resolvedMint {
		return core.NewError(core.ErrCodeInvalidPayload, "ataCreationRequired requires currency to be an SPL token mint address")
	}
	mint := solana.MustPublicKeyFromBase58(resolvedMint)
	expectedProgram := solana.TokenProgramID
	tokenProgram := details.TokenProgram
	if tokenProgram == "" && paycore.StablecoinSymbol(currency) != "" {
		tokenProgram = paycore.DefaultTokenProgramForCurrency(currency, details.Network)
	}
	if tokenProgram == paycore.Token2022Program {
		expectedProgram = solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	}
	type tokenExpectation struct {
		recipient solana.PublicKey
		ata       solana.PublicKey
		amount    uint64
	}
	tokenExpected := make([]tokenExpectation, 0, len(expected))
	for _, want := range expected {
		ata, err := solanatx.FindAssociatedTokenAddressWithProgram(want.recipient, mint, expectedProgram)
		if err != nil {
			return err
		}
		tokenExpected = append(tokenExpected, tokenExpectation{
			recipient: want.recipient,
			ata:       ata,
			amount:    want.amount,
		})
	}
	for _, want := range tokenExpected {
		found := false
		for index, compiled := range tx.Message.Instructions {
			if matched[index] {
				continue
			}
			programID, err := resolveProgramID(tx, compiled.ProgramIDIndex)
			if err != nil {
				return err
			}
			if !programID.Equals(expectedProgram) {
				continue
			}
			accounts, err := compiled.ResolveInstructionAccounts(&tx.Message)
			if err != nil {
				return err
			}
			var (
				transferAmount uint64
				transferMint   solana.PublicKey
				transferDest   solana.PublicKey
				transferSource solana.PublicKey
				transferAuth   solana.PublicKey
				transferDec    *uint8
			)
			if expectedProgram.Equals(solana.TokenProgramID) {
				decoded, err := token.DecodeInstruction(accounts, []byte(compiled.Data))
				if err != nil {
					continue
				}
				transfer, ok := decoded.Impl.(*token.TransferChecked)
				if !ok || transfer.Amount == nil {
					continue
				}
				transferAmount = *transfer.Amount
				transferMint = transfer.GetMintAccount().PublicKey
				transferDest = transfer.GetDestinationAccount().PublicKey
				transferSource = transfer.GetSourceAccount().PublicKey
				transferAuth = transfer.GetOwnerAccount().PublicKey
				transferDec = transfer.Decimals
			} else {
				decoded, err := token2022.DecodeInstruction(accounts, []byte(compiled.Data))
				if err != nil {
					continue
				}
				transfer, ok := decoded.Impl.(*token2022.TransferChecked)
				if !ok || transfer.Amount == nil {
					continue
				}
				transferAmount = *transfer.Amount
				transferMint = transfer.GetMintAccount().PublicKey
				transferDest = transfer.GetDestinationAccount().PublicKey
				transferSource = transfer.GetSourceAccount().PublicKey
				transferAuth = transfer.GetOwnerAccount().PublicKey
				transferDec = transfer.Decimals
			}
			if !transferMint.Equals(mint) || transferAmount != want.amount {
				continue
			}
			// transferChecked decimals byte must match the challenge-pinned
			// decimals, matching rust ix.data[9] guard (charge.rs:1623-1624).
			if details.Decimals != nil && (transferDec == nil || *transferDec != *details.Decimals) {
				continue
			}
			// The configured fee payer must not authorize or fund the
			// payment transfer, matching rust verify_spl_transfer_instructions
			// (charge.rs:1642-1658). Both are hard rejects, not skips: a tx
			// that routes payment authority/funding through the fee payer is
			// malicious regardless of any other matching transfer.
			if fp := feePayerKey(details); fp != nil {
				if transferAuth.Equals(*fp) {
					return core.NewError(core.ErrCodeInvalidPayload, "fee payer cannot authorize the SPL payment transfer")
				}
				feePayerATA, err := solanatx.FindAssociatedTokenAddressWithProgram(*fp, mint, expectedProgram)
				if err != nil {
					return err
				}
				if transferSource.Equals(feePayerATA) {
					return core.NewError(core.ErrCodeInvalidPayload, "fee payer token account cannot fund the SPL payment transfer")
				}
			}
			if transferDest.Equals(want.ata) {
				matched[index] = true
				found = true
				break
			}
		}
		if !found {
			return core.NewError(core.ErrCodeNoTransfer, fmt.Sprintf("no matching token transfer for %s", want.recipient))
		}
	}
	if err := verifyMemoInstructions(tx, matched, externalID, details.Splits); err != nil {
		return err
	}
	allowedOwners := make([]solana.PublicKey, 0, len(tokenExpected))
	for _, want := range tokenExpected {
		allowedOwners = append(allowedOwners, want.recipient)
	}
	return validateInstructionAllowlist(tx, matched, allowlistParams{
		expectedMint:         &mint,
		expectedTokenProgram: &expectedProgram,
		allowedATAOwners:     allowedOwners,
		feePayer:             feePayerKey(details),
		requiredATAOwners:    requiredOwners,
	})
}

// requiredATAOwners returns the split recipients whose challenge pinned
// ataCreationRequired=true. These owners must each have an idempotent
// ATA-create in the settled transaction. Mirrors the rust reference's
// expected_ata_creation_policy required_owners set: only split recipients
// (never the primary recipient) can be required, and only when the split
// explicitly opted in via ataCreationRequired.
func requiredATAOwners(splits []paycore.Split) ([]solana.PublicKey, error) {
	owners := make([]solana.PublicKey, 0, len(splits))
	for _, split := range splits {
		if split.AtaCreationRequired == nil || !*split.AtaCreationRequired {
			continue
		}
		owner, err := solana.PublicKeyFromBase58(split.Recipient)
		if err != nil {
			return nil, err
		}
		owners = append(owners, owner)
	}
	return owners, nil
}

// feePayerKey returns the configured fee payer pubkey when the challenge
// pinned one (fee-payer sponsorship flow), else nil. Used to enforce that
// an ATA-create instruction is funded by the fee payer, mirroring the rust
// reference (validate_instruction_allowlist's expected_ata_payer).
func feePayerKey(details paycore.MethodDetails) *solana.PublicKey {
	if details.FeePayerKey == "" {
		return nil
	}
	key, err := solana.PublicKeyFromBase58(details.FeePayerKey)
	if err != nil {
		return nil
	}
	return &key
}

type expectedMemo struct {
	label string
	value string
}

func buildExpectedMemos(externalID string, splits []paycore.Split) []expectedMemo {
	expected := make([]expectedMemo, 0, 1+len(splits))
	if externalID != "" {
		expected = append(expected, expectedMemo{label: "externalId", value: externalID})
	}
	for _, split := range splits {
		if split.Memo != "" {
			expected = append(expected, expectedMemo{label: "split", value: split.Memo})
		}
	}
	return expected
}

func verifyMemoInstructions(tx *solana.Transaction, matched []bool, externalID string, splits []paycore.Split) error {
	memoProgram := solana.MustPublicKeyFromBase58(paycore.MemoProgram)
	for _, want := range buildExpectedMemos(externalID, splits) {
		if len([]byte(want.value)) > 566 {
			return core.NewError(core.ErrCodeInvalidPayload, "memo cannot exceed 566 bytes")
		}
		found := false
		for index, compiled := range tx.Message.Instructions {
			if matched[index] {
				continue
			}
			programID, err := resolveProgramID(tx, compiled.ProgramIDIndex)
			if err != nil {
				return err
			}
			if !programID.Equals(memoProgram) {
				continue
			}
			if string(compiled.Data) == want.value {
				matched[index] = true
				found = true
				break
			}
		}
		if !found {
			return core.NewError(core.ErrCodeInvalidPayload, fmt.Sprintf("no memo instruction found for %s memo %q", want.label, want.value))
		}
	}

	for index, compiled := range tx.Message.Instructions {
		if matched[index] {
			continue
		}
		programID, err := resolveProgramID(tx, compiled.ProgramIDIndex)
		if err != nil {
			return err
		}
		if programID.Equals(memoProgram) {
			return core.NewError(core.ErrCodeInvalidPayload, "unexpected Memo Program instruction in payment transaction")
		}
	}
	return nil
}

// allowlistParams carries the pinned context the strict instruction
// allowlist validates ATA-create instructions against. All fields are
// optional: for native SOL payments they are zero, which forbids ATA
// creation entirely.
type allowlistParams struct {
	// expectedMint is the charge currency mint; ATA-create instructions are
	// rejected when nil (native SOL).
	expectedMint *solana.PublicKey
	// expectedTokenProgram pins the token program an ATA-create must use.
	expectedTokenProgram *solana.PublicKey
	// allowedATAOwners are the payment recipients (primary + splits) an
	// ATA-create instruction may create an account for.
	allowedATAOwners []solana.PublicKey
	// feePayer, when non-nil, is the configured sponsor; an ATA-create must
	// be funded by it. When nil the transaction fee payer (first account
	// key) is used as the expected ATA payer.
	feePayer *solana.PublicKey
	// requiredATAOwners are split recipients whose challenge pinned
	// ataCreationRequired=true. The transaction MUST contain an idempotent
	// ATA-create for each of them; a missing one is rejected. Mirrors the
	// rust reference required_ata_owners invariant.
	requiredATAOwners []solana.PublicKey
}

// validateInstructionAllowlist is the strict post-match gate. After the
// expected transfer and memo instructions have been matched, every
// remaining instruction is checked against a closed allowlist:
//
//   - ComputeBudget: allowed; caps are enforced earlier in
//     validateComputeBudgetInstructions.
//   - Matched payment/memo instructions: already accounted for via `matched`.
//   - Associated Token Program: only an idempotent ATA-create for an allowed
//     owner/mint/token-program funded by the expected payer is permitted.
//   - Everything else (System, Token, Token-2022, ATA non-idempotent,
//     unknown programs): rejected.
//
// Without this gate a fee-payer route would co-sign and broadcast extra
// System/Token/ATA/other-program instructions appended after the expected
// payment. Mirrors the rust reference validate_instruction_allowlist in
// rust/crates/mpp/src/server/charge.rs.
func validateInstructionAllowlist(tx *solana.Transaction, matched []bool, params allowlistParams) error {
	memoProgram := solana.MustPublicKeyFromBase58(paycore.MemoProgram)
	systemProgram := solana.MustPublicKeyFromBase58(paycore.SystemProgram)
	tokenProgram := solana.MustPublicKeyFromBase58(paycore.TokenProgram)
	token2022Program := solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	ataProgram := solana.MustPublicKeyFromBase58(paycore.AssociatedTokenProgram)

	if len(tx.Message.AccountKeys) == 0 {
		return core.NewError(core.ErrCodeInvalidPayload, "transaction has no fee payer")
	}
	expectedATAPayer := tx.Message.AccountKeys[0]
	if params.feePayer != nil {
		expectedATAPayer = *params.feePayer
	}
	createdATAOwners := make([]solana.PublicKey, 0, len(params.requiredATAOwners))

	for index, compiled := range tx.Message.Instructions {
		programID, err := resolveProgramID(tx, compiled.ProgramIDIndex)
		if err != nil {
			return err
		}
		switch {
		case programID.Equals(computeBudgetProgramID):
			// Caps already enforced in validateComputeBudgetInstructions;
			// allow it through unconditionally here.
			continue
		case programID.Equals(memoProgram):
			if matched[index] {
				continue
			}
			return core.NewError(core.ErrCodeInvalidPayload, "unexpected Memo Program instruction in payment transaction")
		case programID.Equals(systemProgram):
			if matched[index] {
				continue
			}
			return core.NewError(core.ErrCodeInvalidPayload, "unexpected System Program instruction in payment transaction")
		case programID.Equals(tokenProgram) || programID.Equals(token2022Program):
			if matched[index] {
				continue
			}
			return core.NewError(core.ErrCodeInvalidPayload, "unexpected Token Program instruction in payment transaction")
		case programID.Equals(ataProgram):
			owner, err := validateCreateATAIdempotentInstruction(tx, compiled, params, expectedATAPayer)
			if err != nil {
				return err
			}
			createdATAOwners = append(createdATAOwners, owner)
			continue
		default:
			return core.NewError(core.ErrCodeInvalidPayload,
				fmt.Sprintf("unexpected program instruction in payment transaction: %s", programID))
		}
	}

	// Every owner the challenge pinned as ataCreationRequired must have a
	// matching idempotent ATA-create in the transaction. Mirrors the rust
	// reference's required_ata_owners check; without it a split recipient
	// whose ATA does not yet exist would have its transfer fail on-chain
	// (or, on the pull path, force a doomed broadcast).
	for _, owner := range params.requiredATAOwners {
		if !ownerAllowed(owner, createdATAOwners) {
			return core.NewError(core.ErrCodeInvalidPayload,
				fmt.Sprintf("missing required ATA creation instruction for split recipient %s", owner))
		}
	}
	return nil
}

// validateCreateATAIdempotentInstruction enforces that an Associated Token
// Program instruction is a CreateIdempotent (data == [1]) that targets an
// allowed owner, the expected mint and token program, and is funded by the
// expected payer. Mirrors the rust reference
// validate_create_ata_idempotent_instruction.
func validateCreateATAIdempotentInstruction(
	tx *solana.Transaction,
	ix solana.CompiledInstruction,
	params allowlistParams,
	expectedPayer solana.PublicKey,
) (solana.PublicKey, error) {
	if params.expectedMint == nil {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "ATA creation is not allowed for native SOL payments")
	}
	data := []byte(ix.Data)
	if len(data) != 1 || data[0] != 1 {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "only idempotent ATA creation is allowed")
	}
	if len(ix.Accounts) != 6 {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "unexpected ATA creation account layout")
	}
	accountAt := func(pos int, label string) (solana.PublicKey, error) {
		idx := int(ix.Accounts[pos])
		if idx < 0 || idx >= len(tx.Message.AccountKeys) {
			return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload,
				fmt.Sprintf("invalid %s account index", label))
		}
		return tx.Message.AccountKeys[idx], nil
	}
	payer, err := accountAt(0, "ATA payer")
	if err != nil {
		return solana.PublicKey{}, err
	}
	ata, err := accountAt(1, "ATA address")
	if err != nil {
		return solana.PublicKey{}, err
	}
	owner, err := accountAt(2, "ATA owner")
	if err != nil {
		return solana.PublicKey{}, err
	}
	mint, err := accountAt(3, "ATA mint")
	if err != nil {
		return solana.PublicKey{}, err
	}
	systemProgram, err := accountAt(4, "ATA system program")
	if err != nil {
		return solana.PublicKey{}, err
	}
	tokenProgram, err := accountAt(5, "ATA token program")
	if err != nil {
		return solana.PublicKey{}, err
	}
	if !payer.Equals(expectedPayer) {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "ATA payer must match the transaction fee payer")
	}
	if !mint.Equals(*params.expectedMint) {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "ATA creation mint does not match the charge currency")
	}
	if !ownerAllowed(owner, params.allowedATAOwners) {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "ATA creation owner is not authorized by the challenge")
	}
	if !systemProgram.Equals(solana.MustPublicKeyFromBase58(paycore.SystemProgram)) {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "ATA creation must reference the System Program")
	}
	if tokenProgram.String() != paycore.TokenProgram && tokenProgram.String() != paycore.Token2022Program {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "ATA creation uses an unsupported token program")
	}
	if params.expectedTokenProgram != nil && !tokenProgram.Equals(*params.expectedTokenProgram) {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "ATA creation token program does not match methodDetails.tokenProgram")
	}
	expectedATA, err := solanatx.FindAssociatedTokenAddressWithProgram(owner, mint, tokenProgram)
	if err != nil {
		return solana.PublicKey{}, err
	}
	if !ata.Equals(expectedATA) {
		return solana.PublicKey{}, core.NewError(core.ErrCodeInvalidPayload, "ATA creation address does not match owner/mint/token program")
	}
	return owner, nil
}

func ownerAllowed(owner solana.PublicKey, allowed []solana.PublicKey) bool {
	for _, candidate := range allowed {
		if candidate.Equals(owner) {
			return true
		}
	}
	return false
}

type expectedTransfer struct {
	recipient solana.PublicKey
	amount    uint64
}

func buildExpectedTransfers(amount uint64, recipient solana.PublicKey, details paycore.MethodDetails) ([]expectedTransfer, error) {
	primaryAmount, err := solanatx.SplitAmounts(amount, details.Splits)
	if err != nil {
		return nil, err
	}
	expected := []expectedTransfer{{recipient: recipient, amount: primaryAmount}}
	for _, split := range details.Splits {
		splitAmount, err := intents.ChargeRequest{Amount: split.Amount}.ParseAmount()
		if err != nil {
			return nil, err
		}
		splitRecipient, err := solana.PublicKeyFromBase58(split.Recipient)
		if err != nil {
			return nil, err
		}
		expected = append(expected, expectedTransfer{
			recipient: splitRecipient,
			amount:    splitAmount,
		})
	}
	return expected, nil
}

func successReceipt(reference, challengeID, externalID string) core.Receipt {
	return core.Receipt{
		Status:      core.ReceiptStatusSuccess,
		Method:      core.NewMethodName("solana"),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Reference:   reference,
		ChallengeID: challengeID,
		ExternalID:  externalID,
	}
}

func isNativeSOL(currency string) bool {
	return strings.EqualFold(currency, "sol")
}

// resolveProgramID safely resolves the program account for a compiled
// instruction. Attacker-controlled credential transactions on the pull
// path may carry a ProgramIDIndex that points outside AccountKeys; the
// raw indexing operation panics in that case, so verification helpers
// must use this guard and surface a structured 402 payment_invalid
// rejection instead of crashing the request handler.
func resolveProgramID(tx *solana.Transaction, programIDIndex uint16) (solana.PublicKey, error) {
	idx := int(programIDIndex)
	if idx < 0 || idx >= len(tx.Message.AccountKeys) {
		return solana.PublicKey{}, core.NewError(
			core.ErrCodeInvalidPayload,
			fmt.Sprintf("instruction program index %d is out of range for %d account keys",
				programIDIndex, len(tx.Message.AccountKeys)),
		)
	}
	return tx.Message.AccountKeys[idx], nil
}

// validateComputeBudgetInstructions inspects every ComputeBudget program
// instruction in the credential transaction and rejects ones that exceed
// the unit-limit or microlamport-price caps. The wire format follows the
// on-chain ComputeBudget program:
//
//   - discriminator 2 + u32 LE => SetComputeUnitLimit
//   - discriminator 3 + u64 LE => SetComputeUnitPrice
//
// Matches rust/src/server/charge.rs validate_compute_budget_instruction.
func validateComputeBudgetInstructions(tx *solana.Transaction) error {
	for _, ix := range tx.Message.Instructions {
		programID, err := resolveProgramID(tx, ix.ProgramIDIndex)
		if err != nil {
			return err
		}
		if !programID.Equals(computeBudgetProgramID) {
			continue
		}
		if len(ix.Accounts) != 0 {
			return core.NewError(
				core.ErrCodeComputeBudgetExceeded,
				"compute budget instruction must not have accounts",
			)
		}
		data := []byte(ix.Data)
		if len(data) == 0 {
			return core.NewError(
				core.ErrCodeComputeBudgetExceeded,
				"unsupported compute budget instruction: empty data",
			)
		}
		switch data[0] {
		case 2:
			if len(data) != 5 {
				return core.NewError(
					core.ErrCodeComputeBudgetExceeded,
					fmt.Sprintf("compute unit limit instruction has %d data bytes, expected 5", len(data)),
				)
			}
			units := uint32(data[1]) | uint32(data[2])<<8 | uint32(data[3])<<16 | uint32(data[4])<<24
			if units > maxComputeUnitLimit {
				return core.NewError(
					core.ErrCodeComputeBudgetExceeded,
					fmt.Sprintf("compute unit limit %d exceeds maximum %d", units, maxComputeUnitLimit),
				)
			}
		case 3:
			if len(data) != 9 {
				return core.NewError(
					core.ErrCodeComputeBudgetExceeded,
					fmt.Sprintf("compute unit price instruction has %d data bytes, expected 9", len(data)),
				)
			}
			price := uint64(data[1]) | uint64(data[2])<<8 | uint64(data[3])<<16 | uint64(data[4])<<24 |
				uint64(data[5])<<32 | uint64(data[6])<<40 | uint64(data[7])<<48 | uint64(data[8])<<56
			if price > maxComputeUnitPriceMicroLamports {
				return core.NewError(
					core.ErrCodeComputeBudgetExceeded,
					fmt.Sprintf("compute unit price %d exceeds maximum %d", price, maxComputeUnitPriceMicroLamports),
				)
			}
		default:
			return core.NewError(
				core.ErrCodeComputeBudgetExceeded,
				fmt.Sprintf("unsupported compute budget instruction discriminator %d", data[0]),
			)
		}
	}
	return nil
}

// validateSplitsCount enforces the cross-SDK cap of 8 secondary recipients
// per charge. Mirrors the rust/typescript/python/ruby/php server checks so
// a client cannot smuggle a fanned-out fee schedule past the Go SDK.
func validateSplitsCount(splits []paycore.Split) error {
	if len(splits) > maxSplits {
		return core.NewError(
			core.ErrCodeTooManySplits,
			fmt.Sprintf("too many splits: %d (maximum %d)", len(splits), maxSplits),
		)
	}
	return nil
}
