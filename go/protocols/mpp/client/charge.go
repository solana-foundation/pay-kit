package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// BuildOptions customize client-side transaction creation.
type BuildOptions struct {
	Broadcast        bool
	ComputeUnitLimit uint32
	ComputeUnitPrice uint64
	ExternalID       string
	// CreateRecipientATA, when true, prepends an idempotent
	// createAssociatedTokenAccount instruction for the primary recipient on
	// SPL token charges. Default is false to match the canonical Rust/TS
	// client behavior (the receiver server owns its destination ATA).
	// Enable this only when paying a fresh recipient wallet that does not
	// yet hold a token account for the selected mint; the instruction is
	// idempotent so it is safe when the account already exists.
	CreateRecipientATA bool

	// MaxAmountBaseUnits, when non-zero, refuses to sign a challenge whose
	// amount exceeds this cap (in token base units). Opt-in guard for
	// auto-pay integrations where the server controls what gets signed
	// against the user's wallet (#10). Zero means no cap.
	MaxAmountBaseUnits uint64

	// ExpectedNetwork, when non-empty, refuses to sign a challenge whose
	// methodDetails.network does not match (compared canonically, so
	// "mainnet"/"mainnet-beta" are equivalent). Opt-in network pin (#10).
	ExpectedNetwork string

	// AllowUnknownToken2022, when true, permits signing transfers for a
	// Token-2022 mint that is not a known stablecoin. Such mints can carry
	// transfer hooks that execute arbitrary code on every transfer, so they
	// are refused by default (#26). Vanilla Token-program mints are always
	// allowed regardless of this flag.
	AllowUnknownToken2022 bool
}

// BuildChargeTransaction creates a payment credential payload from challenge fields.
func BuildChargeTransaction(
	ctx context.Context,
	signer solanatx.Signer,
	rpcClient solanatx.RPCClient,
	amount string,
	currency string,
	recipient string,
	methodDetails paycore.MethodDetails,
	options BuildOptions,
) (paycore.CredentialPayload, error) {
	total, err := parseAmount(amount)
	if err != nil {
		return paycore.CredentialPayload{}, err
	}
	primaryAmount, err := solanatx.SplitAmounts(total, methodDetails.Splits)
	if err != nil {
		return paycore.CredentialPayload{}, err
	}

	if options.ComputeUnitLimit == 0 {
		options.ComputeUnitLimit = 200_000
	}
	if options.ComputeUnitPrice == 0 {
		options.ComputeUnitPrice = 1
	}

	instructions := make([]solana.Instruction, 0, 2+2+len(methodDetails.Splits)*3)
	if ix, err := solanatx.BuildComputeUnitPrice(options.ComputeUnitPrice); err == nil {
		instructions = append(instructions, ix)
	}
	if ix, err := solanatx.BuildComputeUnitLimit(options.ComputeUnitLimit); err == nil {
		instructions = append(instructions, ix)
	}

	recipientKey, err := solana.PublicKeyFromBase58(recipient)
	if err != nil {
		return paycore.CredentialPayload{}, core.WrapError(core.ErrCodeInvalidConfig, "invalid recipient", err)
	}
	useServerFeePayer := methodDetails.FeePayer != nil && *methodDetails.FeePayer && methodDetails.FeePayerKey != "" && !options.Broadcast
	if options.Broadcast && methodDetails.FeePayer != nil && *methodDetails.FeePayer {
		return paycore.CredentialPayload{}, core.NewError(core.ErrCodeInvalidConfig, `type="signature" cannot be used with fee sponsorship`)
	}

	if isNativeSOL(currency) {
		ix, err := solanatx.BuildSOLTransfer(signer.PublicKey(), recipientKey, primaryAmount)
		if err != nil {
			return paycore.CredentialPayload{}, err
		}
		instructions = append(instructions, ix)
		if options.ExternalID != "" {
			memoIx, err := solanatx.BuildMemoInstruction(options.ExternalID)
			if err != nil {
				return paycore.CredentialPayload{}, err
			}
			instructions = append(instructions, memoIx)
		}
		for _, split := range methodDetails.Splits {
			splitKey, err := solana.PublicKeyFromBase58(split.Recipient)
			if err != nil {
				return paycore.CredentialPayload{}, err
			}
			splitAmount, err := parseAmount(split.Amount)
			if err != nil {
				return paycore.CredentialPayload{}, err
			}
			ix, err := solanatx.BuildSOLTransfer(signer.PublicKey(), splitKey, splitAmount)
			if err != nil {
				return paycore.CredentialPayload{}, err
			}
			instructions = append(instructions, ix)
			if split.Memo != "" {
				memoIx, err := solanatx.BuildMemoInstruction(split.Memo)
				if err != nil {
					return paycore.CredentialPayload{}, err
				}
				instructions = append(instructions, memoIx)
			}
		}
	} else {
		resolvedMint := paycore.ResolveMint(currency, methodDetails.Network)
		mint, err := solana.PublicKeyFromBase58(resolvedMint)
		if err != nil {
			return paycore.CredentialPayload{}, err
		}
		tokenProgram, err := solanatx.ResolveTokenProgram(ctx, rpcClient, mint, methodDetails.TokenProgram)
		if err != nil {
			return paycore.CredentialPayload{}, core.WrapError(core.ErrCodeRPC, "resolve token program", err)
		}
		// #26: refuse to sign an unknown Token-2022 mint unless explicitly
		// allowed. Token-2022 mints can carry transfer hooks that run arbitrary
		// code on every transfer; the vanilla Token program has no such hook so
		// arbitrary Token-program mints stay first-class.
		if tokenProgram.String() == paycore.Token2022Program &&
			paycore.StablecoinSymbol(currency) == "" &&
			!options.AllowUnknownToken2022 {
			return paycore.CredentialPayload{}, core.NewError(core.ErrCodeInvalidConfig,
				"refusing to sign an unknown Token-2022 mint (transfer-hook risk); set AllowUnknownToken2022 to override")
		}
		// #42: decimals are required for SPL charges (spec §7.2 marks them MUST
		// be present for a mint). Defaulting to 6 would silently build a
		// transfer at the wrong divisor for a non-6-decimal mint.
		if methodDetails.Decimals == nil {
			return paycore.CredentialPayload{}, core.NewError(core.ErrCodeInvalidConfig,
				"methodDetails.decimals is required for SPL charges (spec §7.2)")
		}
		decimals := *methodDetails.Decimals
		sourceATA, err := solanatx.FindAssociatedTokenAddressWithProgram(signer.PublicKey(), mint, tokenProgram)
		if err != nil {
			return paycore.CredentialPayload{}, err
		}
		payer := signer.PublicKey()
		if useServerFeePayer {
			payer, err = solana.PublicKeyFromBase58(methodDetails.FeePayerKey)
			if err != nil {
				return paycore.CredentialPayload{}, err
			}
		}
		addTransfer := func(owner solana.PublicKey, amount uint64, createTokenAccount bool) error {
			destATA, err := solanatx.FindAssociatedTokenAddressWithProgram(owner, mint, tokenProgram)
			if err != nil {
				return err
			}
			if createTokenAccount {
				createATA, err := solanatx.BuildCreateAssociatedTokenAccount(payer, owner, mint, tokenProgram)
				if err != nil {
					return err
				}
				instructions = append(instructions, createATA)
			}
			transfer, err := solanatx.BuildTransferChecked(amount, decimals, sourceATA, mint, destATA, signer.PublicKey(), tokenProgram)
			if err != nil {
				return err
			}
			instructions = append(instructions, transfer)
			return nil
		}
		if err := addTransfer(recipientKey, primaryAmount, options.CreateRecipientATA); err != nil {
			return paycore.CredentialPayload{}, err
		}
		if options.ExternalID != "" {
			memoIx, err := solanatx.BuildMemoInstruction(options.ExternalID)
			if err != nil {
				return paycore.CredentialPayload{}, err
			}
			instructions = append(instructions, memoIx)
		}
		for _, split := range methodDetails.Splits {
			splitKey, err := solana.PublicKeyFromBase58(split.Recipient)
			if err != nil {
				return paycore.CredentialPayload{}, err
			}
			splitAmount, err := parseAmount(split.Amount)
			if err != nil {
				return paycore.CredentialPayload{}, err
			}
			// #20: only create a split ATA when the challenge explicitly flags
			// it. Creating one per split in client-paid mode let a hostile
			// server attach N dust splits and drain N x ~0.002 SOL of rent.
			createTokenAccount := split.AtaCreationRequired != nil && *split.AtaCreationRequired
			if err := addTransfer(splitKey, splitAmount, createTokenAccount); err != nil {
				return paycore.CredentialPayload{}, err
			}
			if split.Memo != "" {
				memoIx, err := solanatx.BuildMemoInstruction(split.Memo)
				if err != nil {
					return paycore.CredentialPayload{}, err
				}
				instructions = append(instructions, memoIx)
			}
		}
	}

	blockhash, err := solanatx.ResolveRecentBlockhash(ctx, rpcClient, methodDetails.RecentBlockhash)
	if err != nil {
		return paycore.CredentialPayload{}, core.WrapError(core.ErrCodeRPC, "fetch recent blockhash", err)
	}
	payer := signer.PublicKey()
	txOpts := []solana.TransactionOption{}
	if useServerFeePayer {
		payer, err = solana.PublicKeyFromBase58(methodDetails.FeePayerKey)
		if err != nil {
			return paycore.CredentialPayload{}, err
		}
	}
	txOpts = append(txOpts, solana.TransactionPayer(payer))
	tx, err := solana.NewTransaction(instructions, blockhash, txOpts...)
	if err != nil {
		return paycore.CredentialPayload{}, err
	}
	if err := solanatx.SignTransaction(tx, signer); err != nil {
		return paycore.CredentialPayload{}, err
	}

	if options.Broadcast {
		signature, err := solanatx.SendTransaction(ctx, rpcClient, tx)
		if err != nil {
			return paycore.CredentialPayload{}, core.WrapError(core.ErrCodeRPC, "send transaction", err)
		}
		if err := solanatx.WaitForConfirmation(ctx, rpcClient, signature); err != nil {
			return paycore.CredentialPayload{}, core.WrapError(core.ErrCodeTransactionFailed, "confirm transaction", err)
		}
		return paycore.CredentialPayload{Type: "signature", Signature: signature.String()}, nil
	}

	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		return paycore.CredentialPayload{}, err
	}
	return paycore.CredentialPayload{Type: "transaction", Transaction: encoded}, nil
}

// BuildCredentialHeader creates an Authorization header from a challenge.
func BuildCredentialHeader(
	ctx context.Context,
	signer solanatx.Signer,
	rpcClient solanatx.RPCClient,
	challenge core.PaymentChallenge,
) (string, error) {
	return BuildCredentialHeaderWithOptions(ctx, signer, rpcClient, challenge, BuildOptions{})
}

// BuildCredentialHeaderWithOptions creates an Authorization header from a challenge.
func BuildCredentialHeaderWithOptions(
	ctx context.Context,
	signer solanatx.Signer,
	rpcClient solanatx.RPCClient,
	challenge core.PaymentChallenge,
	options BuildOptions,
) (string, error) {
	// #17: refuse to sign a challenge that is not a solana/charge challenge
	// before doing any work. The transport filters before calling, but this is
	// the lower-level exported builder, so it must gate itself.
	if challenge.Method != core.NewMethodName("solana") {
		return "", core.NewError(core.ErrCodeInvalidMethod,
			"challenge method is not \"solana\"")
	}
	if !challenge.Intent.IsCharge() {
		return "", core.NewError(core.ErrCodeInvalidMethod,
			"challenge intent is not a charge")
	}
	// #10: always refuse to sign an expired challenge. Challenges with no
	// expiry are still accepted (the protocol allows omitting it).
	if challenge.IsExpired(time.Now()) {
		return "", core.NewError(core.ErrCodeChallengeExpired,
			"refusing to sign an expired challenge")
	}
	var request intents.ChargeRequest
	if err := challenge.Request.Decode(&request); err != nil {
		return "", err
	}
	var details paycore.MethodDetails
	if request.MethodDetails != nil {
		raw, err := json.Marshal(request.MethodDetails)
		if err != nil {
			return "", err
		}
		if err := json.Unmarshal(raw, &details); err != nil {
			return "", err
		}
	}
	// #10: opt-in max-amount cap. Compared in base units, matching how the
	// server reasons about the amount.
	if options.MaxAmountBaseUnits > 0 {
		amount, err := request.ParseAmount()
		if err != nil {
			return "", err
		}
		if amount > options.MaxAmountBaseUnits {
			return "", core.NewError(core.ErrCodeAmountMismatch,
				fmt.Sprintf("challenge amount %d exceeds configured maximum %d", amount, options.MaxAmountBaseUnits))
		}
	}
	// #10: opt-in expected-network pin. Compared canonically so the legacy
	// "mainnet-beta" spelling matches the canonical "mainnet".
	if options.ExpectedNetwork != "" {
		if paycore.ParseSolanaNetwork(details.Network) != paycore.ParseSolanaNetwork(options.ExpectedNetwork) {
			return "", core.NewError(core.ErrCodeWrongNetwork,
				fmt.Sprintf("challenge network %q does not match expected %q", details.Network, options.ExpectedNetwork))
		}
	}
	options.ExternalID = request.ExternalID
	payload, err := BuildChargeTransaction(ctx, signer, rpcClient, request.Amount, request.Currency, request.Recipient, details, options)
	if err != nil {
		return "", err
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), payload)
	if err != nil {
		return "", err
	}
	return core.FormatAuthorization(credential)
}

func parseAmount(value string) (uint64, error) {
	request := intents.ChargeRequest{Amount: strings.TrimSpace(value)}
	return request.ParseAmount()
}

func isNativeSOL(currency string) bool {
	return strings.EqualFold(currency, "sol")
}
