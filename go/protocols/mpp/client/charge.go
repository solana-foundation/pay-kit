package client

import (
	"context"
	"encoding/json"
	"strings"

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
		decimals := uint8(6)
		if methodDetails.Decimals != nil {
			decimals = *methodDetails.Decimals
		}
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
			createTokenAccount := !useServerFeePayer || (split.AtaCreationRequired != nil && *split.AtaCreationRequired)
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
