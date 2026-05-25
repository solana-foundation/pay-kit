package client

import (
	"context"
	"encoding/json"
	"strings"

	solana "github.com/gagliardetto/solana-go"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/internal/utils"
	"github.com/solana-foundation/pay-kit/go/protocol"
	"github.com/solana-foundation/pay-kit/go/protocol/intents"
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
	signer utils.Signer,
	rpcClient utils.RPCClient,
	amount string,
	currency string,
	recipient string,
	methodDetails protocol.MethodDetails,
	options BuildOptions,
) (protocol.CredentialPayload, error) {
	total, err := parseAmount(amount)
	if err != nil {
		return protocol.CredentialPayload{}, err
	}
	primaryAmount, err := utils.SplitAmounts(total, methodDetails.Splits)
	if err != nil {
		return protocol.CredentialPayload{}, err
	}

	if options.ComputeUnitLimit == 0 {
		options.ComputeUnitLimit = 200_000
	}
	if options.ComputeUnitPrice == 0 {
		options.ComputeUnitPrice = 1
	}

	instructions := make([]solana.Instruction, 0, 2+2+len(methodDetails.Splits)*3)
	if ix, err := utils.BuildComputeUnitPrice(options.ComputeUnitPrice); err == nil {
		instructions = append(instructions, ix)
	}
	if ix, err := utils.BuildComputeUnitLimit(options.ComputeUnitLimit); err == nil {
		instructions = append(instructions, ix)
	}

	recipientKey, err := solana.PublicKeyFromBase58(recipient)
	if err != nil {
		return protocol.CredentialPayload{}, mpp.WrapError(mpp.ErrCodeInvalidConfig, "invalid recipient", err)
	}
	useServerFeePayer := methodDetails.FeePayer != nil && *methodDetails.FeePayer && methodDetails.FeePayerKey != "" && !options.Broadcast
	if options.Broadcast && methodDetails.FeePayer != nil && *methodDetails.FeePayer {
		return protocol.CredentialPayload{}, mpp.NewError(mpp.ErrCodeInvalidConfig, `type="signature" cannot be used with fee sponsorship`)
	}

	if isNativeSOL(currency) {
		ix, err := utils.BuildSOLTransfer(signer.PublicKey(), recipientKey, primaryAmount)
		if err != nil {
			return protocol.CredentialPayload{}, err
		}
		instructions = append(instructions, ix)
		if options.ExternalID != "" {
			memoIx, err := utils.BuildMemoInstruction(options.ExternalID)
			if err != nil {
				return protocol.CredentialPayload{}, err
			}
			instructions = append(instructions, memoIx)
		}
		for _, split := range methodDetails.Splits {
			splitKey, err := solana.PublicKeyFromBase58(split.Recipient)
			if err != nil {
				return protocol.CredentialPayload{}, err
			}
			splitAmount, err := parseAmount(split.Amount)
			if err != nil {
				return protocol.CredentialPayload{}, err
			}
			ix, err := utils.BuildSOLTransfer(signer.PublicKey(), splitKey, splitAmount)
			if err != nil {
				return protocol.CredentialPayload{}, err
			}
			instructions = append(instructions, ix)
			if split.Memo != "" {
				memoIx, err := utils.BuildMemoInstruction(split.Memo)
				if err != nil {
					return protocol.CredentialPayload{}, err
				}
				instructions = append(instructions, memoIx)
			}
		}
	} else {
		resolvedMint := protocol.ResolveMint(currency, methodDetails.Network)
		mint, err := solana.PublicKeyFromBase58(resolvedMint)
		if err != nil {
			return protocol.CredentialPayload{}, err
		}
		tokenProgram, err := utils.ResolveTokenProgram(ctx, rpcClient, mint, methodDetails.TokenProgram)
		if err != nil {
			return protocol.CredentialPayload{}, mpp.WrapError(mpp.ErrCodeRPC, "resolve token program", err)
		}
		decimals := uint8(6)
		if methodDetails.Decimals != nil {
			decimals = *methodDetails.Decimals
		}
		sourceATA, err := utils.FindAssociatedTokenAddressWithProgram(signer.PublicKey(), mint, tokenProgram)
		if err != nil {
			return protocol.CredentialPayload{}, err
		}
		payer := signer.PublicKey()
		if useServerFeePayer {
			payer, err = solana.PublicKeyFromBase58(methodDetails.FeePayerKey)
			if err != nil {
				return protocol.CredentialPayload{}, err
			}
		}
		addTransfer := func(owner solana.PublicKey, amount uint64, createTokenAccount bool) error {
			destATA, err := utils.FindAssociatedTokenAddressWithProgram(owner, mint, tokenProgram)
			if err != nil {
				return err
			}
			if createTokenAccount {
				createATA, err := utils.BuildCreateAssociatedTokenAccount(payer, owner, mint, tokenProgram)
				if err != nil {
					return err
				}
				instructions = append(instructions, createATA)
			}
			transfer, err := utils.BuildTransferChecked(amount, decimals, sourceATA, mint, destATA, signer.PublicKey(), tokenProgram)
			if err != nil {
				return err
			}
			instructions = append(instructions, transfer)
			return nil
		}
		if err := addTransfer(recipientKey, primaryAmount, options.CreateRecipientATA); err != nil {
			return protocol.CredentialPayload{}, err
		}
		if options.ExternalID != "" {
			memoIx, err := utils.BuildMemoInstruction(options.ExternalID)
			if err != nil {
				return protocol.CredentialPayload{}, err
			}
			instructions = append(instructions, memoIx)
		}
		for _, split := range methodDetails.Splits {
			splitKey, err := solana.PublicKeyFromBase58(split.Recipient)
			if err != nil {
				return protocol.CredentialPayload{}, err
			}
			splitAmount, err := parseAmount(split.Amount)
			if err != nil {
				return protocol.CredentialPayload{}, err
			}
			createTokenAccount := !useServerFeePayer || (split.AtaCreationRequired != nil && *split.AtaCreationRequired)
			if err := addTransfer(splitKey, splitAmount, createTokenAccount); err != nil {
				return protocol.CredentialPayload{}, err
			}
			if split.Memo != "" {
				memoIx, err := utils.BuildMemoInstruction(split.Memo)
				if err != nil {
					return protocol.CredentialPayload{}, err
				}
				instructions = append(instructions, memoIx)
			}
		}
	}

	blockhash, err := utils.ResolveRecentBlockhash(ctx, rpcClient, methodDetails.RecentBlockhash)
	if err != nil {
		return protocol.CredentialPayload{}, mpp.WrapError(mpp.ErrCodeRPC, "fetch recent blockhash", err)
	}
	payer := signer.PublicKey()
	txOpts := []solana.TransactionOption{}
	if useServerFeePayer {
		payer, err = solana.PublicKeyFromBase58(methodDetails.FeePayerKey)
		if err != nil {
			return protocol.CredentialPayload{}, err
		}
	}
	txOpts = append(txOpts, solana.TransactionPayer(payer))
	tx, err := solana.NewTransaction(instructions, blockhash, txOpts...)
	if err != nil {
		return protocol.CredentialPayload{}, err
	}
	if err := utils.SignTransaction(tx, signer); err != nil {
		return protocol.CredentialPayload{}, err
	}

	if options.Broadcast {
		signature, err := utils.SendTransaction(ctx, rpcClient, tx)
		if err != nil {
			return protocol.CredentialPayload{}, mpp.WrapError(mpp.ErrCodeRPC, "send transaction", err)
		}
		if err := utils.WaitForConfirmation(ctx, rpcClient, signature); err != nil {
			return protocol.CredentialPayload{}, mpp.WrapError(mpp.ErrCodeTransactionFailed, "confirm transaction", err)
		}
		return protocol.CredentialPayload{Type: "signature", Signature: signature.String()}, nil
	}

	encoded, err := utils.EncodeTransactionBase64(tx)
	if err != nil {
		return protocol.CredentialPayload{}, err
	}
	return protocol.CredentialPayload{Type: "transaction", Transaction: encoded}, nil
}

// BuildCredentialHeader creates an Authorization header from a challenge.
func BuildCredentialHeader(
	ctx context.Context,
	signer utils.Signer,
	rpcClient utils.RPCClient,
	challenge mpp.PaymentChallenge,
) (string, error) {
	return BuildCredentialHeaderWithOptions(ctx, signer, rpcClient, challenge, BuildOptions{})
}

// BuildCredentialHeaderWithOptions creates an Authorization header from a challenge.
func BuildCredentialHeaderWithOptions(
	ctx context.Context,
	signer utils.Signer,
	rpcClient utils.RPCClient,
	challenge mpp.PaymentChallenge,
	options BuildOptions,
) (string, error) {
	var request intents.ChargeRequest
	if err := challenge.Request.Decode(&request); err != nil {
		return "", err
	}
	var details protocol.MethodDetails
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), payload)
	if err != nil {
		return "", err
	}
	return mpp.FormatAuthorization(credential)
}

func parseAmount(value string) (uint64, error) {
	request := intents.ChargeRequest{Amount: strings.TrimSpace(value)}
	return request.ParseAmount()
}

func isNativeSOL(currency string) bool {
	return strings.EqualFold(currency, "sol")
}
