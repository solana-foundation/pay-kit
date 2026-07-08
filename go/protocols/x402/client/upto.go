package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

const (
	defaultGracePeriodSeconds = 900
	tokenProgramID            = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
)

func randomSalt() (uint64, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 64)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, fmt.Errorf("x402 client: random salt: %w", err)
	}
	return n.Uint64(), nil
}

func assetTransferMethodSupported(requirements *x402.UptoRequirements) bool {
	return requirements.Extra.AssetTransferMethod == x402.UptoAssetTransferMethod
}

func resolveChannelProgram(channelProgramStr string) (solana.PublicKey, error) {
	if channelProgramStr != "" {
		pk, err := solana.PublicKeyFromBase58(channelProgramStr)
		if err != nil {
			return solana.PublicKey{}, fmt.Errorf("x402 client: invalid channelProgram %q: %w", channelProgramStr, err)
		}
		return pk, nil
	}
	return paymentchannels.ProgramPubkey(), nil
}

func BuildUptoPayload(
	ctx context.Context,
	signer solanatx.Signer,
	requirements *x402.UptoRequirements,
	expiresAt int64,
	nonce string,
) (*x402.UptoPayload, error) {
	if !assetTransferMethodSupported(requirements) {
		return nil, errors.New("x402 client: requirement does not use the payment-channel asset transfer method")
	}
	max, err := strconv.ParseUint(requirements.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid upto amount %q: %w", requirements.Amount, err)
	}
	beneficiary, err := solana.PublicKeyFromBase58(requirements.PayTo)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid payTo %q: %w", requirements.PayTo, err)
	}
	mint, err := solana.PublicKeyFromBase58(requirements.Asset)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid asset mint %q: %w", requirements.Asset, err)
	}
	operator, err := solana.PublicKeyFromBase58(requirements.Extra.FacilitatorAddress)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid facilitatorAddress %q: %w", requirements.Extra.FacilitatorAddress, err)
	}
	recipients := []paymentchannels.Distribution(nil)
	if !beneficiary.Equals(operator) {
		if requirements.Extra.FacilitatorFee > 10_000 {
			return nil, errors.New("x402 client: facilitatorFee exceeds 100%")
		}
		recipients = []paymentchannels.Distribution{{
			Recipient: beneficiary,
			Bps:       10_000 - requirements.Extra.FacilitatorFee,
		}}
	}
	programID, err := resolveChannelProgram(requirements.Extra.ChannelProgram)
	if err != nil {
		return nil, err
	}
	var tokenProgram solana.PublicKey
	if requirements.Extra.TokenProgram != "" {
		tokenProgram, err = solana.PublicKeyFromBase58(requirements.Extra.TokenProgram)
		if err != nil {
			return nil, fmt.Errorf("x402 client: invalid tokenProgram %q: %w", requirements.Extra.TokenProgram, err)
		}
	} else {
		tokenProgram = solana.MustPublicKeyFromBase58(tokenProgramID)
	}

	blockhashStr := requirements.Extra.RecentBlockhash
	if blockhashStr == "" {
		return nil, errors.New("x402 client: requirement missing extra.recentBlockhash")
	}
	blockhash, err := solana.HashFromBase58(blockhashStr)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid recentBlockhash %q: %w", blockhashStr, err)
	}

	salt, err := randomSalt()
	if err != nil {
		return nil, err
	}
	channel, _, err := paymentchannels.FindChannelPDAForProgram(signer.PublicKey(), operator, mint, operator, salt, programID)
	if err != nil {
		return nil, fmt.Errorf("x402 client: find channel PDA: %w", err)
	}
	openIx, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            signer.PublicKey(),
		RentPayer:        operator,
		Payee:            operator,
		Mint:             mint,
		AuthorizedSigner: operator,
		Salt:             salt,
		Deposit:          max,
		GracePeriod:      defaultGracePeriodSeconds,
		Recipients:       recipients,
		TokenProgram:     tokenProgram,
		ProgramID:        programID,
	})
	if err != nil {
		return nil, fmt.Errorf("x402 client: build open instruction: %w", err)
	}
	tx, err := solana.NewTransaction(
		[]solana.Instruction{openIx},
		blockhash,
		solana.TransactionPayer(operator),
	)
	if err != nil {
		return nil, fmt.Errorf("x402 client: build transaction: %w", err)
	}
	if err := solanatx.SignTransaction(tx, signer); err != nil {
		return nil, fmt.Errorf("x402 client: sign: %w", err)
	}
	txBase64, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		return nil, fmt.Errorf("x402 client: encode transaction: %w", err)
	}

	validAfter := int64(0)
	if requirements.Extra.ValidAfter != nil {
		validAfter = *requirements.Extra.ValidAfter
	}
	return &x402.UptoPayload{
		From:             signer.PublicKey().String(),
		MaxAmount:        strconv.FormatUint(max, 10),
		ExpiresAt:        expiresAt,
		ValidAfter:       validAfter,
		Nonce:            nonce,
		ChannelID:        channel.String(),
		Deposit:          strconv.FormatUint(max, 10),
		AuthorizedSigner: operator.String(),
		OpenTransaction:  txBase64,
	}, nil
}

func EncodeUptoHeader(requirements *x402.UptoRequirements, payload *x402.UptoPayload) (string, error) {
	accepted, err := json.Marshal(requirements)
	if err != nil {
		return "", fmt.Errorf("x402 client: marshal accepted entry: %w", err)
	}
	envelope := x402.UptoSignatureEnvelope{
		X402Version: x402Version,
		Accepted:    accepted,
		Payload:     *payload,
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("x402 client: marshal envelope: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func BuildUptoHeader(
	ctx context.Context,
	signer solanatx.Signer,
	requirements *x402.UptoRequirements,
	expiresAt int64,
	nonce string,
) (string, error) {
	payload, err := BuildUptoPayload(ctx, signer, requirements, expiresAt, nonce)
	if err != nil {
		return "", err
	}
	return EncodeUptoHeader(requirements, payload)
}

func ParseUptoChallenge(h http.Header, body []byte) (*x402.UptoRequirements, bool) {
	var envelope x402.UptoRequiredEnvelope
	if v := h.Get(paymentRequiredHeader); v != "" {
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, false
		}
		if err := json.Unmarshal(decoded, &envelope); err != nil {
			return nil, false
		}
	} else if len(body) > 0 {
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, false
		}
	} else {
		return nil, false
	}
	for _, req := range envelope.Accepts {
		if req.Scheme == x402.UptoScheme {
			return &req, true
		}
	}
	return nil, false
}
