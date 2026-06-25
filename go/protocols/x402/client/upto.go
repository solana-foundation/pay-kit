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
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

const defaultGracePeriodSeconds = 900

func randomSalt() (uint64, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 64)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, fmt.Errorf("x402 client: random salt: %w", err)
	}
	return n.Uint64(), nil
}

func profileSupported(requirements *x402.UptoRequirements) bool {
	for _, p := range requirements.Extra.Profiles {
		if p == x402.ProfilePaymentChannel {
			return true
		}
	}
	return false
}

func resolveMint(asset string) (solana.PublicKey, error) {
	mint, err := solana.PublicKeyFromBase58(asset)
	if err == nil {
		return mint, nil
	}
	labels := []string{"mainnet-beta", "devnet", "localnet"}
	for _, label := range labels {
		resolved := paycore.ResolveMint(asset, label)
		if resolved != "" {
			return solana.PublicKeyFromBase58(resolved)
		}
	}
	return solana.PublicKey{}, fmt.Errorf("x402 client: cannot resolve mint %q", asset)
}

func resolveTokenProgram(tokenProgramStr string, mint solana.PublicKey) solana.PublicKey {
	if tokenProgramStr != "" {
		if pk, err := solana.PublicKeyFromBase58(tokenProgramStr); err == nil {
			return pk
		}
	}
	labels := []string{"mainnet-beta", "devnet", "localnet"}
	for _, label := range labels {
		tp := paycore.DefaultTokenProgramForCurrency(mint.String(), label)
		if tp != "" {
			if pk, err := solana.PublicKeyFromBase58(tp); err == nil {
				return pk
			}
		}
	}
	return solana.TokenProgramID
}

func resolveChannelProgram(channelProgramStr string) solana.PublicKey {
	if channelProgramStr != "" {
		if pk, err := solana.PublicKeyFromBase58(channelProgramStr); err == nil {
			return pk
		}
	}
	return paymentchannels.ProgramPubkey()
}

func BuildUptoPayload(
	ctx context.Context,
	signer solanatx.Signer,
	requirements *x402.UptoRequirements,
	expiresAt int64,
	nonce string,
) (*x402.UptoPayload, error) {
	if !profileSupported(requirements) {
		return nil, errors.New("x402 client: requirement does not advertise the payment-channel profile")
	}
	max, err := strconv.ParseUint(requirements.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid upto amount %q: %w", requirements.Amount, err)
	}
	payee, err := solana.PublicKeyFromBase58(requirements.PayTo)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid payTo %q: %w", requirements.PayTo, err)
	}
	mint, err := resolveMint(requirements.Asset)
	if err != nil {
		return nil, err
	}
	operator, err := solana.PublicKeyFromBase58(requirements.Extra.FeePayer)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid feePayer %q: %w", requirements.Extra.FeePayer, err)
	}
	programID := resolveChannelProgram(requirements.Extra.ChannelProgram)
	tokenProgram := resolveTokenProgram(requirements.Extra.TokenProgram, mint)

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
	channel, _, err := paymentchannels.FindChannelPDA(signer.PublicKey(), payee, mint, operator, salt)
	if err != nil {
		return nil, fmt.Errorf("x402 client: find channel PDA: %w", err)
	}
	openIx, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            signer.PublicKey(),
		Payee:            payee,
		Mint:             mint,
		AuthorizedSigner: operator,
		Salt:             salt,
		Deposit:          max,
		GracePeriod:      defaultGracePeriodSeconds,
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
		Profile:          x402.ProfilePaymentChannel,
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
		Scheme:      x402.UptoScheme,
		Network:     requirements.Network,
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
	var raw string
	if v := h.Get(paymentRequiredHeader); v != "" {
		raw = v
	} else if v := h.Get(paymentRequiredHeaderLegacy); v != "" {
		raw = v
	} else if len(body) > 0 {
		raw = string(body)
	} else {
		return nil, false
	}

	var envelope x402.UptoRequiredEnvelope
	if h.Get(paymentRequiredHeader) != "" || h.Get(paymentRequiredHeaderLegacy) != "" {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, false
		}
		if err := json.Unmarshal(decoded, &envelope); err != nil {
			return nil, false
		}
	} else {
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
			return nil, false
		}
	}

	for _, req := range envelope.Accepts {
		if req.Scheme == x402.UptoScheme {
			return &req, true
		}
	}
	return nil, false
}
