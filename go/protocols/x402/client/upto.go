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
	tokenProgramID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
)

func randomSalt() (uint64, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 64)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, fmt.Errorf("x402 client: random salt: %w", err)
	}
	return n.Uint64(), nil
}

// BuildUptoPayload derives the payment-channel open and assembles the upto
// authorization payload. The channel open_slot comes from the challenge
// (extra.recentSlot, pre-fetched by the server alongside
// extra.recentBlockhash); clients never fetch the slot via RPC. It is a
// channel PDA seed and an open arg, and the program rejects future slots and
// slots older than the 1500-slot window.
func BuildUptoPayload(
	ctx context.Context,
	signer solanatx.Signer,
	requirements *x402.UptoRequirements,
	expiresAt int64,
	_ string,
) (*x402.UptoPayload, error) {
	if requirements.Extra.RecentSlot == "" {
		return nil, errors.New("x402 client: requirement missing extra.recentSlot")
	}
	openSlot, err := strconv.ParseUint(requirements.Extra.RecentSlot, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid recentSlot %q: %w", requirements.Extra.RecentSlot, err)
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
	feePayer, err := solana.PublicKeyFromBase58(requirements.Extra.FeePayer)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid feePayer %q: %w", requirements.Extra.FeePayer, err)
	}
	receiverAuthorizer, err := solana.PublicKeyFromBase58(requirements.Extra.ReceiverAuthorizer)
	if err != nil {
		return nil, fmt.Errorf("x402 client: invalid receiverAuthorizer %q: %w", requirements.Extra.ReceiverAuthorizer, err)
	}
	if requirements.Extra.WithdrawDelay == 0 {
		return nil, errors.New("x402 client: requirement missing extra.withdrawDelay")
	}
	recipients := []paymentchannels.Distribution(nil)
	if !beneficiary.Equals(receiverAuthorizer) {
		recipients = []paymentchannels.Distribution{{
			Recipient: beneficiary,
			Bps:       10_000,
		}}
	}
	programID := paymentchannels.ProgramPubkey()
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
	channel, _, err := paymentchannels.FindChannelPDAForProgram(
		signer.PublicKey(),
		receiverAuthorizer,
		mint,
		receiverAuthorizer,
		salt,
		openSlot,
		programID,
	)
	if err != nil {
		return nil, fmt.Errorf("x402 client: find channel PDA: %w", err)
	}
	openIx, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            signer.PublicKey(),
		RentPayer:        feePayer,
		Payee:            receiverAuthorizer,
		Mint:             mint,
		AuthorizedSigner: receiverAuthorizer,
		Salt:             salt,
		OpenSlot:         openSlot,
		Deposit:          max,
		GracePeriod:      requirements.Extra.WithdrawDelay,
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
		solana.TransactionPayer(feePayer),
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
		Nonce:            strconv.FormatUint(salt, 10),
		ChannelID:        channel.String(),
		Deposit:          strconv.FormatUint(max, 10),
		AuthorizedSigner: receiverAuthorizer.String(),
		OpenSlot:         strconv.FormatUint(openSlot, 10),
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

// BuildUptoHeader builds and encodes the upto authorization header. The
// channel open_slot comes from the challenge extra.recentSlot; see
// BuildUptoPayload.
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
