package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

const (
	PaymentRequiredHeader       = "payment-required"
	PaymentResponseHeader       = "payment-response"
	SettlementHeader            = "x-payment-settlement-signature"
	PaymentResponseHeaderLegacy = "x-payment-response"

	X402Version       = 2
	X402VersionLegacy = 1

	ExactScheme        = "exact"
	StablecoinDecimals = 6
	DefaultDecimals    = 6

	DefaultMaxTimeoutSeconds = 300

	solanaNetworkCAIP2 = "solana"
	solanaMainnetCAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	solanaDevnetCAIP2  = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	solanaTestnetCAIP2 = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
)

type RPCClient interface {
	SendEncodedTransactionWithOpts(ctx context.Context, b64 string, opts rpc.TransactionOpts) (solana.Signature, error)
	GetSignatureStatuses(ctx context.Context, searchHistory bool, sigs ...solana.Signature) (*rpc.GetSignatureStatusesResult, error)
	GetLatestBlockhash(ctx context.Context, commitment rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error)
}

type AcceptsEntry struct {
	Protocol          string `json:"protocol"`
	Scheme            string `json:"scheme"`
	Network           string `json:"network"`
	Asset             string `json:"asset"`
	Amount            string `json:"amount"`
	MaxAmountRequired string `json:"maxAmountRequired"`
	PayTo             string `json:"payTo"`
	MaxTimeoutSeconds int    `json:"maxTimeoutSeconds"`
	Extra             Extra  `json:"extra"`

	raw json.RawMessage
}

type Extra struct {
	FeePayer        bool   `json:"-"`
	FeePayerSet     bool   `json:"-"`
	FeePayerKey     string `json:"-"`
	Decimals        int    `json:"decimals"`
	DecimalsSet     bool   `json:"-"`
	TokenProgram    string `json:"tokenProgram"`
	Memo            string `json:"memo"`
	RecentBlockhash string `json:"recentBlockhash,omitempty"`
}

type rawAcceptsEntry struct {
	Protocol          string    `json:"protocol"`
	Scheme            string    `json:"scheme"`
	Network           string    `json:"network"`
	Asset             string    `json:"asset"`
	Currency          string    `json:"currency"`
	Amount            string    `json:"amount"`
	MaxAmountRequired string    `json:"maxAmountRequired"`
	PayTo             string    `json:"payTo"`
	Recipient         string    `json:"recipient"`
	MaxTimeoutSeconds *int      `json:"maxTimeoutSeconds"`
	MaxAge            *int      `json:"maxAge"`
	Decimals          *int      `json:"decimals"`
	TokenProgram      string    `json:"tokenProgram"`
	RecentBlockhash   string    `json:"recentBlockhash"`
	FeePayer          *bool     `json:"feePayer"`
	FeePayerKey       string    `json:"feePayerKey"`
	Extra             *rawExtra `json:"extra"`
}

type rawExtra struct {
	FeePayer        string `json:"feePayer"`
	Decimals        *int   `json:"decimals"`
	TokenProgram    string `json:"tokenProgram"`
	Memo            string `json:"memo"`
	RecentBlockhash string `json:"recentBlockhash"`
}

func (e *AcceptsEntry) UnmarshalJSON(data []byte) error {
	var r rawAcceptsEntry
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	if r.Extra == nil {
		r.Extra = &rawExtra{}
	}
	e.raw = append(json.RawMessage(nil), data...)
	e.Protocol = r.Protocol
	e.Scheme = r.Scheme
	e.Network = normalizeNetwork(r.Network)
	e.Asset = firstNonEmpty(r.Asset, r.Currency)
	e.Amount = firstNonEmpty(r.Amount, r.MaxAmountRequired)
	e.MaxAmountRequired = firstNonEmpty(r.MaxAmountRequired, r.Amount)
	e.PayTo = firstNonEmpty(r.Recipient, r.PayTo)
	switch {
	case r.MaxTimeoutSeconds != nil:
		e.MaxTimeoutSeconds = *r.MaxTimeoutSeconds
	case r.MaxAge != nil:
		e.MaxTimeoutSeconds = *r.MaxAge
	default:
		e.MaxTimeoutSeconds = DefaultMaxTimeoutSeconds
	}
	e.Extra.RecentBlockhash = firstNonEmpty(r.RecentBlockhash, r.Extra.RecentBlockhash)
	e.Extra.TokenProgram = firstNonEmpty(r.TokenProgram, r.Extra.TokenProgram)
	e.Extra.Memo = r.Extra.Memo
	switch {
	case r.Decimals != nil:
		e.Extra.Decimals, e.Extra.DecimalsSet = *r.Decimals, true
	case r.Extra.Decimals != nil:
		e.Extra.Decimals, e.Extra.DecimalsSet = *r.Extra.Decimals, true
	default:
		e.Extra.Decimals, e.Extra.DecimalsSet = DefaultDecimals, false
	}
	e.Extra.FeePayerKey = firstNonEmpty(r.FeePayerKey, r.Extra.FeePayer)
	switch {
	case r.FeePayer != nil:
		e.Extra.FeePayer, e.Extra.FeePayerSet = *r.FeePayer, true
	case e.Extra.FeePayerKey != "":
		e.Extra.FeePayer, e.Extra.FeePayerSet = true, true
	default:
		e.Extra.FeePayer, e.Extra.FeePayerSet = false, false
	}
	return nil
}

func (e AcceptsEntry) MarshalJSON() ([]byte, error) {
	if len(e.raw) > 0 {
		return e.raw, nil
	}
	type wireExtra struct {
		FeePayer        string `json:"feePayer,omitempty"`
		Decimals        int    `json:"decimals"`
		TokenProgram    string `json:"tokenProgram"`
		Memo            string `json:"memo"`
		RecentBlockhash string `json:"recentBlockhash,omitempty"`
	}
	type wire struct {
		Protocol          string    `json:"protocol"`
		Scheme            string    `json:"scheme"`
		Network           string    `json:"network"`
		Asset             string    `json:"asset"`
		Amount            string    `json:"amount"`
		MaxAmountRequired string    `json:"maxAmountRequired"`
		PayTo             string    `json:"payTo"`
		MaxTimeoutSeconds int       `json:"maxTimeoutSeconds"`
		Extra             wireExtra `json:"extra"`
	}
	return json.Marshal(wire{
		Protocol:          e.Protocol,
		Scheme:            e.Scheme,
		Network:           e.Network,
		Asset:             e.Asset,
		Amount:            e.Amount,
		MaxAmountRequired: e.MaxAmountRequired,
		PayTo:             e.PayTo,
		MaxTimeoutSeconds: e.MaxTimeoutSeconds,
		Extra: wireExtra{
			FeePayer:        e.Extra.FeePayerKey,
			Decimals:        e.Extra.Decimals,
			TokenProgram:    e.Extra.TokenProgram,
			Memo:            e.Extra.Memo,
			RecentBlockhash: e.Extra.RecentBlockhash,
		},
	})
}

func (e AcceptsEntry) RawAccepted() json.RawMessage { return e.raw }

func (e *AcceptsEntry) ClearRaw() { e.raw = nil }

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func normalizeNetwork(network string) string {
	switch network {
	case "":
		return ""
	case solanaNetworkCAIP2, "mainnet", "mainnet-beta":
		return solanaMainnetCAIP2
	case "solana-devnet", "devnet", "localnet":
		return solanaDevnetCAIP2
	case "solana-testnet", "testnet":
		return solanaTestnetCAIP2
	default:
		return network
	}
}

type Credential struct {
	X402Version int                `json:"x402Version"`
	Scheme      string             `json:"scheme,omitempty"`
	Network     string             `json:"network,omitempty"`
	Payload     CredentialPayload  `json:"payload"`
	Accepted    *AcceptsEntry      `json:"accepted,omitempty"`
	Extensions  *PaymentExtensions `json:"extensions,omitempty"`
}

type CredentialPayload struct {
	Transaction string `json:"transaction"`
	Signature   string `json:"signature,omitempty"`
	ChallengeID string `json:"challengeId,omitempty"`
	Resource    string `json:"resource,omitempty"`
}

type SettlementResponse struct {
	Success     bool   `json:"success"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
	Payer       string `json:"payer"`
	ErrorReason string `json:"errorReason,omitempty"`
}

type ChallengeEnvelope struct {
	X402Version int             `json:"x402Version"`
	Resource    ResourceRef     `json:"resource"`
	Accepts     []AcceptsEntry  `json:"accepts"`
	Extensions  json.RawMessage `json:"extensions,omitempty"`
}

type ResourceRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func ParsePaymentSignature(header string) (Credential, string, error) {
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return Credential{}, "", err
	}
	var credential Credential
	if err := json.Unmarshal(decoded, &credential); err != nil {
		return Credential{}, "", err
	}
	if len(credential.Payload.Transaction) == 0 {
		return Credential{}, "", fmt.Errorf("missing transaction payload")
	}
	return credential, credential.Payload.Signature, nil
}

func ExtractDecimals(accepted *AcceptsEntry) int {
	if accepted == nil {
		return DefaultDecimals
	}
	return accepted.Extra.Decimals
}
