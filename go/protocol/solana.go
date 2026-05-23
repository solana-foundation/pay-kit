package protocol

import "strings"

const (
	TokenProgram           = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	Token2022Program       = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
	AssociatedTokenProgram = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
	SystemProgram          = "11111111111111111111111111111111"
	MemoProgram            = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

	USDCMainnetMint  = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	USDCDevnetMint   = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
	USDTMainnetMint  = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
	USDGMainnetMint  = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
	USDGDevnetMint   = "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
	PYUSDMainnetMint = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
	PYUSDDevnetMint  = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
	CASHMainnetMint  = "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"
)

var knownMints = map[string]map[string]string{
	"USDC": {
		"devnet":       USDCDevnetMint,
		"testnet":      USDCDevnetMint,
		"mainnet-beta": USDCMainnetMint,
	},
	"USDT": {
		"mainnet-beta": USDTMainnetMint,
	},
	"USDG": {
		"devnet":       USDGDevnetMint,
		"testnet":      USDGDevnetMint,
		"mainnet-beta": USDGMainnetMint,
	},
	"PYUSD": {
		"devnet":       PYUSDDevnetMint,
		"testnet":      PYUSDDevnetMint,
		"mainnet-beta": PYUSDMainnetMint,
	},
	"CASH": {
		"mainnet-beta": CASHMainnetMint,
	},
}

var token2022Stablecoins = map[string]struct{}{
	"PYUSD": {},
	"USDG":  {},
	"CASH":  {},
}

// DefaultRPCURL returns the default RPC endpoint for a Solana network.
func DefaultRPCURL(network string) string {
	switch network {
	case "devnet":
		return "https://api.devnet.solana.com"
	case "localnet":
		return "http://localhost:8899"
	default:
		return "https://api.mainnet-beta.solana.com"
	}
}

// ResolveMint converts a symbolic currency into a mint address.
// Returns an empty string for native SOL.
func ResolveMint(currency string, network string) string {
	normalized := strings.ToUpper(currency)
	switch normalized {
	case "SOL":
		return ""
	}
	if mints, ok := knownMints[normalized]; ok {
		if mint, ok := mints[network]; ok {
			return mint
		}
		return mints["mainnet-beta"]
	}
	return currency
}

// StablecoinSymbol returns a supported stablecoin symbol for a symbol or known mint.
func StablecoinSymbol(currency string) string {
	normalized := strings.ToUpper(currency)
	if _, ok := knownMints[normalized]; ok {
		return normalized
	}
	for symbol, mints := range knownMints {
		for _, mint := range mints {
			if currency == mint {
				return symbol
			}
		}
	}
	return ""
}

// DefaultTokenProgramForCurrency returns the known default token program for a currency or mint.
func DefaultTokenProgramForCurrency(currency string, network string) string {
	symbol := StablecoinSymbol(ResolveMint(currency, network))
	if symbol == "" {
		symbol = StablecoinSymbol(currency)
	}
	if _, ok := token2022Stablecoins[symbol]; ok {
		return Token2022Program
	}
	return TokenProgram
}

// MethodDetails contains Solana-specific challenge fields.
type MethodDetails struct {
	Network         string  `json:"network,omitempty"`
	Decimals        *uint8  `json:"decimals,omitempty"`
	TokenProgram    string  `json:"tokenProgram,omitempty"`
	FeePayer        *bool   `json:"feePayer,omitempty"`
	FeePayerKey     string  `json:"feePayerKey,omitempty"`
	Splits          []Split `json:"splits,omitempty"`
	RecentBlockhash string  `json:"recentBlockhash,omitempty"`
}

// Split is an additional transfer in the same asset.
type Split struct {
	Recipient           string `json:"recipient"`
	Amount              string `json:"amount"`
	Label               string `json:"label,omitempty"`
	Memo                string `json:"memo,omitempty"`
	AtaCreationRequired *bool  `json:"ataCreationRequired,omitempty"`
}

// CredentialPayload is sent by clients in the payment credential payload.
type CredentialPayload struct {
	Type        string `json:"type"`
	Transaction string `json:"transaction,omitempty"`
	Signature   string `json:"signature,omitempty"`
}
