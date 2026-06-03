package paykit

import (
	"time"

	"github.com/shopspring/decimal"
)

// Protocol enumerates the payment protocols the kit speaks. Order matters in
// [Config.Accept] and [Gate.Accept] (preference, not set).
type Protocol string

const (
	X402 Protocol = "x402"
	MPP  Protocol = "mpp"
)

// Stablecoin is a typed ticker symbol. The mint pubkey is resolved per
// [Network] via the package's mint table.
type Stablecoin string

const (
	USDC  Stablecoin = "USDC"
	USDT  Stablecoin = "USDT"
	PYUSD Stablecoin = "PYUSD"
	USDG  Stablecoin = "USDG"
	EURC  Stablecoin = "EURC"
)

// Network is the Solana cluster slug. Backing values match the Rust
// spine's `Network::as_str()` so a wire round-trip is trivial.
type Network string

const (
	SolanaMainnet  Network = "solana_mainnet"
	SolanaDevnet   Network = "solana_devnet"
	SolanaLocalnet Network = "solana_localnet"
)

// DefaultRPCURL is the public RPC endpoint the kit falls back to when
// [Config.RPCURL] is "". Localnet defaults to the hosted Surfpool
// endpoint (mainnet-state fork) so the example apps boot without a
// local validator. Mirrors Ruby PR #142 + Lua PR #141 caveat #2.
func (n Network) DefaultRPCURL() string {
	switch n {
	case SolanaMainnet:
		return "https://api.mainnet-beta.solana.com"
	case SolanaDevnet:
		return "https://api.devnet.solana.com"
	case SolanaLocalnet:
		return "https://402.surfnet.dev:8899"
	default:
		return ""
	}
}

// MintsLabel is the slug accepted by the cross-language mints registry.
// Surfpool clones mainnet state, so localnet resolves to the mainnet
// row when a stablecoin has no localnet-specific entry (caveat #1).
func (n Network) MintsLabel() string {
	switch n {
	case SolanaMainnet:
		return "mainnet"
	case SolanaDevnet:
		return "devnet"
	case SolanaLocalnet:
		return "localnet"
	default:
		return string(n)
	}
}

// CAIP2 returns the chain identifier the x402 + MPP accepts entries
// advertise so clients (like `pay --sandbox --x402 curl`) can match the
// offered network against their active wallet. Surfpool-localnet clones
// mainnet state, so it reuses the devnet genesis hash by convention.
func (n Network) CAIP2() string {
	switch n {
	case SolanaMainnet:
		return "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	default:
		return "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	}
}

// Address is a Solana account pubkey in base58 form. Kept as a typed
// string for ergonomics; revisit when a non-Solana rail ships.
type Address string

// Currency is the fiat unit a price is quoted in. Distinct from the
// settlement asset on purpose: `USD("0.10", USDC, USDT)` means "ten
// cents USD, settle in USDC or USDT."
type Currency string

const (
	USD Currency = "USD"
	EUR Currency = "EUR"
	GBP Currency = "GBP"
)

// Price is a denominated amount plus an ordered settlement preference
// list. Construct via [ParseUSD]/[MustParseUSD] etc.; do not build the
// struct directly so the internal invariant (positive decimal, valid
// currency) stays enforced.
type Price struct {
	amount      decimal.Decimal
	currency    Currency
	settlements []Stablecoin
}

// Amount returns the numeric component as a shopspring decimal. The
// money helpers never round; downstream conversion to mint base units
// happens at challenge-build time using the stablecoin's decimals.
func (p Price) Amount() decimal.Decimal { return p.amount }

// Currency returns the fiat unit ("USD", "EUR", "GBP").
func (p Price) Currency() Currency { return p.currency }

// Settlements returns the gate-level stablecoin preference order, or
// nil when the price was built without an explicit narrowing.
func (p Price) Settlements() []Stablecoin {
	if p.settlements == nil {
		return nil
	}
	out := make([]Stablecoin, len(p.settlements))
	copy(out, p.settlements)
	return out
}

// Operator bundles the merchant identity: where settled funds land,
// the Ed25519 signer used for x402 facilitator challenges, and whether
// that signer also pays Solana network fees on settlement.
//
// Zero-value semantics are filled in by [New]:
//
//   - Signer == nil    -> signer.Demo()
//   - Recipient == ""  -> Signer.Pubkey()
//   - FeePayer == true is the recommended default for merchant flows.
type Operator struct {
	Recipient Address
	Signer    Signer
	FeePayer  bool
}

// X402Config groups the x402-specific knobs.
type X402Config struct {
	// FacilitatorURL opts the client into delegated mode. When set the
	// kit POSTs to the facilitator's /verify and /settle endpoints and
	// never touches the chain itself. When "" (default) the kit runs
	// verification + settlement locally using Config.RPCURL + the
	// operator signer.
	FacilitatorURL string
	// Scheme is the x402 sub-scheme advertised in the 402 challenge.
	// Defaults to "exact"; the only scheme this SDK implements today.
	Scheme string
	// Signer overrides Operator.Signer for x402 facilitator cosigning.
	// Escape hatch only (DESIGN rule 3): leave nil to use the operator
	// signer, which is the documented path.
	Signer Signer
	// RequirePaymentIdentifier advertises the x402 v2 `payment-identifier`
	// extension with info.required=true on the 402 challenge, and rejects
	// any submitted credential that does not echo a valid `pay_`-shaped id
	// (coinbase x402 payment_identifier spec: HTTP 400). When false
	// (default) the challenge carries no `extensions` object, matching the
	// rust spine's PaymentRequiredEnvelope.extensions: None default.
	RequirePaymentIdentifier bool
}

// MPPConfig groups the MPP-charge-specific knobs.
type MPPConfig struct {
	Realm                  string
	ChallengeBindingSecret []byte
	ExpiresIn              time.Duration
}

// Config is the boot-time configuration passed to [New]. Zero-value
// [Config] is invalid because Network is required; every other field
// has a sensible default.
type Config struct {
	Network     Network
	Accept      []Protocol
	Stablecoins []Stablecoin
	RPCURL      string
	Operator    Operator
	X402        X402Config
	MPP         MPPConfig

	// Preflight runs the soundness checks at New() time. Defaults to
	// true; set to false (or export PAY_KIT_DISABLE_PREFLIGHT=1) to
	// skip when wiring the kit into tests that don't have an RPC
	// reachable.
	Preflight *bool

	// RecentBlockhashProvider lets tests inject a stub blockhash so the
	// kit never touches the wire. Production callers leave it nil; the
	// x402 adapter then calls Config.RPCURL's getLatestBlockhash at
	// challenge-build time (caveat #5).
	RecentBlockhashProvider func() (string, error)
}

// Payment is the verified proof attached to the request context after
// the middleware accepts a credential. Handlers read it via
// [PaymentFrom] / [IsPaid] / [IsPaidFor].
type Payment struct {
	Protocol          Protocol
	Gate              string
	Transaction       string
	SettlementHeaders map[string]string
	Raw               string
}
