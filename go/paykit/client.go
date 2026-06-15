package paykit

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

// DefaultSigner is populated by the signer package init() so
// paykit.New can fall back to the demo signer when Operator.Signer is
// nil, without paykit importing signer (which would cycle).
var DefaultSigner func() Signer

// Client is the umbrella entry point. Created via [New]; carries the
// resolved [Config] plus the per-protocol adapters wired against it.
//
// Adapters are wired lazily inside the protocols/ packages to avoid a
// circular import: paykit -> protocols/x402 -> paykit.
type Client struct {
	Config Config

	// Adapters are set during New() via the package-level registration
	// hooks each adapter registers in its init(). Tests can override
	// them through ClientOption.
	mppAdapter  Adapter
	x402Adapter Adapter

	// errorHandler renders the 402 (or other) response when a gate
	// rejects a request. Defaults to DefaultErrorHandler; override with
	// SetErrorHandler.
	errorHandler ErrorHandler
}

// ErrorHandler renders the response when a gated request is rejected.
// The supplied error is a *PaymentError carrying the canonical code,
// the gate, and the accepted protocols. Apps override it via
// [Client.SetErrorHandler] to customize the 402 body or status.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// SetErrorHandler replaces the response writer used on a rejected
// request. A nil handler restores [DefaultErrorHandler]. Not safe to
// call concurrently with in-flight requests; set it at startup.
func (c *Client) SetErrorHandler(h ErrorHandler) {
	if h == nil {
		h = DefaultErrorHandler
	}
	c.errorHandler = h
}

// Close releases any resources held by the client. Today the kit holds
// no background goroutines or pooled connections, so Close is a no-op
// that returns nil; it exists so callers can write `defer client.Close()`
// and stay forward-compatible when pooled RPC clients or replay-store
// flushers land.
func (c *Client) Close() error { return nil }

// Adapter is the minimal contract a payment protocol adapter implements.
// Each protocol package returns its [Adapter] via [RegisterAdapter] in
// init().
type Adapter interface {
	Protocol() Protocol
	// AcceptsEntry returns the protocol-specific entry the middleware
	// embeds in the 402 body's `accepts[]` array. Each protocol
	// package defines its own typed struct that satisfies the
	// [AcceptsEntry] marker.
	AcceptsEntry(gate *Gate) AcceptsEntry
	// ChallengeHeaders returns the per-protocol headers the middleware
	// stamps on the 402 response (e.g. WWW-Authenticate for MPP,
	// payment-required for x402).
	ChallengeHeaders(gate *Gate) map[string]string
	// VerifyAndSettle inspects the incoming request, validates the
	// credential, performs settlement (chain broadcast or
	// facilitator POST), and returns the verified [Payment].
	VerifyAndSettle(req *AdapterRequest) (*Payment, error)
}

// AcceptsEntry is the marker every protocol-specific accepts-entry
// struct satisfies. The middleware JSON-marshals these directly into
// the 402 body's `accepts[]` array; protocols emit typed structs (not
// map[string]any) per Ludo PR #146 review.
type AcceptsEntry interface {
	AcceptsProtocol() Protocol
}

// AdapterRequest is the cross-adapter handoff shape. Avoids dragging
// net/http into the adapter interface (which lets the adapters live in
// protocols/ without circular imports back into paykit).
type AdapterRequest struct {
	Method        string
	Path          string
	Host          string
	Authorization string
	PaymentSig    string
	// PaymentSigLegacy carries the legacy x402 `X-PAYMENT` header value
	// (base64 of a top-level {x402Version, scheme, network, payload}
	// envelope). The x402 adapter reads the canonical PaymentSig first
	// and falls back to this so it dual-accepts both wire shapes without
	// the middleware needing to know which version a client speaks.
	PaymentSigLegacy string
	Gate             *Gate
}

// Builder is the constructor each protocol package registers. paykit.New
// calls these once it has resolved the [Config].
type Builder func(cfg Config) (Adapter, error)

var registeredBuilders = map[Protocol]Builder{}

// RegisterAdapter is called from each protocol package's init() to plug
// its concrete [Adapter] into the umbrella [New] flow. Test helpers
// can swap implementations by re-registering before [New] runs.
func RegisterAdapter(protocol Protocol, b Builder) {
	registeredBuilders[protocol] = b
}

// MppAdapter returns the configured MPP adapter (nil when the kit was
// built without MPP support compiled in).
func (c *Client) MppAdapter() Adapter { return c.mppAdapter }

// X402Adapter returns the configured x402 adapter (nil when the kit
// was built without x402 support compiled in or X402 is missing from
// Config.Accept).
func (c *Client) X402Adapter() Adapter { return c.x402Adapter }

// New resolves zero-value defaults, runs the boot preflight when
// enabled, and returns a Client wired against the resolved config.
func New(cfg Config) (*Client, error) {
	if cfg.Network == "" {
		return nil, fmt.Errorf("%w: Config.Network is required", ErrInvalidConfig)
	}
	warnDeprecatedEnv()
	usingDefaultRPC := cfg.RPCURL == ""
	if usingDefaultRPC {
		cfg.RPCURL = cfg.Network.DefaultRPCURL()
	}
	if cfg.Network == SolanaMainnet && usingDefaultRPC {
		slog.Warn("paykit: using the public mainnet RPC; it is rate-limited and unsuitable for production traffic. Set Config.RPCURL to a dedicated endpoint.",
			"rpc", cfg.RPCURL)
	}
	if len(cfg.Accept) == 0 {
		cfg.Accept = []Protocol{X402, MPP}
	}
	if len(cfg.Stablecoins) == 0 {
		cfg.Stablecoins = []Stablecoin{USDC}
	}
	if cfg.Operator.Signer == nil {
		if DefaultSigner == nil {
			return nil, fmt.Errorf("%w: Operator.Signer is nil and no default registered; import signer", ErrInvalidConfig)
		}
		cfg.Operator.Signer = DefaultSigner()
		if cfg.Network == SolanaMainnet {
			return nil, ErrDemoSignerOnMainnet
		}
		slog.Warn("paykit: demo signer in use; do not ship to production",
			"pubkey", cfg.Operator.Signer.Pubkey())
	}
	if cfg.Operator.Recipient == "" {
		cfg.Operator.Recipient = cfg.Operator.Signer.Pubkey()
	}
	if cfg.MPP.Realm == "" {
		cfg.MPP.Realm = "PayKit"
	}
	if cfg.MPP.ExpiresIn == 0 {
		cfg.MPP.ExpiresIn = 120_000_000_000 // 2 minutes in ns
	}
	if cfg.X402.Scheme == "" {
		cfg.X402.Scheme = "exact"
	}
	// MPP HMAC secret auto-resolution (caveat #4). Resolve only when
	// MPP is actually accepted -- x402-only callers must never be
	// forced to supply (or have a .env generated for) an MPP secret,
	// and the resolution is independent of preflight so a server with
	// Preflight=false still gets a usable secret.
	if containsProtocol(cfg.Accept, MPP) && len(cfg.MPP.ChallengeBindingSecret) == 0 {
		secret, err := resolveMPPSecret()
		if err != nil {
			return nil, fmt.Errorf("paykit: %w", err)
		}
		cfg.MPP.ChallengeBindingSecret = secret
	}

	c := &Client{Config: cfg, errorHandler: DefaultErrorHandler}
	for _, s := range cfg.Accept {
		b, ok := registeredBuilders[s]
		if !ok {
			continue
		}
		adapter, err := b(cfg)
		if err != nil {
			return nil, fmt.Errorf("paykit: %s adapter: %w", s, err)
		}
		switch s {
		case MPP:
			c.mppAdapter = adapter
		case X402:
			c.x402Adapter = adapter
		}
	}
	if preflightEnabled(cfg) {
		if err := runPreflight(cfg); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func preflightEnabled(cfg Config) bool {
	if os.Getenv("PAY_KIT_DISABLE_PREFLIGHT") == "1" {
		return false
	}
	if cfg.Preflight != nil {
		return *cfg.Preflight
	}
	return true
}
