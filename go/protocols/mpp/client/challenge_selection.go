// Session challenge selection.
//
// Servers can return multiple 402 challenges for the same resource (one per
// supported currency or intent). These helpers pick the Solana session
// challenge a client should open, filtering by network, currency, and funding
// mode while preserving server order otherwise.
package client

import (
	"fmt"

	"github.com/solana-foundation/pay-kit/go/paycore"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// SessionRequestModes returns the funding modes a session challenge offers.
// An omitted or empty modes list means push-only.
func SessionRequestModes(request intents.SessionRequest) []intents.SessionMode {
	if len(request.Modes) > 0 {
		return request.Modes
	}
	return []intents.SessionMode{intents.SessionModePush}
}

// SelectSessionChallengeOptions filters the session challenges a client is
// willing to open. Zero-value fields do not filter.
type SelectSessionChallengeOptions struct {
	// Network is the Solana network the client wants to pay on. Use the
	// paycore.Network* constants; raw strings (including the legacy
	// "mainnet-beta" alias) are folded onto the canonical slug before
	// matching.
	Network paycore.SolanaNetwork

	// Currencies are the currency symbols or mint addresses the client wants
	// to pay with. A challenge matches when its currency resolves to the same
	// mint as any entry.
	Currencies []string

	// Modes are the funding modes the client supports. When set, the selected
	// challenge must advertise at least one of them (an omitted or empty
	// challenge modes list advertises push only).
	Modes []intents.SessionMode
}

// SelectedSessionChallenge is a session challenge paired with its decoded
// request.
type SelectedSessionChallenge struct {
	// Challenge is the matched 402 session challenge, kept whole so it can be
	// echoed back when serializing the payment credential.
	Challenge core.PaymentChallenge

	// Request is the challenge's session request decoded from its base64url
	// JSON request value (currency, cap, recipient, modes, ...).
	Request intents.SessionRequest
}

// SelectSessionChallenge selects the Solana session challenge the client
// should open, or nil when none matches. A challenge with the session intent
// but an undecodable request is an error.
func SelectSessionChallenge(
	challenges []core.PaymentChallenge,
	options SelectSessionChallengeOptions,
) (*SelectedSessionChallenge, error) {
	var candidates []SelectedSessionChallenge

	for _, challenge := range challenges {
		if challenge.Method != core.NewMethodName("solana") || !challenge.Intent.IsSession() {
			continue
		}
		var request intents.SessionRequest
		if err := challenge.Request.Decode(&request); err != nil {
			return nil, fmt.Errorf("invalid Solana session challenge request: %w", err)
		}
		if !matchesSessionNetwork(request, options.Network) {
			continue
		}
		if !matchesSessionCurrency(request, options.Currencies) {
			continue
		}
		candidates = append(candidates, SelectedSessionChallenge{Challenge: challenge, Request: request})
	}

	if len(options.Modes) == 0 {
		if len(candidates) == 0 {
			return nil, nil
		}
		return &candidates[0], nil
	}

	for _, candidate := range candidates {
		challengeModes := SessionRequestModes(candidate.Request)
		for _, accepted := range options.Modes {
			for _, mode := range challengeModes {
				if mode == accepted {
					selected := candidate
					return &selected, nil
				}
			}
		}
	}
	return nil, nil
}

// SelectSessionChallengeFromHeaders parses WWW-Authenticate header values and
// selects the Solana session challenge the client should open. Pass
// response.Header.Values(core.WWWAuthenticateHeader).
func SelectSessionChallengeFromHeaders(
	headers []string,
	options SelectSessionChallengeOptions,
) (*SelectedSessionChallenge, error) {
	return SelectSessionChallenge(core.ParseWWWAuthenticateAll(headers), options)
}

// matchesSessionNetwork reports whether the challenge network equals the
// requested network, treating mainnet and mainnet-beta as equivalent.
func matchesSessionNetwork(request intents.SessionRequest, network paycore.SolanaNetwork) bool {
	if network == "" {
		return true
	}
	challengeNetwork := string(paycore.NetworkMainnet)
	if request.Network != nil {
		challengeNetwork = *request.Network
	}
	return paycore.ParseSolanaNetwork(challengeNetwork) == paycore.ParseSolanaNetwork(string(network))
}

// matchesSessionCurrency reports whether the challenge currency resolves to
// the same mint as any accepted currency on the challenge network.
func matchesSessionCurrency(request intents.SessionRequest, currencies []string) bool {
	if len(currencies) == 0 {
		return true
	}
	network := ""
	if request.Network != nil {
		network = *request.Network
	}
	challengeMint := paycore.ResolveMint(request.Currency, network)
	for _, accepted := range currencies {
		if paycore.ResolveMint(accepted, network) == challengeMint {
			return true
		}
	}
	return false
}
