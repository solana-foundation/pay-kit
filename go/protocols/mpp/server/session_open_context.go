package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

type openAdmission string

const (
	openAdmissionHost         openAdmission = "host"
	openAdmissionCoreVerifier openAdmission = "core-verifier"
	openAdmissionRPC          openAdmission = "rpc-confirmed"
)

// openFundingContext binds admitted credit to this server's funding policy.
// Deposits, voucher watermarks and transaction representations can change during
// a session; they are deliberately excluded so a top-up remains replayable.
func (s *SessionServer) openFundingContext(payload *intents.OpenPayload, admission openAdmission) string {
	program := paymentchannels.ProgramPubkey()
	if s.config.ProgramID != nil {
		program = *s.config.ProgramID
	}
	authority := s.config.SettlementAuthority
	if authority == "" {
		authority = intents.SessionSettlementAuthorityClientVoucher
	}
	strategy := ""
	if payload.Mode == intents.SessionModePull && s.config.PullVoucherStrategy != nil {
		strategy = string(*s.config.PullVoucherStrategy)
	}
	kind := "host-delegation"
	if paymentChannelOpen(payload) {
		kind = "payment-channel"
	} else {
		// Host-managed delegation never invokes the payment-channel verifier.
		admission = openAdmissionHost
	}
	network := paycore.ParseSolanaNetwork(s.config.Network).String()
	distribution := sessionDistributionHash(s.config.Splits)
	// A fixed, versioned JSON string vector gives unambiguous boundaries and
	// canonical ordering without relying on map iteration or function identity.
	encoded, _ := json.Marshal([]string{
		"go-mpp-open-funding-v1", s.config.Operator, s.config.Recipient,
		paycore.ResolveMint(s.config.Currency, network), network, program.String(),
		hex.EncodeToString(distribution[:]), kind, string(payload.Mode), string(authority), strategy,
		strconv.FormatUint(s.config.MaxCap, 10), string(admission),
	})
	hash := sha256.Sum256(encoded)
	return "v1:" + hex.EncodeToString(hash[:])
}

func checkOpenFundingContext(state *ChannelState, expected string) error {
	if state.OpenFundingContext == "" {
		return fmt.Errorf("channel %s has no open funding context; cannot replay an unbound record", state.ChannelID)
	}
	if state.OpenFundingContext != expected {
		return fmt.Errorf("channel %s belongs to a different open funding context", state.ChannelID)
	}
	return nil
}
