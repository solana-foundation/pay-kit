package server

import (
	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// VerifyChargeTransactionPreBroadcast runs the RPC-free pre-broadcast
// verification a charge server applies to a credential transaction before it
// co-signs, simulates, or broadcasts. It is the deterministic half of
// [Mpp.VerifyCredential]: the same split-count, address-lookup-table,
// compute-budget, network-blockhash, and transfer/memo/allowlist checks that
// run in verifyTransaction up to the simulate/send boundary, with no HMAC
// challenge step and no live RPC.
//
// It exists so the cross-SDK conformance harness can exercise the verifier's
// accept/reject decision against a fixed transaction without surfpool. The
// caller supplies the decoded charge request and method details (the same
// values the challenge would carry) plus the network slug used for the
// Surfpool wrong-cluster guard. A nil return means the transaction conforms;
// a non-nil error carries the structured rejection code.
func VerifyChargeTransactionPreBroadcast(
	transactionBase64 string,
	request intents.ChargeRequest,
	details paycore.MethodDetails,
	network string,
) error {
	if transactionBase64 == "" {
		return core.NewError(core.ErrCodeMissingTransaction, "missing transaction data in credential payload")
	}
	if err := validateSplitsCount(details.Splits); err != nil {
		return err
	}
	tx, err := solanatx.DecodeTransactionBase64(transactionBase64)
	if err != nil {
		return err
	}
	if len(tx.Message.AddressTableLookups) > 0 {
		return core.NewError(core.ErrCodeInvalidPayload, "v0 transactions with address lookup tables are not supported")
	}
	if err := validateComputeBudgetInstructions(tx); err != nil {
		return err
	}
	if err := CheckNetworkBlockhash(network, tx.Message.RecentBlockhash.String()); err != nil {
		return err
	}
	amount, err := request.ParseAmount()
	if err != nil {
		return err
	}
	recipient, err := solana.PublicKeyFromBase58(request.Recipient)
	if err != nil {
		return core.WrapError(core.ErrCodeInvalidConfig, "invalid recipient", err)
	}
	return verifyTransfersAgainstChallenge(tx, amount, request.Currency, recipient, request.ExternalID, details)
}
