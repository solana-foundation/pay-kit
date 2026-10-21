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
// [Mpp.VerifyCredentialWithExpected]: the same split-count, address-lookup-table,
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
	tx, err := decodeCredentialTransaction(transactionBase64)
	if err != nil {
		return err
	}
	if len(tx.Message.AddressTableLookups) > 0 {
		return core.NewError(core.ErrCodeInvalidPayload, "v0 transactions with address lookup tables are not supported")
	}
	feeSponsored := details.FeePayer != nil && *details.FeePayer
	if err := validateComputeBudgetInstructions(tx, feeSponsored); err != nil {
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
	if err := verifyTransfersAgainstChallenge(tx, amount, request.Currency, recipient, request.ExternalID, details); err != nil {
		return err
	}
	var serverFeePayer *solana.PublicKey
	if feeSponsored {
		serverFeePayer = feePayerKey(details)
		if serverFeePayer == nil {
			return core.NewError(core.ErrCodeInvalidPayload, "fee-sponsored challenge carries no valid feePayerKey")
		}
	}
	return verifyClientSignatures(tx, serverFeePayer)
}

// verifyClientSignatures refuses a credential transaction whose signature
// list is not exactly the message's required count, or whose client
// signatures do not verify over the message, before the server claims,
// co-signs or sends it (RULINGS SIG1). serverFeePayer is the server's own
// fee-payer key when it sponsors fees: it must be account zero, whose slot
// the server overwrites when it co-signs. Both the pre-broadcast verifier
// and the live verifyTransaction call it.
func verifyClientSignatures(tx *solana.Transaction, serverFeePayer *solana.PublicKey) error {
	if err := solanatx.VerifyClientSignatures(tx, serverFeePayer); err != nil {
		return core.WrapError(core.ErrCodeInvalidPayload, "invalid payload: verify client signatures", err)
	}
	return nil
}

// decodeCredentialTransaction decodes a client-supplied credential
// transaction through the shared version policy (legacy and v0 accepted).
// Every decode failure is reported as an invalid payload.
func decodeCredentialTransaction(transactionBase64 string) (*solana.Transaction, error) {
	tx, err := solanatx.DecodeTransactionBase64(transactionBase64)
	if err != nil {
		return nil, &core.Error{Code: core.ErrCodeInvalidPayload, Message: err.Error(), Err: err}
	}
	return tx, nil
}
