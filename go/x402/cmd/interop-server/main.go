package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gagliardetto/solana-go"
)

const (
	defaultResourcePath     = "/protected"
	defaultPrice            = "$0.001"
	defaultSettlementHeader = "x-fixture-settlement"
	defaultDecimals         = 6
	defaultTokenProgram     = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	token2022Program        = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
	lighthouseProgram       = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
	defaultMaxTimeout       = 60
	duplicateCacheTTL       = 120 * time.Second
	maxComputeUnitPrice     = 5_000_000
	maxMemoBytes            = 256
)

var (
	computeBudgetProgramID = solana.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")
	memoProgramID          = solana.MustPublicKeyFromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
)

// Lighthouse instructions are passed through by program-ID match alone, matching
// the canonical spines:
//   - rust/src/protocol/schemes/exact/verify.rs:266 — `if program == LIGHTHOUSE_PROGRAM || program == MEMO_PROGRAM { continue; }`
//   - typescript/packages/x402/src/facilitator/exact/scheme.ts:300 — same shape
// No discriminator or account-count allowlist is enforced here: inventing one
// in a single language port would diverge from real-world Phantom/Solflare
// transactions that the Rust + TypeScript adapters accept. Tightening this is
// a protocol-wide decision that must land in the Rust spine first; tracked at
// /notes/lighthouse-allowlist-tracking.md.

// CAIP-2 network identifiers shared with the TypeScript spine.
const (
	solanaMainnetCAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	solanaDevnetCAIP2  = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	solanaTestnetCAIP2 = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
)

// stablecoinMintsByNetwork mirrors STABLECOIN_MINTS from the TypeScript
// reference (typescript/packages/x402/src/protocol/schemes/exact/constants.ts).
// Aliases are resolved at the env-read boundary so the rest of the server
// always sees canonical base58 mint addresses.
var stablecoinMintsByNetwork = map[string]map[string]string{
	"USDC": {
		solanaMainnetCAIP2: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		solanaDevnetCAIP2:  "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
	},
	"USDT": {
		solanaMainnetCAIP2: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
	},
	"USDG": {
		solanaMainnetCAIP2: "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH",
		solanaDevnetCAIP2:  "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
		solanaTestnetCAIP2: "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
	},
	"PYUSD": {
		solanaMainnetCAIP2: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
		solanaDevnetCAIP2:  "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
		solanaTestnetCAIP2: "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
	},
	"CASH": {
		solanaMainnetCAIP2: "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH",
	},
}

// knownMintAliases lists the case-insensitive currency-name aliases that
// resolveMintAlias understands. Kept stable for error messages.
var knownMintAliases = []string{"USDC", "USDT", "USDG", "PYUSD", "CASH"}

// resolveMintAlias returns the canonical base58 mint address for a given
// input on the configured CAIP-2 network. The input may already be a base58
// mint (in which case it is returned unchanged) or a known stablecoin alias
// (USDC, USDT, USDG, PYUSD, CASH). Unknown aliases and aliases without a
// configured mint for the network return a descriptive error.
func resolveMintAlias(input string, network string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", fmt.Errorf("mint is required")
	}
	upper := strings.ToUpper(trimmed)
	if mintsByNetwork, ok := stablecoinMintsByNetwork[upper]; ok {
		if mint, ok := mintsByNetwork[network]; ok {
			return mint, nil
		}
		return "", fmt.Errorf("alias %s has no configured mint for network %s", upper, network)
	}
	if _, err := solana.PublicKeyFromBase58(trimmed); err != nil {
		return "", fmt.Errorf("mint %q is neither a base58 address nor a known alias (accepted aliases: %s)", input, strings.Join(knownMintAliases, ", "))
	}
	return trimmed, nil
}

type serverState struct {
	rpcURL            string
	network           string
	mint              string
	payTo             string
	feePayer          solana.PrivateKey
	amount            string
	extraOfferedMints []string
	memo              string
	httpClient        *http.Client
}

type paymentEnvelope struct {
	X402Version int                  `json:"x402Version"`
	Accepts     []paymentRequirement `json:"accepts"`
	Resource    map[string]any       `json:"resource,omitempty"`
}

type paymentRequirement struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Asset             string         `json:"asset"`
	Amount            string         `json:"amount"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds,omitempty"`
	Extra             map[string]any `json:"extra,omitempty"`
}

type paymentSignatureEnvelope struct {
	X402Version int                `json:"x402Version"`
	Accepted    paymentRequirement `json:"accepted"`
	Payload     map[string]string  `json:"payload"`
}

type duplicateSettlementCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	now     func() time.Time
}

var settlementCache = newDuplicateSettlementCache()

func newDuplicateSettlementCache() *duplicateSettlementCache {
	return &duplicateSettlementCache{
		entries: map[string]time.Time{},
		now:     time.Now,
	}
}

func (cache *duplicateSettlementCache) claim(key string) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	now := cache.now()
	for cached, seenAt := range cache.entries {
		if now.Sub(seenAt) > duplicateCacheTTL {
			delete(cache.entries, cached)
		}
	}
	if _, ok := cache.entries[key]; ok {
		return false
	}
	cache.entries[key] = now
	return true
}

func (cache *duplicateSettlementCache) release(key string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	delete(cache.entries, key)
}

func writeJSON(response http.ResponseWriter, status int, payload map[string]any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	response.Header().Set("content-type", "application/json")
	response.WriteHeader(status)
	if _, err := response.Write(encoded); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func writeJSONWithHeaders(response http.ResponseWriter, status int, headers map[string]string, payload map[string]any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	response.Header().Set("content-type", "application/json")
	for key, value := range headers {
		response.Header().Set(key, value)
	}
	response.WriteHeader(status)
	if _, err := response.Write(encoded); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func capabilityPayload(implementation string) map[string]any {
	return map[string]any{
		"implementation":    implementation,
		"role":              "server",
		"capabilities":      []string{"exact"},
		"plannedBoundaries": []string{"exact", "upto", "session", "batch-settlement"},
	}
}

func exactRequirementForMint(state serverState, mint string) paymentRequirement {
	requirement := paymentRequirement{
		Scheme:            "exact",
		Network:           state.network,
		Asset:             mint,
		Amount:            state.amount,
		PayTo:             state.payTo,
		MaxTimeoutSeconds: defaultMaxTimeout,
		Extra: map[string]any{
			"decimals":     defaultDecimals,
			"feePayer":     state.feePayer.PublicKey().String(),
			"tokenProgram": defaultTokenProgramForMint(mint),
		},
	}
	if state.memo != "" {
		requirement.Extra["memo"] = state.memo
	}
	return requirement
}

func exactRequirement(state serverState) paymentRequirement {
	return exactRequirementForMint(state, state.mint)
}

func exactChallengePayload(state serverState) paymentEnvelope {
	accepts := []paymentRequirement{exactRequirement(state)}
	for _, mint := range state.extraOfferedMints {
		if mint == "" {
			continue
		}
		accepts = append(accepts, exactRequirementForMint(state, mint))
	}
	return paymentEnvelope{
		X402Version: 2,
		Accepts:     accepts,
		Resource: map[string]any{
			"type": "http",
			"uri":  defaultResourcePath,
		},
	}
}

func defaultTokenProgramForMint(mint string) string {
	switch strings.ToUpper(strings.TrimSpace(mint)) {
	case "USDG", "PYUSD", "CASH":
		return token2022Program
	}
	switch strings.TrimSpace(mint) {
	case "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH",
		"4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
		"CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
		"2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
		"CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH":
		return token2022Program
	default:
		return defaultTokenProgram
	}
}

func uptoChallengePayload() map[string]any {
	return map[string]any{
		"x402Version": 2,
		"accepts": []map[string]any{
			{
				"scheme":  "upto",
				"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"asset":   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"amount":  "1000",
			},
		},
	}
}

func writePaymentRequired(response http.ResponseWriter, challenge map[string]any) {
	encoded, err := json.Marshal(challenge)
	if err != nil {
		panic(err)
	}
	response.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(encoded))
	writeJSON(response, http.StatusPaymentRequired, map[string]any{"error": "payment_required"})
}

func writeExactPaymentRequired(response http.ResponseWriter, state serverState) {
	challenge := exactChallengePayload(state)
	encoded, err := json.Marshal(challenge)
	if err != nil {
		panic(err)
	}
	response.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(encoded))
	writeJSON(response, http.StatusPaymentRequired, map[string]any{"error": "payment_required"})
}

func sessionChallengePayload() map[string]any {
	return map[string]any{
		"intent":           "session",
		"payee":            "session-payee",
		"mint":             "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		"suggestedDeposit": "10000",
		"unitPrice":        "25",
		"unitType":         "llm_token",
	}
}

func batchSettlementChallengePayload() map[string]any {
	return map[string]any{
		"x402Version": 2,
		"accepts": []map[string]any{
			{
				"scheme":        "batch-settlement",
				"network":       "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
				"receiver":      "batch-receiver",
				"token":         "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				"maximumAmount": "1000",
			},
		},
	}
}

func readRequiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(fmt.Sprintf("%s is required", name))
	}
	return value
}

func readEnvWithDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func readCSVEnv(name string) []string {
	raw := os.Getenv(name)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func normalizeAmount(price string) string {
	trimmed := strings.TrimSpace(price)
	if len(trimmed) > 0 && trimmed[0] == '$' {
		trimmed = trimmed[1:]
	}
	amountPart := strings.Fields(trimmed)[0]
	parts := strings.SplitN(amountPart, ".", 2)
	whole, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		panic(fmt.Sprintf("invalid X402_INTEROP_PRICE: %s", price))
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	if len(fraction) > defaultDecimals {
		panic(fmt.Sprintf("X402_INTEROP_PRICE has too many decimal places: %s", price))
	}
	fraction = fraction + strings.Repeat("0", defaultDecimals-len(fraction))
	fractional, err := strconv.ParseUint(fraction, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("invalid X402_INTEROP_PRICE: %s", price))
	}
	return strconv.FormatUint((whole*1_000_000)+fractional, 10)
}

func keypairFromJSONSecret(raw string) solana.PrivateKey {
	var values []byte
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		panic(fmt.Sprintf("decode Solana secret key: %s", err))
	}
	if len(values) != 64 {
		panic("expected a 64-byte Solana secret key JSON array")
	}
	privateKey := solana.PrivateKey(values)
	if _, err := solana.ValidatePrivateKey(privateKey); err != nil {
		panic(err)
	}
	return privateKey
}

func readState() serverState {
	network := readEnvWithDefault("X402_INTEROP_NETWORK", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1")
	rawMint := readEnvWithDefault("X402_INTEROP_MINT", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
	resolvedMint, err := resolveMintAlias(rawMint, network)
	if err != nil {
		panic(fmt.Sprintf("X402_INTEROP_MINT: %s", err))
	}
	rawExtra := readCSVEnv("X402_INTEROP_EXTRA_OFFERED_MINTS")
	resolvedExtra := make([]string, 0, len(rawExtra))
	for _, candidate := range rawExtra {
		resolved, err := resolveMintAlias(candidate, network)
		if err != nil {
			panic(fmt.Sprintf("X402_INTEROP_EXTRA_OFFERED_MINTS: %s", err))
		}
		resolvedExtra = append(resolvedExtra, resolved)
	}
	return serverState{
		rpcURL:            readRequiredEnv("X402_INTEROP_RPC_URL"),
		network:           network,
		mint:              resolvedMint,
		payTo:             readRequiredEnv("X402_INTEROP_PAY_TO"),
		feePayer:          keypairFromJSONSecret(readRequiredEnv("X402_INTEROP_FACILITATOR_SECRET_KEY")),
		amount:            normalizeAmount(readEnvWithDefault("X402_INTEROP_PRICE", defaultPrice)),
		extraOfferedMints: resolvedExtra,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func paymentRequirementMatches(left paymentRequirement, right paymentRequirement) bool {
	return reflect.DeepEqual(normalizeRequirement(left), normalizeRequirement(right))
}

func acceptedExactRequirement(state serverState, accepted paymentRequirement) (paymentRequirement, bool) {
	for _, requirement := range exactChallengePayload(state).Accepts {
		if paymentRequirementMatches(accepted, requirement) {
			return requirement, true
		}
	}
	return paymentRequirement{}, false
}

func normalizeRequirement(requirement paymentRequirement) paymentRequirement {
	normalized := requirement
	normalized.Extra = map[string]any{}
	for key, value := range requirement.Extra {
		normalized.Extra[key] = fmt.Sprint(value)
	}
	return normalized
}

func decodePaymentSignature(headerValue string) (paymentSignatureEnvelope, error) {
	decoded, err := base64.StdEncoding.DecodeString(headerValue)
	if err != nil {
		return paymentSignatureEnvelope{}, err
	}
	var payload paymentSignatureEnvelope
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return paymentSignatureEnvelope{}, err
	}
	return payload, nil
}

func settleExactPayment(state serverState, headerValue string) (string, error) {
	payload, err := decodePaymentSignature(headerValue)
	if err != nil {
		return "", err
	}
	if payload.X402Version != 2 {
		return "", fmt.Errorf("unsupported x402Version: %d", payload.X402Version)
	}
	requirement, ok := acceptedExactRequirement(state, payload.Accepted)
	if !ok {
		return "", fmt.Errorf("accepted payment requirement does not match server challenge")
	}

	encodedTransaction := payload.Payload["transaction"]
	if encodedTransaction == "" {
		return "", fmt.Errorf("payment payload is missing transaction")
	}

	transaction, err := solana.TransactionFromBase64(encodedTransaction)
	if err != nil {
		return "", err
	}
	if err := verifyExactTransaction(transaction, requirement); err != nil {
		return "", err
	}
	// Bind the transaction's message fee-payer (account key 0) to the
	// server's configured fee-payer. Without this guard a malicious client
	// could nominate a different message payer and rely on the facilitator
	// being in the signer set to drain SOL via co-signing.
	if len(transaction.Message.AccountKeys) == 0 {
		return "", fmt.Errorf("invalid_exact_svm_payload_transaction_fee_payer_missing")
	}
	if !transaction.Message.AccountKeys[0].Equals(state.feePayer.PublicKey()) {
		return "", fmt.Errorf("invalid_exact_svm_payload_transaction_fee_payer_mismatch")
	}
	cacheKey := transactionCacheKey(encodedTransaction)
	if !settlementCache.claim(cacheKey) {
		return "", fmt.Errorf("duplicate_settlement")
	}
	settled := false
	defer func() {
		if !settled {
			settlementCache.release(cacheKey)
		}
	}()
	if err := verifyTokenAccountsExist(state, transaction, requirement); err != nil {
		return "", err
	}

	if _, err := transaction.PartialSign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(state.feePayer.PublicKey()) {
			return &state.feePayer
		}
		return nil
	}); err != nil {
		return "", err
	}
	if err := transaction.VerifySignatures(); err != nil {
		return "", err
	}

	settlement, err := sendTransaction(state, transaction)
	if err != nil {
		return "", err
	}
	settled = true
	return settlement, nil
}

func transactionCacheKey(encodedTransaction string) string {
	sum := sha256.Sum256([]byte(encodedTransaction))
	return base64.StdEncoding.EncodeToString(sum[:])
}

type transferCheckedFields struct {
	source       solana.PublicKey
	mint         solana.PublicKey
	destination  solana.PublicKey
	authority    solana.PublicKey
	amount       uint64
	decimals     uint8
	tokenProgram solana.PublicKey
}

func verifyExactTransaction(transaction *solana.Transaction, requirement paymentRequirement) error {
	if !transaction.Message.IsVersioned() {
		return fmt.Errorf("payment transaction must be versioned")
	}
	instructions := transaction.Message.Instructions
	if len(instructions) < 3 || len(instructions) > 6 {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_instructions_length")
	}
	if err := verifyComputeLimitInstruction(transaction, instructions[0]); err != nil {
		return err
	}
	if err := verifyComputePriceInstruction(transaction, instructions[1]); err != nil {
		return err
	}
	transfer, err := parseTransferCheckedInstruction(transaction, instructions[2])
	if err != nil {
		return err
	}
	// Mirror the Rust spine binding (rust/crates/x402/src/protocol/schemes/exact/verify.rs:73-80)
	// and the PHP/Ruby/Lua ports: the on-chain transfer's token program MUST match the
	// program declared in requirement.Extra["tokenProgram"]. Without this check, a Token-2022
	// transfer can satisfy an SPL Token requirement (or vice versa), because the
	// destination-ATA derivation below uses the parsed program rather than the required one.
	requiredTokenProgramRaw, ok := requirement.Extra["tokenProgram"].(string)
	if !ok || requiredTokenProgramRaw == "" {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_token_program")
	}
	requiredTokenProgram, err := solana.PublicKeyFromBase58(requiredTokenProgramRaw)
	if err != nil {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_token_program")
	}
	if !transfer.tokenProgram.Equals(requiredTokenProgram) {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_token_program")
	}
	if err := verifyOptionalInstructions(transaction, instructions[3:], requirement, transfer); err != nil {
		return err
	}
	feePayer, err := solana.PublicKeyFromBase58(fmt.Sprint(requirement.Extra["feePayer"]))
	if err != nil {
		return fmt.Errorf("invalid feePayer: %w", err)
	}
	// Codex P1.2 (May 2026): the previous unconditional "fee-payer in any
	// instruction account" loop was both over-broad (false-positive on the
	// legitimate destination-ATA-create flow, where the SPL Associated Token
	// Account program requires the rent payer at accounts[0]) and incomplete
	// (it did not distinguish *role* — fee-payer as transfer authority/source
	// is the real attack the Rust spine bans at
	// rust/src/protocol/schemes/exact/verify.rs:382). Tightened rule:
	//   * fee-payer is allowed at accounts[0] of a *validated* ATA-create ix
	//     (the canonical rent-payer position).
	//   * fee-payer is allowed inside Lighthouse instruction account lists
	//     (the Rust spine has NO fee-payer-in-accounts sweep at all; it only
	//     blocks fee-payer as transfer authority at verify.rs:382, and accepts
	//     any Lighthouse ix by program-id alone at verify.rs:263 — wallets such
	//     as Phantom/Solflare routinely add `AssertAccount*` ixs that reference
	//     the fee-payer's pubkey to guard against malicious facilitator rewrites).
	//   * fee-payer in any other (non-Lighthouse, non-ATA-create-payer-slot)
	//     instruction account list is rejected with a distinct typed error.
	//   * fee-payer as transfer authority / source is still rejected with the
	//     spine-aligned `_transferring_funds` error.
	if transfer.authority.Equals(feePayer) || transfer.source.Equals(feePayer) {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_fee_payer_transferring_funds")
	}
	for index, instruction := range instructions {
		if index == 2 {
			// instruction[2] is the transferChecked; its fee-payer-as-role
			// abuses are already covered by the spine-aligned guard above.
			continue
		}
		program, err := programID(transaction, instruction)
		if err != nil {
			return err
		}
		if program.String() == lighthouseProgram {
			// Mirror rust/src/protocol/schemes/exact/verify.rs:263 — Lighthouse
			// ixs are passed through by program-id alone; the spine never
			// inspects their account lists for the managed fee-payer.
			continue
		}
		isATACreatePayerSlot := index >= 3 && isValidatedATACreateInstruction(transaction, instruction, requirement, transfer)
		for accountPosition, accountIndex := range instruction.Accounts {
			account, err := accountAt(transaction, accountIndex)
			if err != nil {
				return err
			}
			if !account.Equals(feePayer) {
				continue
			}
			if isATACreatePayerSlot && accountPosition == 0 {
				continue
			}
			return fmt.Errorf("invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts")
		}
	}
	mint, err := solana.PublicKeyFromBase58(requirement.Asset)
	if err != nil {
		return fmt.Errorf("invalid asset: %w", err)
	}
	if !transfer.mint.Equals(mint) {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_mint")
	}
	expectedAmount, err := strconv.ParseUint(requirement.Amount, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %w", err)
	}
	if transfer.amount != expectedAmount {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_amount")
	}
	payTo, err := solana.PublicKeyFromBase58(requirement.PayTo)
	if err != nil {
		return fmt.Errorf("invalid payTo: %w", err)
	}
	expectedDestination, _, err := solana.FindAssociatedTokenAddressWithProgram(payTo, mint, transfer.tokenProgram)
	if err != nil {
		return err
	}
	if !transfer.destination.Equals(expectedDestination) {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_destination")
	}
	if decimals, err := strconv.ParseUint(fmt.Sprint(requirement.Extra["decimals"]), 10, 8); err == nil && transfer.decimals != uint8(decimals) {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_decimals")
	}
	return nil
}

func verifyComputeLimitInstruction(transaction *solana.Transaction, instruction solana.CompiledInstruction) error {
	program, err := programID(transaction, instruction)
	if err != nil {
		return err
	}
	if !program.Equals(computeBudgetProgramID) || len(instruction.Data) != 5 || instruction.Data[0] != 2 {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction")
	}
	return nil
}

func verifyComputePriceInstruction(transaction *solana.Transaction, instruction solana.CompiledInstruction) error {
	program, err := programID(transaction, instruction)
	if err != nil {
		return err
	}
	if !program.Equals(computeBudgetProgramID) || len(instruction.Data) != 9 || instruction.Data[0] != 3 {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_instructions_compute_price_instruction")
	}
	price := binary.LittleEndian.Uint64(instruction.Data[1:])
	if price > maxComputeUnitPrice {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high")
	}
	return nil
}

func parseTransferCheckedInstruction(transaction *solana.Transaction, instruction solana.CompiledInstruction) (transferCheckedFields, error) {
	program, err := programID(transaction, instruction)
	if err != nil {
		return transferCheckedFields{}, err
	}
	if !program.Equals(solana.TokenProgramID) && !program.Equals(solana.Token2022ProgramID) {
		return transferCheckedFields{}, fmt.Errorf("invalid_exact_svm_payload_transaction_transfer_program")
	}
	if len(instruction.Accounts) < 4 || len(instruction.Data) != 10 || instruction.Data[0] != 12 {
		return transferCheckedFields{}, fmt.Errorf("invalid_exact_svm_payload_transaction_transfer_checked")
	}
	source, err := accountAt(transaction, instruction.Accounts[0])
	if err != nil {
		return transferCheckedFields{}, err
	}
	mint, err := accountAt(transaction, instruction.Accounts[1])
	if err != nil {
		return transferCheckedFields{}, err
	}
	destination, err := accountAt(transaction, instruction.Accounts[2])
	if err != nil {
		return transferCheckedFields{}, err
	}
	authority, err := accountAt(transaction, instruction.Accounts[3])
	if err != nil {
		return transferCheckedFields{}, err
	}
	return transferCheckedFields{
		source:       source,
		mint:         mint,
		destination:  destination,
		authority:    authority,
		amount:       binary.LittleEndian.Uint64(instruction.Data[1:9]),
		decimals:     instruction.Data[9],
		tokenProgram: program,
	}, nil
}

func verifyOptionalInstructions(transaction *solana.Transaction, instructions []solana.CompiledInstruction, requirement paymentRequirement, transfer transferCheckedFields) error {
	memoCount := 0
	expectedMemo, hasExpectedMemo := requirement.Extra["memo"].(string)
	invalidReasonByIndex := []string{
		"invalid_exact_svm_payload_unknown_fourth_instruction",
		"invalid_exact_svm_payload_unknown_fifth_instruction",
		"invalid_exact_svm_payload_unknown_sixth_instruction",
	}
	for index, instruction := range instructions {
		program, err := programID(transaction, instruction)
		if err != nil {
			return err
		}
		if program.Equals(memoProgramID) {
			memoCount++
			memo := string(instruction.Data)
			if len([]byte(memo)) > maxMemoBytes {
				return fmt.Errorf("extra.memo exceeds maximum %d bytes", maxMemoBytes)
			}
			if hasExpectedMemo && memo != expectedMemo {
				return fmt.Errorf("invalid_exact_svm_payload_transaction_memo")
			}
			if !hasExpectedMemo && memo == "" {
				return fmt.Errorf("invalid_exact_svm_payload_transaction_memo")
			}
			continue
		}
		if program.String() == lighthouseProgram {
			// Pass through Lighthouse instructions by program-id match only,
			// mirroring rust/src/protocol/schemes/exact/verify.rs:266 and
			// typescript/packages/x402/src/facilitator/exact/scheme.ts:300.
			continue
		}
		if program.Equals(solana.SPLAssociatedTokenAccountProgramID) && validDestinationATACreateInstruction(transaction, instruction, requirement, transfer) {
			continue
		}
		if index < len(invalidReasonByIndex) {
			return fmt.Errorf("%s", invalidReasonByIndex[index])
		}
		return fmt.Errorf("invalid_exact_svm_payload_unknown_optional_instruction")
	}
	if hasExpectedMemo && memoCount != 1 {
		return fmt.Errorf("invalid_exact_svm_payload_transaction_memo")
	}
	return nil
}

// isValidatedATACreateInstruction returns true when `instruction` is an
// SPL Associated Token Account program create that targets the payment's
// destination ATA — i.e. the only optional instruction in which the facilitator
// fee-payer is permitted to appear (as the rent payer at accounts[0]).
func isValidatedATACreateInstruction(transaction *solana.Transaction, instruction solana.CompiledInstruction, requirement paymentRequirement, transfer transferCheckedFields) bool {
	program, err := programID(transaction, instruction)
	if err != nil {
		return false
	}
	if !program.Equals(solana.SPLAssociatedTokenAccountProgramID) {
		return false
	}
	return validDestinationATACreateInstruction(transaction, instruction, requirement, transfer)
}

func validDestinationATACreateInstruction(transaction *solana.Transaction, instruction solana.CompiledInstruction, requirement paymentRequirement, transfer transferCheckedFields) bool {
	if len(instruction.Data) > 1 {
		return false
	}
	if len(instruction.Data) == 1 && instruction.Data[0] != 0 && instruction.Data[0] != 1 {
		return false
	}
	if len(instruction.Accounts) < 6 {
		return false
	}
	associatedAccount, err := accountAt(transaction, instruction.Accounts[1])
	if err != nil || !associatedAccount.Equals(transfer.destination) {
		return false
	}
	wallet, err := accountAt(transaction, instruction.Accounts[2])
	if err != nil {
		return false
	}
	payTo, err := solana.PublicKeyFromBase58(requirement.PayTo)
	if err != nil || !wallet.Equals(payTo) {
		return false
	}
	mint, err := accountAt(transaction, instruction.Accounts[3])
	if err != nil || !mint.Equals(transfer.mint) {
		return false
	}
	systemProgram, err := accountAt(transaction, instruction.Accounts[4])
	if err != nil || !systemProgram.Equals(solana.SystemProgramID) {
		return false
	}
	tokenProgram, err := accountAt(transaction, instruction.Accounts[5])
	if err != nil || !tokenProgram.Equals(transfer.tokenProgram) {
		return false
	}
	return true
}

func programID(transaction *solana.Transaction, instruction solana.CompiledInstruction) (solana.PublicKey, error) {
	return accountAt(transaction, instruction.ProgramIDIndex)
}

func accountAt(transaction *solana.Transaction, index uint16) (solana.PublicKey, error) {
	if int(index) >= len(transaction.Message.AccountKeys) {
		return solana.PublicKey{}, fmt.Errorf("invalid account index: %d", index)
	}
	return transaction.Message.AccountKeys[index], nil
}

func verifyTokenAccountsExist(state serverState, transaction *solana.Transaction, requirement paymentRequirement) error {
	transfer, err := parseTransferCheckedInstruction(transaction, transaction.Message.Instructions[2])
	if err != nil {
		return err
	}
	if exists, err := accountExists(state, transfer.source); err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("source token account does not exist")
	}
	if hasDestinationATACreateInstruction(transaction, requirement, transfer) {
		return nil
	}
	if exists, err := accountExists(state, transfer.destination); err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("destination token account does not exist")
	}
	return nil
}

func hasDestinationATACreateInstruction(transaction *solana.Transaction, requirement paymentRequirement, transfer transferCheckedFields) bool {
	for _, instruction := range transaction.Message.Instructions[3:] {
		program, err := programID(transaction, instruction)
		if err != nil || !program.Equals(solana.SPLAssociatedTokenAccountProgramID) {
			continue
		}
		if validDestinationATACreateInstruction(transaction, instruction, requirement, transfer) {
			return true
		}
	}
	return false
}

func accountExists(state serverState, account solana.PublicKey) (bool, error) {
	requestBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getAccountInfo",
		"params": []any{
			account.String(),
			map[string]any{"encoding": "base64"},
		},
	})
	if err != nil {
		return false, err
	}
	response, err := state.httpClient.Post(state.rpcURL, "application/json", bytes.NewReader(requestBody))
	if err != nil {
		return false, err
	}
	defer func() { _ = response.Body.Close() }()
	rawBody, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, fmt.Errorf("getAccountInfo HTTP %d: %s", response.StatusCode, string(rawBody))
	}
	var payload struct {
		Result *struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		return false, err
	}
	if payload.Error != nil {
		return false, fmt.Errorf("getAccountInfo RPC error: %v", payload.Error)
	}
	if payload.Result == nil || len(payload.Result.Value) == 0 || string(payload.Result.Value) == "null" {
		return false, nil
	}
	return true, nil
}

func sendTransaction(state serverState, transaction *solana.Transaction) (string, error) {
	encodedTransaction, err := transaction.ToBase64()
	if err != nil {
		return "", err
	}
	requestBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "sendTransaction",
		"params": []any{
			encodedTransaction,
			map[string]any{
				"encoding":            "base64",
				"skipPreflight":       false,
				"preflightCommitment": "processed",
				"maxRetries":          3,
			},
		},
	})
	if err != nil {
		return "", err
	}

	response, err := state.httpClient.Post(state.rpcURL, "application/json", bytes.NewReader(requestBody))
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	rawBody, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("sendTransaction HTTP %d: %s", response.StatusCode, string(rawBody))
	}

	var payload struct {
		Result string `json:"result"`
		Error  any    `json:"error"`
	}
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		return "", err
	}
	if payload.Error != nil {
		return "", fmt.Errorf("sendTransaction RPC error: %v", payload.Error)
	}
	if payload.Result == "" {
		return "", fmt.Errorf("sendTransaction returned empty signature")
	}
	return payload.Result, nil
}

func newInteropMux(state serverState) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/capabilities", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, capabilityPayload("go"))
	})
	mux.HandleFunc("/exact", func(response http.ResponseWriter, _ *http.Request) {
		writeExactPaymentRequired(response, state)
	})
	mux.HandleFunc("/upto", func(response http.ResponseWriter, _ *http.Request) {
		writePaymentRequired(response, uptoChallengePayload())
	})
	mux.HandleFunc("/session", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusPaymentRequired, sessionChallengePayload())
	})
	mux.HandleFunc("/batch-settlement", func(response http.ResponseWriter, _ *http.Request) {
		writePaymentRequired(response, batchSettlementChallengePayload())
	})
	mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != defaultResourcePath {
			writeJSON(response, http.StatusNotFound, map[string]any{"error": "not_found"})
			return
		}

		paymentSignature := request.Header.Get("PAYMENT-SIGNATURE")
		if paymentSignature == "" {
			writeExactPaymentRequired(response, state)
			return
		}

		settlement, err := settleExactPayment(state, paymentSignature)
		if err != nil {
			challenge := exactChallengePayload(state)
			encoded, marshalErr := json.Marshal(challenge)
			if marshalErr != nil {
				panic(marshalErr)
			}
			writeJSONWithHeaders(
				response,
				http.StatusPaymentRequired,
				map[string]string{"PAYMENT-REQUIRED": base64.StdEncoding.EncodeToString(encoded)},
				map[string]any{
					"error":   "payment_invalid",
					"message": err.Error(),
				},
			)
			return
		}

		writeJSONWithHeaders(
			response,
			http.StatusOK,
			map[string]string{defaultSettlementHeader: settlement},
			map[string]any{
				"ok":   true,
				"paid": true,
				"settlement": map[string]any{
					"success":     true,
					"transaction": settlement,
					"network":     state.network,
				},
			},
		)
	})
	return mux
}

func runInteropServer(state serverState, listener net.Listener, signals <-chan os.Signal, readyWriter io.Writer, errWriter io.Writer) error {
	server := &http.Server{Handler: newInteropMux(state)}
	serveErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
		close(serveErr)
	}()

	ready := capabilityPayload("go")
	ready["type"] = "ready"
	ready["port"] = listener.Addr().(*net.TCPAddr).Port
	encoded, err := json.Marshal(ready)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(readyWriter, string(encoded)); err != nil {
		return err
	}

	select {
	case <-signals:
		if err := server.Close(); err != nil {
			_, _ = fmt.Fprintln(errWriter, err)
			return err
		}
		return nil
	case err := <-serveErr:
		if err != nil {
			_, _ = fmt.Fprintln(errWriter, err)
		}
		return err
	}
}

func main() {
	state := readState()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	if err := runInteropServer(state, listener, signals, os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}
