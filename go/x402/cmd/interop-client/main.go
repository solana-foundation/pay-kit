package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
)

type paymentEnvelope struct {
	Resource map[string]any       `json:"resource,omitempty"`
	Accepts  []paymentRequirement `json:"accepts"`
}

type paymentRequirement struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Asset             string         `json:"asset"`
	Amount            string         `json:"amount"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds,omitempty"`
	Extra             map[string]any `json:"extra"`
}

type paymentSignatureEnvelope struct {
	X402Version int                `json:"x402Version"`
	Accepted    paymentRequirement `json:"accepted"`
	Resource    map[string]any     `json:"resource,omitempty"`
	Payload     map[string]string  `json:"payload"`
}

const (
	defaultComputeUnitLimit             = 20_000
	defaultComputeUnitPriceMicrolamport = 1
	maxMemoBytes                        = 256
)

var (
	computeBudgetProgramID = solana.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")
	memoProgramID          = solana.MustPublicKeyFromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
	httpClient             = &http.Client{Timeout: 10 * time.Second}
)

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func loadPaymentRequiredHeader(headers map[string]string) *paymentEnvelope {
	encoded := headerValue(headers, "PAYMENT-REQUIRED")
	if encoded == "" {
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}

	var envelope paymentEnvelope
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		return nil
	}
	return &envelope
}

func loadPaymentRequiredBody(body string) *paymentEnvelope {
	if body == "" {
		return nil
	}

	var envelope paymentEnvelope
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return nil
	}
	return &envelope
}

func selectSVMRequirement(headers map[string]string, body string, network string, scheme string) *paymentRequirement {
	requirement, _ := selectSVMChallengeWithPreferences(headers, body, network, scheme, nil)
	return requirement
}

func selectSVMChallenge(headers map[string]string, body string, network string, scheme string) (*paymentRequirement, map[string]any) {
	return selectSVMChallengeWithPreferences(headers, body, network, scheme, parseCSVEnv("X402_INTEROP_PREFER_CURRENCIES"))
}

func selectSVMChallengeWithPreferences(headers map[string]string, body string, network string, scheme string, preferredCurrencies []string) (*paymentRequirement, map[string]any) {
	envelopes := []*paymentEnvelope{
		loadPaymentRequiredHeader(headers),
		loadPaymentRequiredBody(body),
	}

	// Preference path: envelope-by-envelope fallback. Each preferred currency
	// is searched against each envelope in order; the first match wins. If no
	// envelope satisfies the preference list we return nil (caller's strict
	// opt-in is preserved instead of silently downgrading to "any" selection).
	if len(preferredCurrencies) > 0 {
		for _, envelope := range envelopes {
			if envelope == nil {
				continue
			}
			candidates := filterCandidates(envelope.Accepts, scheme, network)
			if len(candidates) == 0 {
				continue
			}
			for _, preferred := range preferredCurrencies {
				for _, requirement := range candidates {
					if currenciesMatch(requirement.Asset, preferred, network) {
						selected := requirement
						return &selected, envelope.Resource
					}
				}
			}
		}
		return nil, nil
	}

	// No-preference path: aggregate valid candidates from ALL envelopes and
	// pick the globally cheapest amount. Resource attribution follows the
	// envelope that contributed the winning candidate so downstream telemetry
	// and signing flows see the correct context.
	type candidateEntry struct {
		requirement paymentRequirement
		resource    map[string]any
	}
	var entries []candidateEntry
	for _, envelope := range envelopes {
		if envelope == nil {
			continue
		}
		for _, requirement := range filterCandidates(envelope.Accepts, scheme, network) {
			entries = append(entries, candidateEntry{requirement: requirement, resource: envelope.Resource})
		}
	}
	if len(entries) == 0 {
		return nil, nil
	}
	winner := entries[0]
	winnerAmount, err := strconv.ParseUint(winner.requirement.Amount, 10, 64)
	if err != nil {
		winnerAmount = ^uint64(0)
	}
	for _, entry := range entries[1:] {
		amount, err := strconv.ParseUint(entry.requirement.Amount, 10, 64)
		if err != nil {
			amount = ^uint64(0)
		}
		if amount < winnerAmount {
			winner = entry
			winnerAmount = amount
		}
	}
	selected := winner.requirement
	return &selected, winner.resource
}

func filterCandidates(accepts []paymentRequirement, scheme string, network string) []paymentRequirement {
	candidates := make([]paymentRequirement, 0, len(accepts))
	for _, requirement := range accepts {
		if requirement.Scheme != scheme {
			continue
		}
		if requirement.Network != network {
			continue
		}
		if requirement.Asset == "" || requirement.Amount == "" {
			continue
		}
		candidates = append(candidates, requirement)
	}
	return candidates
}

func parseCSVEnv(name string) []string {
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

func currenciesMatch(offered string, accepted string, network string) bool {
	return resolveStablecoinMint(offered, network) == resolveStablecoinMint(accepted, network)
}

func resolveStablecoinMint(currency string, network string) string {
	upper := strings.ToUpper(strings.TrimSpace(currency))
	switch upper {
	case "USDC", "USD":
		if network == "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" || network == "devnet" || network == "localnet" {
			return "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
		}
		return "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	case "PYUSD":
		if network == "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" || network == "devnet" || network == "localnet" {
			return "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
		}
		return "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
	case "USDG":
		if network == "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" || network == "devnet" || network == "localnet" {
			return "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
		}
		return "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
	case "USDT":
		return "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
	case "CASH":
		return "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"
	default:
		return strings.TrimSpace(currency)
	}
}

func intFromRequirement(requirement paymentRequirement, key string) (uint64, error) {
	value, ok := requirement.Extra[key]
	if !ok {
		return 0, fmt.Errorf("payment requirement is missing integer extra.%s", key)
	}

	switch typed := value.(type) {
	case float64:
		return uint64(typed), nil
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid integer extra.%s: %w", key, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("payment requirement has invalid integer extra.%s", key)
	}
}

func stringFromExtra(requirement paymentRequirement, key string) (string, error) {
	value, ok := requirement.Extra[key]
	if !ok {
		return "", fmt.Errorf("payment requirement is missing extra.%s", key)
	}
	typed, ok := value.(string)
	if !ok || typed == "" {
		return "", fmt.Errorf("payment requirement has invalid extra.%s", key)
	}
	return typed, nil
}

func keypairFromJSONSecret(raw string) (solana.PrivateKey, error) {
	var values []byte
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("decode Solana secret key: %w", err)
	}
	if len(values) != 64 {
		return nil, fmt.Errorf("expected a 64-byte Solana secret key JSON array")
	}
	privateKey := solana.PrivateKey(values)
	if _, err := solana.ValidatePrivateKey(privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func latestBlockhash(rpcURL string) (solana.Hash, error) {
	requestBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getLatestBlockhash",
	})
	if err != nil {
		return solana.Hash{}, err
	}
	response, err := httpClient.Post(rpcURL, "application/json", bytes.NewReader(requestBody))
	if err != nil {
		return solana.Hash{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return solana.Hash{}, fmt.Errorf("getLatestBlockhash HTTP %d", response.StatusCode)
	}
	var payload struct {
		Result struct {
			Value struct {
				Blockhash string `json:"blockhash"`
			} `json:"value"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return solana.Hash{}, err
	}
	if payload.Error != nil {
		return solana.Hash{}, fmt.Errorf("getLatestBlockhash RPC error: %v", payload.Error)
	}
	return solana.HashFromBase58(payload.Result.Value.Blockhash)
}

func computeUnitLimitInstruction(units uint32) solana.Instruction {
	data := []byte{2}
	data = binary.LittleEndian.AppendUint32(data, units)
	return solana.NewInstruction(computeBudgetProgramID, nil, data)
}

func computeUnitPriceInstruction(microLamports uint64) solana.Instruction {
	data := []byte{3}
	data = binary.LittleEndian.AppendUint64(data, microLamports)
	return solana.NewInstruction(computeBudgetProgramID, nil, data)
}

func transferCheckedInstruction(requirement paymentRequirement, signer solana.PublicKey, decimals uint8, tokenProgram solana.PublicKey) (solana.Instruction, error) {
	amount, err := strconv.ParseUint(requirement.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %w", err)
	}
	mint, err := solana.PublicKeyFromBase58(requirement.Asset)
	if err != nil {
		return nil, fmt.Errorf("invalid asset: %w", err)
	}
	payTo, err := solana.PublicKeyFromBase58(requirement.PayTo)
	if err != nil {
		return nil, fmt.Errorf("invalid payTo: %w", err)
	}
	sourceATA, _, err := findAssociatedTokenAddress(signer, tokenProgram, mint)
	if err != nil {
		return nil, err
	}
	destinationATA, _, err := findAssociatedTokenAddress(payTo, tokenProgram, mint)
	if err != nil {
		return nil, err
	}

	data := []byte{12}
	data = binary.LittleEndian.AppendUint64(data, amount)
	data = append(data, decimals)

	return solana.NewInstruction(
		tokenProgram,
		solana.AccountMetaSlice{
			solana.Meta(sourceATA).WRITE(),
			solana.Meta(mint),
			solana.Meta(destinationATA).WRITE(),
			solana.Meta(signer).SIGNER(),
		},
		data,
	), nil
}

func findAssociatedTokenAddress(wallet solana.PublicKey, tokenProgram solana.PublicKey, mint solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress(
		[][]byte{wallet[:], tokenProgram[:], mint[:]},
		solana.SPLAssociatedTokenAccountProgramID,
	)
}

func memoInstruction(requirement paymentRequirement) (solana.Instruction, error) {
	memo := ""
	if value, ok := requirement.Extra["memo"].(string); ok && value != "" {
		memo = value
	} else {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, fmt.Errorf("generate memo nonce: %w", err)
		}
		memo = hex.EncodeToString(nonce[:])
	}
	if len([]byte(memo)) > maxMemoBytes {
		return nil, fmt.Errorf("extra.memo exceeds maximum %d bytes", maxMemoBytes)
	}
	return solana.NewInstruction(memoProgramID, nil, []byte(memo)), nil
}

func buildExactPaymentSignature(requirement paymentRequirement, resource map[string]any, privateKey solana.PrivateKey, rpcURL string) (string, error) {
	if requirement.Scheme != "exact" {
		return "", fmt.Errorf("only exact payment requirements can be signed")
	}

	decimalsValue, err := intFromRequirement(requirement, "decimals")
	if err != nil {
		return "", err
	}
	tokenProgramValue, err := stringFromExtra(requirement, "tokenProgram")
	if err != nil {
		return "", err
	}
	feePayerValue, err := stringFromExtra(requirement, "feePayer")
	if err != nil {
		return "", err
	}
	tokenProgram, err := solana.PublicKeyFromBase58(tokenProgramValue)
	if err != nil {
		return "", fmt.Errorf("invalid tokenProgram: %w", err)
	}
	feePayer, err := solana.PublicKeyFromBase58(feePayerValue)
	if err != nil {
		return "", fmt.Errorf("invalid feePayer: %w", err)
	}

	blockhashValue, _ := requirement.Extra["recentBlockhash"].(string)
	blockhash := solana.Hash{}
	if blockhashValue != "" {
		blockhash, err = solana.HashFromBase58(blockhashValue)
		if err != nil {
			return "", fmt.Errorf("invalid recentBlockhash: %w", err)
		}
	} else {
		blockhash, err = latestBlockhash(rpcURL)
		if err != nil {
			return "", err
		}
	}

	transferIx, err := transferCheckedInstruction(requirement, privateKey.PublicKey(), uint8(decimalsValue), tokenProgram)
	if err != nil {
		return "", err
	}
	memoIx, err := memoInstruction(requirement)
	if err != nil {
		return "", err
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			computeUnitLimitInstruction(defaultComputeUnitLimit),
			computeUnitPriceInstruction(defaultComputeUnitPriceMicrolamport),
			transferIx,
			memoIx,
		},
		blockhash,
		solana.TransactionPayer(feePayer),
	)
	if err != nil {
		return "", err
	}
	tx.Message.SetVersion(solana.MessageVersionV0)
	if _, err := tx.PartialSign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(privateKey.PublicKey()) {
			return &privateKey
		}
		return nil
	}); err != nil {
		return "", err
	}
	transaction, err := tx.ToBase64()
	if err != nil {
		return "", err
	}

	encoded, err := json.Marshal(paymentSignatureEnvelope{
		X402Version: 2,
		Accepted:    requirement,
		Resource:    resource,
		Payload:     map[string]string{"transaction": transaction},
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

func readResponse(response *http.Response) (map[string]string, string, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, "", err
	}
	headers := map[string]string{}
	for key, values := range response.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	return headers, string(body), nil
}

func parseResponseBody(body string) any {
	var parsed any
	decoder := json.NewDecoder(bytes.NewReader([]byte(body)))
	if err := decoder.Decode(&parsed); err == nil {
		return parsed
	}
	return body
}

func main() {
	targetURL := os.Getenv("X402_INTEROP_TARGET_URL")
	if targetURL == "" {
		panic("X402_INTEROP_TARGET_URL is required")
	}

	response, err := httpClient.Get(targetURL)
	if err != nil {
		panic(err)
	}
	headers, body, err := readResponse(response)
	if err != nil {
		panic(err)
	}

	selectedRequirement, resource := selectSVMChallenge(
		headers,
		body,
		readEnvWithDefault("X402_INTEROP_NETWORK", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"),
		readEnvWithDefault("X402_INTEROP_SCHEME", "exact"),
	)
	scheme := readEnvWithDefault("X402_INTEROP_SCHEME", "exact")
	errorDomain := readEnvWithDefault("X402_INTEROP_INTENT", scheme)

	if response.StatusCode == http.StatusPaymentRequired && os.Getenv("X402_INTEROP_INTENT") == "" && scheme == "exact" && selectedRequirement != nil && os.Getenv("X402_INTEROP_CLIENT_SECRET_KEY") != "" && os.Getenv("X402_INTEROP_RPC_URL") != "" {
		privateKey, err := keypairFromJSONSecret(os.Getenv("X402_INTEROP_CLIENT_SECRET_KEY"))
		var paymentSignature string
		if err == nil {
			paymentSignature, err = buildExactPaymentSignature(*selectedRequirement, resource, privateKey, os.Getenv("X402_INTEROP_RPC_URL"))
		}
		if err == nil {
			request, requestErr := http.NewRequest(http.MethodGet, targetURL, nil)
			if requestErr != nil {
				err = requestErr
			} else {
				request.Header.Set("PAYMENT-SIGNATURE", paymentSignature)
				var paidResponse *http.Response
				paidResponse, err = httpClient.Do(request)
				if err == nil {
					paidHeaders, paidBody, readErr := readResponse(paidResponse)
					if readErr != nil {
						err = readErr
					} else {
						payload := map[string]any{
							"type":            "result",
							"implementation":  "go",
							"role":            "client",
							"ok":              paidResponse.StatusCode >= 200 && paidResponse.StatusCode < 300,
							"status":          paidResponse.StatusCode,
							"responseHeaders": paidHeaders,
							"responseBody":    parseResponseBody(paidBody),
							"settlement":      headerValue(paidHeaders, "x-fixture-settlement"),
						}
						encoded, marshalErr := json.Marshal(payload)
						if marshalErr != nil {
							panic(marshalErr)
						}
						fmt.Println(string(encoded))
						return
					}
				}
			}
		}
		if err != nil {
			payload := map[string]any{
				"type":            "result",
				"implementation":  "go",
				"role":            "client",
				"ok":              false,
				"status":          response.StatusCode,
				"responseHeaders": headers,
				"responseBody": map[string]any{
					"error":               "go_exact_client_payment_failed",
					"message":             err.Error(),
					"challengeStatus":     response.StatusCode,
					"challengeBody":       body,
					"selectedRequirement": selectedRequirement,
				},
				"settlement": nil,
			}
			encoded, marshalErr := json.Marshal(payload)
			if marshalErr != nil {
				panic(marshalErr)
			}
			fmt.Println(string(encoded))
			return
		}
	}

	payload := map[string]any{
		"type":            "result",
		"implementation":  "go",
		"role":            "client",
		"ok":              false,
		"status":          response.StatusCode,
		"responseHeaders": headers,
		"responseBody": map[string]any{
			"error":               fmt.Sprintf("go_%s_client_not_implemented", errorDomain),
			"challengeStatus":     response.StatusCode,
			"challengeBody":       body,
			"selectedRequirement": selectedRequirement,
		},
		"settlement": nil,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(encoded))
}

func readEnvWithDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}
