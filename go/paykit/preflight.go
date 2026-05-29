package paykit

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
)

// secretEnvVar is the orchestrator-supplied env var the MPP HMAC
// secret comes from when set explicitly (caveat #4 chain step 1).
const secretEnvVar = "PAY_KIT_MPP_CHALLENGE_BINDING_SECRET"

// deprecatedEnvVars maps the pre-Operator env-var names to their
// replacements. Go has no Ruby-style `deprecate` macro, so boot-time
// detection in New() is the idiomatic spot to warn (DESIGN.md
// "Cascading"). Removed after one minor release.
var deprecatedEnvVars = map[string]string{
	"PAY_KIT_PAY_TO":               "PAY_KIT_OPERATOR_RECIPIENT",
	"PAY_KIT_X402_FACILITATOR_KEY": "PAY_KIT_OPERATOR_KEY",
	"PAY_KIT_X402_FACILITATOR":     "PAY_KIT_X402_FACILITATOR_URL (or PAY_KIT_RPC_URL if it held an RPC endpoint)",
	"PAY_KIT_MPP_SECRET":           secretEnvVar,
}

// warnDeprecatedEnv emits one slog.Warn per set legacy env var,
// pointing at the new name. Called once from New().
func warnDeprecatedEnv() {
	for old, replacement := range deprecatedEnvVars {
		if _, ok := os.LookupEnv(old); ok {
			slog.Warn("paykit: deprecated env var; use the new name",
				"deprecated", old, "use", replacement)
		}
	}
}

const (
	// minFeePayerLamports is the soundness gate the boot-time
	// preflight enforces on the fee-payer balance: enough SOL for
	// ~200 settlement transactions at the default 5_000 lamports each.
	minFeePayerLamports = 1_000_000
	// autofundLamports is the amount surfnet_setAccount sets when the
	// auto-bootstrap branch fires (10 SOL).
	autofundLamports uint64 = 10_000_000_000
	systemProgramID         = "11111111111111111111111111111111"
)

// preflightRPC is the narrow surface the preflight uses; abstracted
// behind an interface so unit tests can inject a fake without
// touching the wire (caveat #7 -- the live RPC path is intentionally
// excluded from the coverage gate; the unit tests cover the branching
// only).
type preflightRPC interface {
	GetBalance(ctx context.Context, addr solana.PublicKey, commitment rpc.CommitmentType) (*rpc.GetBalanceResult, error)
	GetAccountInfoWithOpts(ctx context.Context, addr solana.PublicKey, opts *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error)
	RPCCallForInto(ctx context.Context, out any, method string, params []any) error
}

// preflightRPCFactory builds a preflightRPC for the given URL. Tests
// override this to inject a fake.
var preflightRPCFactory = func(url string) preflightRPC {
	return rpc.New(url)
}

// PreflightRPCInterface is the exported alias of the package-private
// preflightRPC contract; consumers' test packages use it to register a
// fake via [SetPreflightRPCFactoryForTests].
type PreflightRPCInterface = preflightRPC

// SetPreflightRPCFactoryForTests overrides the RPC factory used by
// [New]'s preflight stage. The test fake replaces the factory for the
// lifetime of the override; restore via the returned closure (or
// stash the original and pass `nil` to reset).
func SetPreflightRPCFactoryForTests(factory func(url string) PreflightRPCInterface) (restore func()) {
	prev := preflightRPCFactory
	preflightRPCFactory = factory
	return func() { preflightRPCFactory = prev }
}

// runPreflight implements the contract from Ruby PR #142 / Lua PR
// #141 / PHP PR #145 caveat #3:
//
//  1. Fee-payer SOL balance >= minFeePayerLamports. On
//     localnet + demo signer, auto-fund via surfnet_setAccount;
//     otherwise raise *PreflightError.
//  2. Recipient ATA exists for each Config.Stablecoins entry. On
//     localnet + demo signer, auto-provision via
//     surfnet_setTokenAccount; otherwise raise.
//
// RPC failures (network unreachable, RPC errors) are logged via
// slog and returned to the caller as nil -- an unreachable endpoint
// never blocks boot. The runtime resurfaces the connection problem
// on the first request.
func runPreflight(cfg Config) error {
	rpcClient := preflightRPCFactory(cfg.RPCURL)
	autofix := cfg.Network == SolanaLocalnet && cfg.Operator.Signer != nil && cfg.Operator.Signer.IsDemo()

	if cfg.Operator.FeePayer && cfg.Operator.Signer != nil {
		if err := checkFeePayerSOL(cfg, rpcClient, autofix); err != nil {
			return err
		}
	}
	for _, coin := range cfg.Stablecoins {
		if err := checkRecipientATA(cfg, coin, rpcClient, autofix); err != nil {
			return err
		}
	}
	return nil
}

// PreflightError is the typed boot-time failure when a soundness
// check fails on a non-localnet network (or on localnet with a
// non-demo signer, where Surfnet cheatcodes do not apply).
type PreflightError struct {
	Stage  string
	Detail string
}

func (e *PreflightError) Error() string {
	return fmt.Sprintf("paykit: preflight %s: %s", e.Stage, e.Detail)
}

func checkFeePayerSOL(cfg Config, rpcClient preflightRPC, autofix bool) error {
	pub, err := solana.PublicKeyFromBase58(string(cfg.Operator.Signer.Pubkey()))
	if err != nil {
		return &PreflightError{Stage: "fee-payer", Detail: err.Error()}
	}
	bal, err := rpcClient.GetBalance(context.Background(), pub, rpc.CommitmentConfirmed)
	if err != nil {
		slog.Warn("paykit: preflight getBalance failed; deferring to runtime",
			"err", err, "rpc", cfg.RPCURL)
		return nil
	}
	if bal.Value >= minFeePayerLamports {
		return nil
	}
	if autofix {
		slog.Info("paykit: preflight funding demo fee-payer via surfnet_setAccount",
			"pubkey", pub, "lamports", autofundLamports)
		params := []any{
			pub.String(),
			map[string]any{
				"lamports":   autofundLamports,
				"data":       "",
				"executable": false,
				"owner":      systemProgramID,
				"rentEpoch":  0,
			},
		}
		if err := rpcClient.RPCCallForInto(context.Background(), nil, "surfnet_setAccount", params); err != nil {
			return &PreflightError{Stage: "fee-payer", Detail: fmt.Sprintf("surfnet_setAccount failed: %v", err)}
		}
		return nil
	}
	return &PreflightError{
		Stage:  "fee-payer",
		Detail: fmt.Sprintf("operator signer %s has %d lamports on %s; fund it with at least %d", pub, bal.Value, cfg.Network, minFeePayerLamports),
	}
}

func checkRecipientATA(cfg Config, coin Stablecoin, rpcClient preflightRPC, autofix bool) error {
	mint := paycore.ResolveMint(string(coin), cfg.Network.MintsLabel())
	if mint == "" || mint == string(coin) {
		return nil // SOL-native or unknown coin; nothing to check.
	}
	tokenProgram := paycore.DefaultTokenProgramForCurrency(string(coin), cfg.Network.MintsLabel())
	recipient, err := solana.PublicKeyFromBase58(string(cfg.Operator.Recipient))
	if err != nil {
		return &PreflightError{Stage: "ata", Detail: err.Error()}
	}
	mintPub, err := solana.PublicKeyFromBase58(mint)
	if err != nil {
		return &PreflightError{Stage: "ata", Detail: err.Error()}
	}
	ata, err := deriveATA(recipient, mintPub, tokenProgram)
	if err != nil {
		return &PreflightError{Stage: "ata", Detail: err.Error()}
	}
	info, err := rpcClient.GetAccountInfoWithOpts(context.Background(), ata, &rpc.GetAccountInfoOpts{
		Encoding: solana.EncodingBase64, Commitment: rpc.CommitmentConfirmed,
	})
	if err != nil {
		slog.Warn("paykit: preflight getAccountInfo failed; deferring to runtime",
			"err", err, "rpc", cfg.RPCURL, "ata", ata)
		return nil
	}
	if info != nil && info.Value != nil {
		return nil
	}
	if autofix {
		slog.Info("paykit: preflight provisioning ATA via surfnet_setTokenAccount",
			"coin", coin, "recipient", recipient, "mint", mint)
		params := []any{
			recipient.String(),
			mint,
			map[string]any{"amount": 0, "state": "initialized"},
			tokenProgram,
		}
		if err := rpcClient.RPCCallForInto(context.Background(), nil, "surfnet_setTokenAccount", params); err != nil {
			return &PreflightError{Stage: "ata", Detail: fmt.Sprintf("surfnet_setTokenAccount failed: %v", err)}
		}
		return nil
	}
	return &PreflightError{
		Stage:  "ata",
		Detail: fmt.Sprintf("recipient %s has no %s ATA at %s on %s; create it before boot", recipient, coin, ata, cfg.Network),
	}
}

func deriveATA(owner, mint solana.PublicKey, tokenProgram string) (solana.PublicKey, error) {
	tp, err := solana.PublicKeyFromBase58(tokenProgram)
	if err != nil {
		return solana.PublicKey{}, err
	}
	return solanatx.FindAssociatedTokenAddressWithProgram(owner, mint, tp)
}

// resolveMPPSecret implements the chain from caveat #4:
//
//  1. ENV[PAY_KIT_MPP_CHALLENGE_BINDING_SECRET]
//  2. ./.env parsed for the same key
//  3. Generate hex(rand(32)) and append to ./.env (mode 0600 if the
//     file is being created). If ./.env is unwritable, keep the
//     in-memory value and signal via a warn log.
func resolveMPPSecret() ([]byte, error) {
	if v := os.Getenv(secretEnvVar); v != "" {
		return []byte(v), nil
	}
	if v, ok := readDotenv(".env", secretEnvVar); ok && v != "" {
		return []byte(v), nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("failed to generate MPP secret: %w", err)
	}
	hexed := hex.EncodeToString(buf)
	if err := appendToDotenv(".env", secretEnvVar, hexed); err != nil {
		slog.Warn("paykit: MPP secret persisted in-memory only (./.env unwritable)",
			"err", err)
	}
	return []byte(hexed), nil
}

// readDotenv is a tolerant ~10-line parser: blank lines, `#`
// comments, and KEY=value / KEY="value" / KEY='value' forms.
// Intentionally avoids a new dependency.
func readDotenv(path, key string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(line[:eq])
		if name != key {
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		if len(val) >= 2 {
			first, last := val[0], val[len(val)-1]
			if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		return val, val != ""
	}
	return "", false
}

func appendToDotenv(path, key, value string) error {
	_, existedErr := os.Stat(path)
	existed := existedErr == nil
	flag := os.O_APPEND | os.O_WRONLY
	if !existed {
		flag |= os.O_CREATE
	}
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if existed {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(f, "%s=%s\n", key, value)
	return err
}

// RunPreflightForTests + PreflightEnabledForTests expose the
// package-private preflight entry points so tests in external test
// packages can exercise the live RPC + autofix branches via a fake
// PreflightRPCInterface registered through
// [SetPreflightRPCFactoryForTests].
func RunPreflightForTests(cfg Config) error { return runPreflight(cfg) }

// PreflightEnabledForTests exposes [preflightEnabled] to external
// test packages.
func PreflightEnabledForTests(cfg Config) bool { return preflightEnabled(cfg) }

// Sentinel kept for documentation purposes; preflight returns nil on
// RPC failures so the caller can defer the error to the first request.
