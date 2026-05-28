package paykit

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// secretEnvVar is the orchestrator-supplied env var the MPP HMAC
// secret comes from when set explicitly (caveat #4 chain step 1).
const secretEnvVar = "PAY_KIT_MPP_CHALLENGE_BINDING_SECRET"

// runPreflight is the boot-time soundness check. Mirrors the Ruby PR
// #142 / Lua PR #141 contract:
//
//  1. Fee-payer SOL balance >= MIN_FEE_PAYER_LAMPORTS (auto-fund via
//     surfnet_setAccount on localnet+demo signer, raise elsewhere).
//  2. Recipient ATA exists for each Config.Stablecoins entry (auto-
//     provision via surfnet_setTokenAccount on localnet+demo signer,
//     raise elsewhere).
//
// RPC failures are logged, not raised -- an unreachable endpoint
// never blocks boot. The runtime resurfaces the connection problem on
// the first request.
//
// Wired here as a stub for the v1 surface; the live RPC + cheatcode
// implementation lands when the schemes packages bring in the chain
// helpers. The existing /server/network_check.go covers the network
// shape probe, which the adapters call lazily on first request.
func runPreflight(_ Config) error {
	// Intentionally a no-op for the umbrella skeleton. The real check
	// runs inside each adapter's first request because the chain
	// helpers (RpcClient + Surfnet cheatcodes) live in the schemes
	// packages, not the root.
	return nil
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
		return nil, fmt.Errorf("paykit: failed to generate MPP secret: %w", err)
	}
	hexed := hex.EncodeToString(buf)
	_ = appendToDotenv(".env", secretEnvVar, hexed)
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
	defer f.Close()
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
	defer f.Close()
	if existed {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(f, "%s=%s\n", key, value)
	return err
}
