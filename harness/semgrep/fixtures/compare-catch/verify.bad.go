package verify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
)

// BAD: non-constant-time secret compare, and err-swallowed-as-accept.

func checkMac(payload, secretKey []byte, providedMac []byte) bool {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(payload)
	expectedMac := mac.Sum(nil)
	// timing-variable
	return bytes.Equal(expectedMac, providedMac)
}

func verifyToken(token string) (bool, error) {
	err := assertSignatureValid(token)
	if err != nil {
		// swallow verification failure as success => fails open
		return true, nil
	}
	return true, nil
}
