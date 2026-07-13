package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

// GOOD: constant-time compare via subtle.ConstantTimeCompare, and errors propagate.

func checkMac(payload, secretKey []byte, providedMac []byte) bool {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(payload)
	expectedMac := mac.Sum(nil)
	return subtle.ConstantTimeCompare(expectedMac, providedMac) == 1
}

func verifyToken(token string) (bool, error) {
	err := assertSignatureValid(token)
	if err != nil {
		return false, err
	}
	return true, nil
}
