package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
)

// header is the fixed JOSE header for HS256 tokens. It is a constant so signing
// never depends on map ordering.
const header = `{"alg":"HS256","typ":"JWT"}`

// Sign creates a signed HS256 JWT for the claims. The key must be non-empty.
func Sign(claims Claims, key []byte) (string, error) {
	if len(key) == 0 {
		return "", ErrNoKey
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := encodeSegment([]byte(header)) + "." + encodeSegment(payload)
	sig := sign(key, signingInput)
	return signingInput + "." + encodeSegment(sig), nil
}

// sign returns the HMAC-SHA256 of signingInput under key.
func sign(key []byte, signingInput string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}
