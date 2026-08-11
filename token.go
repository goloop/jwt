package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
)

// header is the fixed JOSE header for HS256 tokens. It is a constant so signing
// never depends on map ordering.
const header = `{"alg":"HS256","typ":"JWT"}`

// minKeyLen is the smallest HS256 key accepted: 32 bytes (256 bits), matching
// the HMAC-SHA256 output size as required by RFC 7518.
const minKeyLen = 32

// checkKey reports whether key is usable for HS256: present and long enough.
func checkKey(key []byte) error {
	if len(key) == 0 {
		return ErrNoKey
	}
	if len(key) < minKeyLen {
		return ErrWeakKey
	}
	return nil
}

// CheckKey reports whether key is usable for HS256: ErrNoKey when it is empty,
// ErrWeakKey when it is shorter than 32 bytes, nil otherwise. It is the same
// check Sign and Verify run on every call, exported so a configuration layer
// can fail at startup instead of at the first token - and without copying the
// 32-byte rule into its own code, where it would drift.
//
// It validates the key alone. A nil result does not prove a token will verify:
// that still depends on the token.
func CheckKey(key []byte) error {
	return checkKey(key)
}

// Sign creates a signed HS256 JWT for the claims. The key must be at least 32
// bytes. Claims.Extra must not carry registered claim names; set those through
// the typed fields.
func Sign(claims Claims, key []byte) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	if claims.hasReservedExtra() {
		return "", ErrReservedClaim
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
