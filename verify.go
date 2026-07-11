package jwt

import (
	"crypto/hmac"
	"encoding/json"
	"strings"
	"time"
)

// options holds verification settings.
type options struct {
	keys     [][]byte
	leeway   time.Duration
	issuer   string
	audience string
	now      func() time.Time
}

// Option configures Verify.
type Option func(*options)

// WithKey adds another key to try during verification, for key rotation. Tokens
// are always signed with the primary key; verification accepts any configured
// key.
func WithKey(key []byte) Option {
	return func(o *options) {
		if len(key) > 0 {
			o.keys = append(o.keys, key)
		}
	}
}

// WithLeeway allows a clock-skew tolerance when checking exp, nbf and iat.
func WithLeeway(d time.Duration) Option {
	return func(o *options) { o.leeway = d }
}

// WithIssuer requires the iss claim to equal issuer.
func WithIssuer(issuer string) Option {
	return func(o *options) { o.issuer = issuer }
}

// WithAudience requires the aud claim to include audience.
func WithAudience(audience string) Option {
	return func(o *options) { o.audience = audience }
}

// WithClock overrides the time source (for testing).
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

// Verify parses and validates an HS256 JWT and returns its claims. It requires
// alg=HS256 and a present exp; it verifies the signature (constant time) before
// interpreting the payload, and checks exp/nbf/iat plus any configured issuer
// and audience.
func Verify(token string, key []byte, opts ...Option) (Claims, error) {
	if len(key) == 0 {
		return Claims{}, ErrNoKey
	}
	o := options{keys: [][]byte{key}, now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, ErrMalformed
	}

	// Header: reject anything but HS256 before spending work on the signature.
	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return Claims{}, ErrMalformed
	}
	if hdr.Alg != "HS256" {
		return Claims{}, ErrAlgMismatch
	}

	// Signature: verify before interpreting the payload.
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	signingInput := parts[0] + "." + parts[1]
	if !anyKeyVerifies(o.keys, signingInput, sig) {
		return Claims{}, ErrSignature
	}

	// Payload.
	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return Claims{}, ErrMalformed
	}

	if err := validate(claims, o); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

// anyKeyVerifies reports whether the signature matches under any key, using a
// constant-time comparison.
func anyKeyVerifies(keys [][]byte, signingInput string, sig []byte) bool {
	for _, k := range keys {
		if len(k) == 0 {
			continue
		}
		if hmac.Equal(sign(k, signingInput), sig) {
			return true
		}
	}
	return false
}

// validate checks the temporal and identity claims.
func validate(c Claims, o options) error {
	now := o.now()

	if c.ExpiresAt == 0 {
		return ErrMissingExpiry
	}
	if now.After(time.Unix(c.ExpiresAt, 0).Add(o.leeway)) {
		return ErrExpired
	}
	if c.NotBefore != 0 && now.Before(time.Unix(c.NotBefore, 0).Add(-o.leeway)) {
		return ErrNotYetValid
	}
	if c.IssuedAt != 0 && now.Before(time.Unix(c.IssuedAt, 0).Add(-o.leeway)) {
		return ErrIssuedInFuture
	}
	if o.issuer != "" && c.Issuer != o.issuer {
		return ErrIssuer
	}
	if o.audience != "" && !c.Audience.Contains(o.audience) {
		return ErrAudience
	}
	return nil
}
