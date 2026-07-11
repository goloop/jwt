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
	maxBytes int
}

// Option configures Verify.
type Option func(*options)

// WithKey adds another key to try during verification, for key rotation. Tokens
// are always signed with the primary key; verification accepts any configured
// key. A key shorter than 32 bytes is ignored, matching the signing minimum.
func WithKey(key []byte) Option {
	return func(o *options) {
		if len(key) >= minKeyLen {
			o.keys = append(o.keys, key)
		}
	}
}

// WithMaxBytes rejects a token longer than n bytes before any parsing, to bound
// the work spent on untrusted input. The default (0) imposes no limit; set a
// limit when verifying tokens from the open internet.
func WithMaxBytes(n int) Option {
	return func(o *options) { o.maxBytes = n }
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

// WithClock overrides the time source (for testing). A nil function is ignored,
// leaving the default of time.Now.
func WithClock(now func() time.Time) Option {
	return func(o *options) {
		if now != nil {
			o.now = now
		}
	}
}

// Verify parses and validates an HS256 JWT and returns its claims. It requires
// alg=HS256 and a present exp; it verifies the HMAC signature (compared with
// hmac.Equal) before interpreting the payload, then checks exp/nbf/iat plus any
// configured issuer and audience. A token that declares a crit header is
// rejected, since this verifier implements no extensions.
func Verify(token string, key []byte, opts ...Option) (Claims, error) {
	if err := checkKey(key); err != nil {
		return Claims{}, err
	}
	o := options{keys: [][]byte{key}, now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.maxBytes > 0 && len(token) > o.maxBytes {
		return Claims{}, ErrTooLarge
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, ErrMalformed
	}

	// Header: reject anything but HS256, and any declared crit extension,
	// before spending work on the signature.
	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var hdr struct {
		Alg  string   `json:"alg"`
		Typ  string   `json:"typ"`
		Crit []string `json:"crit"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return Claims{}, ErrMalformed
	}
	if hdr.Alg != "HS256" {
		return Claims{}, ErrAlgMismatch
	}
	if len(hdr.Crit) > 0 {
		return Claims{}, ErrUnsupportedCritical
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
	// RFC 7519: the token must not be accepted on or after exp. The leeway
	// widens that boundary for clock skew but keeps it exclusive.
	if !now.Before(time.Unix(c.ExpiresAt, 0).Add(o.leeway)) {
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
