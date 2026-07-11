package jwt

import "errors"

var (
	// ErrNoKey is returned when signing or verifying without a key.
	ErrNoKey = errors.New("jwt: no signing key")

	// ErrWeakKey is returned when the HS256 key is shorter than 32 bytes. RFC
	// 7518 requires a key at least as long as the hash output (256 bits) for
	// HMAC-SHA256, so shorter keys are rejected instead of silently weakening
	// every token.
	ErrWeakKey = errors.New("jwt: key too short, HS256 needs at least 32 bytes")

	// ErrMalformed is returned when the token is not a well-formed
	// header.payload.signature triple, a segment is not strict base64url, or a
	// registered claim has the wrong JSON type.
	ErrMalformed = errors.New("jwt: malformed token")

	// ErrUnsupportedCritical is returned when the header carries a crit
	// parameter: this verifier implements no extensions, so it must reject any
	// token that declares one as mandatory (RFC 7515 section 4.1.11).
	ErrUnsupportedCritical = errors.New("jwt: unsupported crit header parameter")

	// ErrReservedClaim is returned by Sign when Claims.Extra contains a
	// registered claim name (iss, sub, aud, exp, nbf, iat, jti). Set those
	// through the typed fields so the source of each registered claim is
	// unambiguous.
	ErrReservedClaim = errors.New("jwt: Extra must not contain registered claim names")

	// ErrTooLarge is returned by Verify when the token exceeds the configured
	// maximum size (see WithMaxBytes).
	ErrTooLarge = errors.New("jwt: token exceeds maximum size")

	// ErrAlgMismatch is returned when the token header does not use HS256
	// (this includes "none" and any asymmetric algorithm).
	ErrAlgMismatch = errors.New("jwt: unexpected algorithm, want HS256")

	// ErrSignature is returned when the signature does not verify against any
	// configured key.
	ErrSignature = errors.New("jwt: signature mismatch")

	// ErrMissingExpiry is returned when the token has no exp claim, which is
	// required.
	ErrMissingExpiry = errors.New("jwt: missing exp claim")

	// ErrExpired is returned when the token is past its exp (plus leeway).
	ErrExpired = errors.New("jwt: token expired")

	// ErrNotYetValid is returned when the token is before its nbf (minus leeway).
	ErrNotYetValid = errors.New("jwt: token not yet valid")

	// ErrIssuedInFuture is returned when the token's iat is in the future
	// (minus leeway).
	ErrIssuedInFuture = errors.New("jwt: token issued in the future")

	// ErrIssuer is returned when the iss claim does not match the expected one.
	ErrIssuer = errors.New("jwt: issuer mismatch")

	// ErrAudience is returned when the aud claim does not include the expected
	// audience.
	ErrAudience = errors.New("jwt: audience mismatch")
)
