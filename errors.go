package jwt

import "errors"

var (
	// ErrNoKey is returned when signing or verifying without a key.
	ErrNoKey = errors.New("jwt: no signing key")

	// ErrMalformed is returned when the token is not a well-formed
	// header.payload.signature triple.
	ErrMalformed = errors.New("jwt: malformed token")

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
