# jwt - reference

`jwt` is a strict, HS256-only JWT implementation. Full English reference;
Ukrainian in [DOC.UK.md](DOC.UK.md).

## Contents

- [Design](#design)
- [Claims](#claims)
- [Signing](#signing)
- [Verifying](#verifying)
- [Options](#options)
- [Errors](#errors)
- [Security notes](#security-notes)
- [Scope](#scope)

## Design

The token is the JWS compact serialization `header.payload.signature`, each
segment base64url without padding. The header is a constant
`{"alg":"HS256","typ":"JWT"}`. Only HMAC-SHA256 is supported: there is no
algorithm agility, which removes an entire class of JWT vulnerabilities (alg
confusion, `none`).

## Claims

```go
type Claims struct {
	Issuer    string   // iss
	Subject   string   // sub
	Audience  Audience // aud (string or []string)
	ExpiresAt int64    // exp, Unix seconds
	NotBefore int64    // nbf
	IssuedAt  int64    // iat
	ID        string   // jti
	Extra     map[string]any // custom claims
}
```

Times are Unix seconds (RFC 7519 NumericDate). `Extra` holds **only** custom
claims: a registered claim name (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`,
`jti`) in `Extra` is rejected by `Sign` (`ErrReservedClaim`), so the typed
fields are the single source of truth for registered claims. `Audience`
marshals to a JSON string when it holds one value, an array otherwise, and
unmarshals from either.

## Signing

```go
token, err := jwt.Sign(claims, key)
```

The key must be at least 32 bytes (`ErrWeakKey`; empty gives `ErrNoKey`) - the
HMAC-SHA256 output size required by RFC 7518. Signing marshals the claims,
base64url-encodes the constant header and the payload, and appends the
HMAC-SHA256 of `header.payload`.

## Verifying

```go
claims, err := jwt.Verify(token, key, opts...)
```

The steps, in order:

1. reject a token longer than `WithMaxBytes` (`ErrTooLarge`), if set;
2. split into exactly three non-empty segments (`ErrMalformed`); each segment
   must be strict base64url (embedded whitespace is rejected, not skipped);
3. decode the header, require `alg=HS256` (`ErrAlgMismatch`), and reject any
   declared `crit` parameter (`ErrUnsupportedCritical`);
4. verify the signature against every configured key with `hmac.Equal`
   (`ErrSignature`) - **before** decoding the payload;
5. decode the payload; a registered claim of the wrong JSON type is rejected
   (`ErrMalformed`) rather than silently coerced;
6. require `exp` (`ErrMissingExpiry`) and check `exp`/`nbf`/`iat` with leeway
   (`exp` is exclusive: a token is invalid on or after `exp`+leeway);
7. check issuer and audience when configured.

## Options

| Option | Effect |
|--------|--------|
| `WithKey(key)` | add another verification key (rotation); keys under 32 bytes are ignored |
| `WithLeeway(d)` | clock-skew tolerance for exp/nbf/iat |
| `WithIssuer(s)` | require iss to equal s |
| `WithAudience(s)` | require aud to include s |
| `WithMaxBytes(n)` | reject a token longer than n bytes before parsing |
| `WithClock(fn)` | override the time source (testing); nil is ignored |

## Errors

`ErrNoKey`, `ErrWeakKey`, `ErrReservedClaim`, `ErrMalformed`,
`ErrUnsupportedCritical`, `ErrTooLarge`, `ErrAlgMismatch`, `ErrSignature`,
`ErrMissingExpiry`, `ErrExpired`, `ErrNotYetValid`, `ErrIssuedInFuture`,
`ErrIssuer`, `ErrAudience`. All are sentinel errors comparable with `errors.Is`.

## Security notes

- Only HS256; `none` and asymmetric algorithms are rejected (`ErrAlgMismatch`).
- The key must be at least 32 bytes; shorter keys are rejected, not silently
  accepted.
- The signature is compared with `hmac.Equal` before the payload is interpreted,
  so a forged payload never reaches your claims.
- A `crit` header is rejected: this verifier implements no extensions, so it
  never accepts a token whose producer demanded semantics it does not apply.
- Segments must be strict base64url, so a token cannot smuggle whitespace past
  the standard-library decoder.
- `exp` is mandatory: a token with no expiry is rejected.
- The parser is fuzzed and never panics on malformed input.

## Scope

`jwt` does: sign and verify HS256 tokens with the registered claims and custom
claims. It does not: support other algorithms, `none`, JWE, JWKS, or expose
unverified parsing.
