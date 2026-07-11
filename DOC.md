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

Times are Unix seconds (RFC 7519 NumericDate). `Extra` holds custom claims and
is merged into the payload; a registered claim wins over a same-named `Extra`
key. `Audience` marshals to a JSON string when it holds one value, an array
otherwise, and unmarshals from either.

## Signing

```go
token, err := jwt.Sign(claims, key)
```

The key must be non-empty (`ErrNoKey`). Signing marshals the claims, base64url
encodes the constant header and the payload, and appends the HMAC-SHA256 of
`header.payload`.

## Verifying

```go
claims, err := jwt.Verify(token, key, opts...)
```

The steps, in order:

1. split into exactly three non-empty segments (`ErrMalformed`);
2. decode the header and require `alg=HS256` (`ErrAlgMismatch`);
3. verify the signature against every configured key with a constant-time
   compare (`ErrSignature`) - **before** decoding the payload;
4. decode the payload;
5. require `exp` (`ErrMissingExpiry`) and check `exp`/`nbf`/`iat` with leeway;
6. check issuer and audience when configured.

## Options

| Option | Effect |
|--------|--------|
| `WithKey(key)` | add another verification key (rotation) |
| `WithLeeway(d)` | clock-skew tolerance for exp/nbf/iat |
| `WithIssuer(s)` | require iss to equal s |
| `WithAudience(s)` | require aud to include s |
| `WithClock(fn)` | override the time source (testing) |

## Errors

`ErrNoKey`, `ErrMalformed`, `ErrAlgMismatch`, `ErrSignature`, `ErrMissingExpiry`,
`ErrExpired`, `ErrNotYetValid`, `ErrIssuedInFuture`, `ErrIssuer`, `ErrAudience`.
All are sentinel errors comparable with `errors.Is`.

## Security notes

- Only HS256; `none` and asymmetric algorithms are rejected.
- Signature is verified in constant time (`hmac.Equal`) before the payload is
  interpreted, so a forged payload never reaches your claims.
- `exp` is mandatory: a token with no expiry is rejected.
- Use a high-entropy key of at least 32 bytes (HS256 uses SHA-256).
- The parser is fuzzed and never panics on malformed input.

## Scope

`jwt` does: sign and verify HS256 tokens with the registered claims and custom
claims. It does not: support other algorithms, `none`, JWE, JWKS, or expose
unverified parsing.
