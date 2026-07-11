[![Go Reference](https://img.shields.io/badge/godoc-reference-blue)](https://pkg.go.dev/github.com/goloop/jwt) [![License](https://img.shields.io/badge/license-MIT-brightgreen)](https://github.com/goloop/jwt/blob/master/LICENSE) [![Stay with Ukraine](https://img.shields.io/static/v1?label=Stay%20with&message=Ukraine%20♥&color=ffD700&labelColor=0057B8&style=flat)](https://u24.gov.ua/)

# jwt

`jwt` issues and verifies compact JSON Web Tokens, deliberately limited to
**HS256**. It follows the JWS compact serialization (RFC 7515) and the
registered claims (RFC 7519), but supports exactly one algorithm with strict
defaults - a smaller surface is a safer surface. Zero dependencies, standard
library only.

## Install

```bash
go get github.com/goloop/jwt
```

## Sign

```go
token, err := jwt.Sign(jwt.Claims{
	Subject:   "user-123",
	Issuer:    "api",
	Audience:  jwt.Audience{"web"},
	ExpiresAt: time.Now().Add(time.Hour).Unix(),
	IssuedAt:  time.Now().Unix(),
	Extra:     map[string]any{"role": "admin"},
}, key)
```

The header is always `{"alg":"HS256","typ":"JWT"}`. Custom claims go in
`Claims.Extra`.

## Verify

```go
claims, err := jwt.Verify(token, key,
	jwt.WithIssuer("api"),
	jwt.WithAudience("web"),
	jwt.WithLeeway(30*time.Second),
)
```

`Verify`:

- requires `alg=HS256` (rejects `none`, `RS256`, everything else);
- requires a present `exp`;
- verifies the signature in **constant time before** interpreting the payload;
- checks `exp`/`nbf`/`iat` with optional leeway, and issuer/audience when set.

## Key rotation

```go
claims, err := jwt.Verify(token, newKey, jwt.WithKey(oldKey))
```

Tokens are signed with the primary key; verification accepts any configured key.

## Not supported (by design)

RS/ES/PS algorithms, `none`, JWE encryption, JWKS, and parsing without
signature verification.

## Documentation

- English reference: [DOC.md](DOC.md)
- Ukrainian reference: [DOC.UK.md](DOC.UK.md)

## License

MIT - see [LICENSE](LICENSE).
