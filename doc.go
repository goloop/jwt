// Package jwt issues and verifies compact JSON Web Tokens, deliberately limited
// to HS256, standard library only.
//
// It follows the JWS compact serialization of RFC 7515 and the registered
// claims of RFC 7519, but supports exactly one algorithm (HMAC-SHA256) with
// strict defaults. There is no algorithm negotiation, no "none", and no
// asymmetric keys: a smaller surface is a safer surface.
//
// # Signing
//
//	claims := jwt.Claims{
//	    Subject:   "user-123",
//	    Issuer:    "api",
//	    ExpiresAt: time.Now().Add(time.Hour).Unix(),
//	    IssuedAt:  time.Now().Unix(),
//	}
//	token, err := jwt.Sign(claims, key)
//
// The header is always {"alg":"HS256","typ":"JWT"}. Custom claims go in
// Claims.Extra; a registered claim name there is rejected (ErrReservedClaim),
// so registered claims come only from the typed fields. The key must be at
// least 32 bytes (ErrWeakKey), the HMAC-SHA256 output size required by RFC 7518.
// CheckKey runs that same check on its own, so a configuration layer can fail
// at process start instead of at the first token.
//
// # Verifying
//
//	claims, err := jwt.Verify(token, key,
//	    jwt.WithIssuer("api"),
//	    jwt.WithLeeway(30*time.Second),
//	)
//
// Verify requires alg=HS256 and a present exp, verifies the HMAC signature
// (compared with hmac.Equal) before interpreting the payload, and then checks
// exp/nbf/iat plus any configured issuer and audience. It rejects a token that
// declares a crit header, a segment that is not strict base64url, and a
// registered claim of the wrong JSON type. For key rotation, pass additional
// keys with WithKey: tokens are signed with the primary key and verified
// against any configured key. WithMaxBytes bounds the work spent on untrusted
// input.
//
// # Not supported
//
// RS/ES/PS algorithms, "none", JWE encryption and JWKS are out of scope by
// design. Parsing without signature verification is not exposed.
//
// See DOC.md (English) and DOC.UK.md (Ukrainian) for the full reference.
package jwt
