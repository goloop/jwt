package jwt

import "encoding/base64"

// JWS uses base64url without padding for every segment (RFC 7515 section 2).

// encodeSegment base64url-encodes b without padding.
func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeSegment decodes a base64url segment without padding.
func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
