package jwt

import "encoding/base64"

// JWS uses base64url without padding for every segment (RFC 7515 section 2).

// encodeSegment base64url-encodes b without padding.
func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeSegment decodes a base64url segment without padding. It first checks
// the alphabet by hand: the standard library decoder silently skips CR and LF,
// so a compact-serialization segment could otherwise smuggle line breaks. A
// JWS segment must be pure unpadded base64url, nothing else.
func decodeSegment(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z',
			c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return nil, base64.CorruptInputError(i)
		}
	}
	return base64.RawURLEncoding.DecodeString(s)
}
