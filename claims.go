package jwt

import "encoding/json"

// Audience is the aud claim. Per RFC 7519 it may be a single string or an array
// of strings; it marshals to a string when it holds one value.
type Audience []string

// Contains reports whether the audience includes v.
func (a Audience) Contains(v string) bool {
	for _, s := range a {
		if s == v {
			return true
		}
	}
	return false
}

// MarshalJSON encodes a single-element audience as a string, otherwise as an
// array.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// UnmarshalJSON accepts either a string or an array of strings.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = Audience(many)
	return nil
}

// Claims holds the RFC 7519 registered claims plus any custom claims in Extra.
// Times are Unix seconds (the RFC NumericDate representation).
type Claims struct {
	Issuer    string
	Subject   string
	Audience  Audience
	ExpiresAt int64
	NotBefore int64
	IssuedAt  int64
	ID        string
	Extra     map[string]any
}

// registeredNames are the RFC 7519 registered claim keys. They may only be set
// through the typed Claims fields, never through Extra, so the origin of every
// registered claim is unambiguous.
var registeredNames = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {},
}

// hasReservedExtra reports whether Extra holds any registered claim name, so
// Sign can fail with a clean ErrReservedClaim before marshaling.
func (c Claims) hasReservedExtra() bool {
	for k := range c.Extra {
		if _, ok := registeredNames[k]; ok {
			return true
		}
	}
	return false
}

// MarshalJSON merges the registered claims and Extra into one JSON object. Extra
// carries only custom claims; a registered claim name in Extra is an error
// (ErrReservedClaim), because the typed fields are the single source of truth
// for those claims.
func (c Claims) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(c.Extra)+7)
	for k, v := range c.Extra {
		if _, reserved := registeredNames[k]; reserved {
			return nil, ErrReservedClaim
		}
		m[k] = v
	}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	if len(c.Audience) == 1 {
		m["aud"] = c.Audience[0]
	} else if len(c.Audience) > 1 {
		m["aud"] = []string(c.Audience)
	}
	if c.ExpiresAt != 0 {
		m["exp"] = c.ExpiresAt
	}
	if c.NotBefore != 0 {
		m["nbf"] = c.NotBefore
	}
	if c.IssuedAt != 0 {
		m["iat"] = c.IssuedAt
	}
	if c.ID != "" {
		m["jti"] = c.ID
	}
	return json.Marshal(m)
}

// UnmarshalJSON extracts the registered claims and keeps the rest in Extra. A
// registered claim with the wrong JSON type is rejected (ErrMalformed) rather
// than silently coerced, so a malformed exp or aud cannot slip through
// verification as if it were absent.
func (c *Claims) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	if c.Issuer, err = popString(raw, "iss"); err != nil {
		return err
	}
	if c.Subject, err = popString(raw, "sub"); err != nil {
		return err
	}
	if c.ID, err = popString(raw, "jti"); err != nil {
		return err
	}
	if c.ExpiresAt, err = popInt(raw, "exp"); err != nil {
		return err
	}
	if c.NotBefore, err = popInt(raw, "nbf"); err != nil {
		return err
	}
	if c.IssuedAt, err = popInt(raw, "iat"); err != nil {
		return err
	}
	if c.Audience, err = popAudience(raw, "aud"); err != nil {
		return err
	}
	if len(raw) > 0 {
		c.Extra = raw
	} else {
		c.Extra = nil
	}
	return nil
}

// popString removes key and returns its string value. A present non-string
// value is an error.
func popString(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", nil
	}
	delete(m, key)
	s, ok := v.(string)
	if !ok {
		return "", ErrMalformed
	}
	return s, nil
}

// popInt removes key and returns its NumericDate value as Unix seconds. JSON
// numbers are integral seconds; a present non-numeric or fractional value is an
// error.
func popInt(m map[string]any, key string) (int64, error) {
	v, ok := m[key]
	if !ok {
		return 0, nil
	}
	delete(m, key)
	switch n := v.(type) {
	case float64:
		if n != float64(int64(n)) {
			return 0, ErrMalformed
		}
		return int64(n), nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, ErrMalformed
		}
		return i, nil
	default:
		return 0, ErrMalformed
	}
}

// popAudience removes key and returns the aud claim. It accepts a string or an
// array of strings; any other shape, including an array with a non-string
// element, is an error.
func popAudience(m map[string]any, key string) (Audience, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}
	delete(m, key)
	switch a := v.(type) {
	case string:
		return Audience{a}, nil
	case []any:
		out := make(Audience, 0, len(a))
		for _, e := range a {
			s, ok := e.(string)
			if !ok {
				return nil, ErrMalformed
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, ErrMalformed
	}
}
