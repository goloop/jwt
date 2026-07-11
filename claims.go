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

// MarshalJSON merges the registered claims and Extra into one JSON object.
// Registered claims take precedence over same-named Extra keys.
func (c Claims) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(c.Extra)+7)
	for k, v := range c.Extra {
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

// UnmarshalJSON extracts the registered claims and keeps the rest in Extra.
func (c *Claims) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Issuer = popString(raw, "iss")
	c.Subject = popString(raw, "sub")
	c.ID = popString(raw, "jti")
	c.ExpiresAt = popInt(raw, "exp")
	c.NotBefore = popInt(raw, "nbf")
	c.IssuedAt = popInt(raw, "iat")
	c.Audience = popAudience(raw, "aud")
	if len(raw) > 0 {
		c.Extra = raw
	} else {
		c.Extra = nil
	}
	return nil
}

func popString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	delete(m, key)
	s, _ := v.(string)
	return s
}

func popInt(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	delete(m, key)
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, _ := n.Int64()
		return i
	default:
		return 0
	}
}

func popAudience(m map[string]any, key string) Audience {
	v, ok := m[key]
	if !ok {
		return nil
	}
	delete(m, key)
	switch a := v.(type) {
	case string:
		return Audience{a}
	case []any:
		out := make(Audience, 0, len(a))
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
