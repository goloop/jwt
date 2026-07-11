package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func hourToken(t *testing.T, mut func(*Claims)) string {
	t.Helper()
	c := Claims{
		Subject:   "user-1",
		Issuer:    "api",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}
	if mut != nil {
		mut(&c)
	}
	tok, err := Sign(c, testKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestRoundTrip(t *testing.T) {
	tok := hourToken(t, func(c *Claims) {
		c.Audience = Audience{"web"}
		c.Extra = map[string]any{"role": "admin"}
	})
	claims, err := Verify(tok, testKey, WithIssuer("api"), WithAudience("web"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.Issuer != "api" {
		t.Fatalf("claims: %+v", claims)
	}
	if claims.Extra["role"] != "admin" {
		t.Fatalf("extra: %+v", claims.Extra)
	}
}

func TestExpired(t *testing.T) {
	tok := hourToken(t, func(c *Claims) { c.ExpiresAt = time.Now().Add(-time.Hour).Unix() })
	if _, err := Verify(tok, testKey); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	// Leeway large enough should accept it.
	if _, err := Verify(tok, testKey, WithLeeway(2*time.Hour)); err != nil {
		t.Fatalf("leeway should accept: %v", err)
	}
}

func TestNotYetValid(t *testing.T) {
	tok := hourToken(t, func(c *Claims) { c.NotBefore = time.Now().Add(time.Hour).Unix() })
	if _, err := Verify(tok, testKey); err != ErrNotYetValid {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
}

func TestMissingExpiry(t *testing.T) {
	// Build a token without exp.
	tok, err := Sign(Claims{Subject: "x", IssuedAt: time.Now().Unix()}, testKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Verify(tok, testKey); err != ErrMissingExpiry {
		t.Fatalf("expected ErrMissingExpiry, got %v", err)
	}
}

func TestTamperedSignature(t *testing.T) {
	tok := hourToken(t, nil)
	if _, err := Verify(tok+"x", testKey); err != ErrSignature {
		t.Fatalf("expected ErrSignature, got %v", err)
	}
	if _, err := Verify(tok, []byte("wrong-key-wrong-key-wrong-key-00")); err != ErrSignature {
		t.Fatalf("expected ErrSignature for wrong key, got %v", err)
	}
}

func TestTamperedPayload(t *testing.T) {
	tok := hourToken(t, nil)
	parts := strings.Split(tok, ".")
	// Re-encode a modified payload but keep the old signature.
	forged, _ := json.Marshal(Claims{Subject: "admin", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)
	if _, err := Verify(strings.Join(parts, "."), testKey); err != ErrSignature {
		t.Fatalf("expected ErrSignature for forged payload, got %v", err)
	}
}

func TestAlgRejected(t *testing.T) {
	// Forge alg=none and alg=RS256 headers with the real payload/signature.
	tok := hourToken(t, nil)
	parts := strings.Split(tok, ".")
	for _, alg := range []string{"none", "RS256", "HS384"} {
		hdr, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
		parts0 := base64.RawURLEncoding.EncodeToString(hdr)
		forged := parts0 + "." + parts[1] + "." + parts[2]
		if _, err := Verify(forged, testKey); err != ErrAlgMismatch {
			t.Fatalf("alg %q: expected ErrAlgMismatch, got %v", alg, err)
		}
	}
}

func TestMalformed(t *testing.T) {
	for _, tok := range []string{"", "a", "a.b", "a.b.c.d", "..", "!.!.!"} {
		if _, err := Verify(tok, testKey); err != ErrMalformed && err != ErrSignature {
			t.Fatalf("token %q: expected malformed/signature, got %v", tok, err)
		}
	}
}

func TestIssuerAudienceMismatch(t *testing.T) {
	tok := hourToken(t, func(c *Claims) { c.Audience = Audience{"web"} })
	if _, err := Verify(tok, testKey, WithIssuer("other")); err != ErrIssuer {
		t.Fatalf("expected ErrIssuer, got %v", err)
	}
	if _, err := Verify(tok, testKey, WithAudience("mobile")); err != ErrAudience {
		t.Fatalf("expected ErrAudience, got %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	oldKey := []byte("old-key-old-key-old-key-old-key0")
	tok, _ := Sign(Claims{Subject: "x", ExpiresAt: time.Now().Add(time.Hour).Unix()}, oldKey)
	// New primary key, old key accepted via WithKey.
	if _, err := Verify(tok, testKey, WithKey(oldKey)); err != nil {
		t.Fatalf("rotation verify: %v", err)
	}
}

func TestAudienceSingleAndArray(t *testing.T) {
	// Single value marshals to a JSON string.
	tok := hourToken(t, func(c *Claims) { c.Audience = Audience{"web"} })
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !strings.Contains(string(payload), `"aud":"web"`) {
		t.Fatalf("single aud not a string: %s", payload)
	}
	// Multiple values marshal to an array and round-trip.
	tok2 := hourToken(t, func(c *Claims) { c.Audience = Audience{"web", "mobile"} })
	claims, err := Verify(tok2, testKey, WithAudience("mobile"))
	if err != nil || !claims.Audience.Contains("mobile") {
		t.Fatalf("array aud: %+v err=%v", claims.Audience, err)
	}
}

func FuzzVerify(f *testing.F) {
	seed, _ := Sign(Claims{Subject: "x", ExpiresAt: time.Now().Add(time.Hour).Unix()}, testKey)
	f.Add(seed)
	f.Add("a.b.c")
	f.Add("")
	f.Add("....")
	f.Fuzz(func(t *testing.T, token string) {
		// Must never panic, whatever the input.
		_, _ = Verify(token, testKey)
	})
}
