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

// --- production hardening (v0.1.0) ---------------------------------------

func TestSignRejectsWeakKey(t *testing.T) {
	c := Claims{ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if _, err := Sign(c, []byte("short")); err != ErrWeakKey {
		t.Fatalf("Sign short key = %v, want ErrWeakKey", err)
	}
	if _, err := Sign(c, nil); err != ErrNoKey {
		t.Fatalf("Sign nil key = %v, want ErrNoKey", err)
	}
	if _, err := Verify("a.b.c", []byte("short")); err != ErrWeakKey {
		t.Fatalf("Verify short key = %v, want ErrWeakKey", err)
	}
}

func TestSignRejectsReservedExtra(t *testing.T) {
	c := Claims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Extra:     map[string]any{"exp": 1},
	}
	if _, err := Sign(c, testKey); err != ErrReservedClaim {
		t.Fatalf("Sign reserved Extra = %v, want ErrReservedClaim", err)
	}
}

func TestVerifyRejectsCritHeader(t *testing.T) {
	// Hand-craft a token whose header declares a crit parameter.
	hdr := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"HS256","typ":"JWT","crit":["exp"]}`))
	payload := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"exp":` + itoa(time.Now().Add(time.Hour).Unix()) + `}`))
	sig := sign(testKey, hdr+"."+payload)
	tok := hdr + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := Verify(tok, testKey); err != ErrUnsupportedCritical {
		t.Fatalf("Verify crit = %v, want ErrUnsupportedCritical", err)
	}
}

func TestVerifyRejectsMalformedRegisteredClaim(t *testing.T) {
	// exp as a string, not a number.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":"soon"}`))
	sig := sign(testKey, hdr+"."+payload)
	tok := hdr + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := Verify(tok, testKey); err != ErrMalformed {
		t.Fatalf("Verify string exp = %v, want ErrMalformed", err)
	}
}

func TestVerifyRejectsSegmentWithNewline(t *testing.T) {
	tok := hourToken(t, nil)
	parts := strings.SplitN(tok, ".", 3)
	// Inject a newline the stdlib base64 decoder would otherwise ignore.
	tampered := parts[0] + "\n." + parts[1] + "." + parts[2]
	if _, err := Verify(tampered, testKey); err != ErrMalformed {
		t.Fatalf("Verify newline segment = %v, want ErrMalformed", err)
	}
}

func TestVerifyMaxBytes(t *testing.T) {
	tok := hourToken(t, nil)
	if _, err := Verify(tok, testKey, WithMaxBytes(10)); err != ErrTooLarge {
		t.Fatalf("Verify oversize = %v, want ErrTooLarge", err)
	}
	if _, err := Verify(tok, testKey, WithMaxBytes(len(tok))); err != nil {
		t.Fatalf("Verify at limit = %v, want nil", err)
	}
}

func TestVerifyNilClockIgnored(t *testing.T) {
	tok := hourToken(t, nil)
	if _, err := Verify(tok, testKey, WithClock(nil)); err != nil {
		t.Fatalf("Verify nil clock = %v, want nil (default clock)", err)
	}
}

func TestVerifyExpiryBoundaryExclusive(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	tok := hourToken(t, func(c *Claims) { c.ExpiresAt = exp.Unix() })
	// Exactly at exp (no leeway) must be rejected.
	at := func() time.Time { return exp }
	if _, err := Verify(tok, testKey, WithClock(at)); err != ErrExpired {
		t.Fatalf("Verify at exp = %v, want ErrExpired", err)
	}
}

// itoa avoids importing strconv just for the crafted-token tests.
func itoa(n int64) string {
	return strings.TrimSpace(string(appendInt(nil, n)))
}

func appendInt(b []byte, n int64) []byte {
	if n == 0 {
		return append(b, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(b, tmp[i:]...)
}
