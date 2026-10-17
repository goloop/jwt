package jwt

import (
	"strings"
	"testing"
	"time"
)

func BenchmarkVerifyToken(b *testing.B) {
	key := []byte(strings.Repeat("k", 32))
	token, err := Sign(Claims{Subject: "test", ExpiresAt: time.Now().Add(time.Hour).Unix()}, key)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Verify(token, key); err != nil {
			b.Fatal(err)
		}
	}
}
