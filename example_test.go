package jwt_test

import (
	"fmt"
	"time"

	"github.com/goloop/jwt"
)

func ExampleSign() {
	key := []byte("0123456789abcdef0123456789abcdef")

	token, err := jwt.Sign(jwt.Claims{
		Subject:   "user-123",
		Issuer:    "api",
		Audience:  jwt.Audience{"web"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Extra:     map[string]any{"role": "admin"},
	}, key)
	if err != nil {
		panic(err)
	}

	claims, err := jwt.Verify(token, key,
		jwt.WithIssuer("api"),
		jwt.WithAudience("web"),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(claims.Subject, claims.Extra["role"])
	// Output: user-123 admin
}
