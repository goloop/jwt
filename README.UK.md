[![Go Reference](https://img.shields.io/badge/godoc-reference-blue)](https://pkg.go.dev/github.com/goloop/jwt) [![License](https://img.shields.io/badge/license-MIT-brightgreen)](https://github.com/goloop/jwt/blob/master/LICENSE) [![Stay with Ukraine](https://img.shields.io/static/v1?label=Stay%20with&message=Ukraine%20♥&color=ffD700&labelColor=0057B8&style=flat)](https://u24.gov.ua/)

# jwt

`jwt` видає й перевіряє компактні JSON Web Token-и, свідомо обмежені до
**HS256**. Дотримується compact-серіалізації JWS (RFC 7515) і зареєстрованих
claim-ів (RFC 7519), але підтримує рівно один алгоритм зі суворими дефолтами -
менша поверхня безпечніша. Нуль залежностей, лише стандартна бібліотека.

## Встановлення

```bash
go get github.com/goloop/jwt
```

## Підпис

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

Заголовок завжди `{"alg":"HS256","typ":"JWT"}`. Кастомні claim-и - у
`Claims.Extra`.

## Перевірка

```go
claims, err := jwt.Verify(token, key,
	jwt.WithIssuer("api"),
	jwt.WithAudience("web"),
	jwt.WithLeeway(30*time.Second),
)
```

`Verify`:

- вимагає `alg=HS256` (відкидає `none`, `RS256` тощо);
- вимагає наявний `exp`;
- перевіряє підпис у **constant time до** інтерпретації payload;
- перевіряє `exp`/`nbf`/`iat` з опційним leeway, а також issuer/audience, якщо
  задано.

## Ротація ключів

```go
claims, err := jwt.Verify(token, newKey, jwt.WithKey(oldKey))
```

Токени підписуються первинним ключем; перевірка приймає будь-який налаштований.

## Не підтримується (свідомо)

Алгоритми RS/ES/PS, `none`, шифрування JWE, JWKS і парсинг без перевірки підпису.

## Документація

- Англійський довідник: [DOC.md](DOC.md)
- Український довідник: [DOC.UK.md](DOC.UK.md)

## Ліцензія

MIT - див. [LICENSE](LICENSE).
