# jwt - довідник

`jwt` - сувора реалізація JWT лише на HS256. Повний український довідник;
англійською - [DOC.md](DOC.md).

## Зміст

- [Дизайн](#дизайн)
- [Claims](#claims)
- [Підпис](#підпис)
- [Перевірка](#перевірка)
- [Опції](#опції)
- [Помилки](#помилки)
- [Нотатки безпеки](#нотатки-безпеки)
- [Межі](#межі)

## Дизайн

Токен - це compact-серіалізація JWS `header.payload.signature`, кожен сегмент -
base64url без padding. Заголовок - константа `{"alg":"HS256","typ":"JWT"}`.
Підтримується лише HMAC-SHA256: немає гнучкості алгоритмів, що усуває цілий клас
JWT-вразливостей (alg confusion, `none`).

## Claims

```go
type Claims struct {
	Issuer    string   // iss
	Subject   string   // sub
	Audience  Audience // aud (string або []string)
	ExpiresAt int64    // exp, Unix-секунди
	NotBefore int64    // nbf
	IssuedAt  int64    // iat
	ID        string   // jti
	Extra     map[string]any // кастомні claim-и
}
```

Час - Unix-секунди (NumericDate за RFC 7519). `Extra` тримає кастомні claim-и і
зливається в payload; зареєстрований claim перемагає однойменний ключ `Extra`.
`Audience` маршалиться в JSON-рядок для одного значення, інакше в масив, і
демаршалиться з обох.

## Підпис

```go
token, err := jwt.Sign(claims, key)
```

Ключ має бути непорожнім (`ErrNoKey`). Підпис маршалить claim-и, base64url-кодує
константний заголовок і payload, і додає HMAC-SHA256 від `header.payload`.

## Перевірка

```go
claims, err := jwt.Verify(token, key, opts...)
```

Кроки по порядку:

1. розбити рівно на три непорожні сегменти (`ErrMalformed`);
2. декодувати заголовок і вимагати `alg=HS256` (`ErrAlgMismatch`);
3. перевірити підпис проти кожного налаштованого ключа constant-time-порівнянням
   (`ErrSignature`) - **до** декодування payload;
4. декодувати payload;
5. вимагати `exp` (`ErrMissingExpiry`) і перевірити `exp`/`nbf`/`iat` з leeway;
6. перевірити issuer і audience, якщо налаштовано.

## Опції

| Опція | Ефект |
|-------|-------|
| `WithKey(key)` | додати ще ключ перевірки (ротація) |
| `WithLeeway(d)` | допуск на розбіжність годинника для exp/nbf/iat |
| `WithIssuer(s)` | вимагати iss == s |
| `WithAudience(s)` | вимагати aud, що містить s |
| `WithClock(fn)` | перевизначити джерело часу (тести) |

## Помилки

`ErrNoKey`, `ErrMalformed`, `ErrAlgMismatch`, `ErrSignature`, `ErrMissingExpiry`,
`ErrExpired`, `ErrNotYetValid`, `ErrIssuedInFuture`, `ErrIssuer`, `ErrAudience`.
Усі - sentinel-помилки, порівнювані через `errors.Is`.

## Нотатки безпеки

- Лише HS256; `none` й асиметричні алгоритми відкидаються.
- Підпис перевіряється constant-time (`hmac.Equal`) до інтерпретації payload,
  тож підроблений payload ніколи не доходить до ваших claim-ів.
- `exp` обов'язковий: токен без строку дії відхиляється.
- Використовуйте ключ високої ентропії від 32 байт (HS256 - SHA-256).
- Парсер профаззено; він не панікує на некоректному вводі.

## Межі

`jwt` робить: підпис і перевірку HS256-токенів із зареєстрованими й кастомними
claim-ами. Не робить: інші алгоритми, `none`, JWE, JWKS чи неперевірений парсинг.
