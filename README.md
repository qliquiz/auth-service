# Auth Service

Микросервис аутентификации и авторизации на Go. Экспонирует gRPC и REST (gRPC-Gateway) API. PostgreSQL — хранилище
пользователей и сессий, Redis — write-through кэш refresh-токенов.

---

## Стек

| Слой       | Технология                 |
|------------|----------------------------|
| Язык       | Go 1.24+                   |
| API        | gRPC + gRPC-Gateway (REST) |
| БД         | PostgreSQL 17              |
| Кэш        | Redis 7                    |
| Миграции   | golang-migrate             |
| Контейнеры | Docker / Docker Compose    |

---

## API

| Метод         | HTTP                                    | Auth       | Описание                                                               |
|---------------|-----------------------------------------|------------|------------------------------------------------------------------------|
| Register      | `POST /v1/auth/register`                | —          | Регистрация нового пользователя                                        |
| Login         | `POST /v1/auth/login`                   | —          | Вход. Возвращает access + refresh токены. Поле `device_id` опционально |
| ValidateToken | `POST /v1/auth/validate`                | —          | Stateless проверка JWT; для межсервисного использования                |
| RefreshToken  | `POST /v1/auth/refresh`                 | —          | Ротация токенов. Старый refresh-токен немедленно инвалидируется        |
| Logout        | `POST /v1/auth/logout`                  | —          | Завершение сессии по `refresh_token` в теле запроса                    |
| LogoutAll     | `POST /v1/auth/logout-all`              | Bearer JWT | Инвалидация всех сессий пользователя                                   |
| ListSessions  | `GET /v1/auth/sessions`                 | Bearer JWT | Список активных сессий с информацией об устройствах                    |
| RevokeSession | `DELETE /v1/auth/sessions/{session_id}` | Bearer JWT | Отзыв конкретной сессии                                                |

Защищённые эндпоинты требуют заголовка `Authorization: Bearer <access_token>` (HTTP) или metadata `authorization` (
gRPC).

Интерактивная документация (Scalar UI): `http://localhost:8080/docs` — доступна при `ENV=local` или `ENV=dev`.

---

## Конфигурация

Загружается из `.env` через `cleanenv`.

```env
ENV=local               # local (pretty-логи), dev/prod (JSON)
GRPC_PORT=8082
GATEWAY_PORT=8080
GRPC_TIMEOUT=5s         # deadline for completing new connection handshakes

JWT_SECRET=your-secret-min-32-chars
JWT_ACCESS_TTL=15m
JWT_REFRESH_TTL=720h    # 30 дней

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=auth_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Gateway → gRPC connection
GATEWAY_GRPC_TARGET=         # override gRPC backend host:port (default: localhost:<GRPC_PORT>)
GATEWAY_GRPC_TLS_CERT=       # path to gRPC server TLS cert; leave empty for insecure loopback (dev)

# Brute-force protection
BRUTE_FORCE_MAX_ATTEMPTS=5   # failed logins before lockout
BRUTE_FORCE_WINDOW=15m       # rolling window for counting failures
BRUTE_FORCE_LOCKOUT_TTL=15m  # how long the account stays locked

# Rate limiting (per IP)
RATE_LIMIT_GLOBAL_RPM=300    # max requests/min across all endpoints
RATE_LIMIT_LOGIN_RPM=20      # stricter limit for Login and Register
```

> Внутри Docker: `POSTGRES_HOST=db`, `REDIS_HOST=redis`.

---

## Быстрый старт

```bash
make compose     # PostgreSQL + Redis в Docker
make migrate-up  # применить миграции (один раз при первом запуске)
make run         # собрать бинарник и запустить приложение локально
```

`make run` уже включает `make compose`, поэтому повторно поднимать инфраструктуру не нужно.

---

## Команды

```bash
make proto              # Перегенерировать gRPC-код из .proto
make build              # Собрать бинарник → ./bin/auth-service
make compose            # Поднять PostgreSQL + Redis в Docker
make run                # compose + build + запуск приложения локально
make migrate-up         # Применить миграции
make migrate-down       # Откатить последнюю миграцию
make lint               # golangci-lint
make clean              # Удалить gen/, bin/, coverage-файлы
```

---

## Тесты

```bash
make test               # юнит-тесты (без Docker)
make test-integration   # интеграционные тесты репозитория (требует Docker)
make test-e2e           # E2E тесты полного стека (требует Docker)
make test-all           # все три уровня
make test-cover         # юнит-тесты + HTML-отчёт → tests/coverage.html
```

Интеграционные и E2E тесты используют [testcontainers-go](https://golang.testcontainers.org/) — Docker поднимается
автоматически.

Один тест:

```bash
go test ./internal/service/auth/... -run TestLogin_WrongPassword -v
```

---

## Примеры запросов

### HTTP (cURL)

```bash
# Регистрация
curl -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepassword"}'

# Вход
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepassword","device_id":"my-laptop"}'

# Обновление токенов
curl -X POST http://localhost:8080/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

# Список сессий
curl -X GET http://localhost:8080/v1/auth/sessions \
  -H "Authorization: Bearer <access_token>"
```

### gRPC (grpcurl)

```bash
grpcurl -plaintext \
  -d '{"email":"user@example.com","password":"securepassword"}' \
  localhost:8082 api.AuthService/Login
```

---

## Архитектура

```
HTTP :8080 (gRPC-Gateway)
      │
gRPC :8082
      │
   AuthService
   ├── UserRepository    → PostgreSQL
   └── SessionRepository → PostgreSQL + Redis (write-through cache)
```

**Токены:**

- **Access token** — JWT HS256, TTL 15 мин, stateless.
- **Refresh token** — случайная 32-байтовая строка, хранится как SHA-256 хэш в `sessions` и в Redis (`refresh:{hash}` →
  JSON). TTL совпадает с `expires_at` сессии.
- **Ротация** — при RefreshToken старый токен атомарно удаляется и новый создаётся в одной DB-транзакции, предотвращая replay при параллельных запросах.
- **Logout / RevokeSession / LogoutAll** — явно удаляют Redis-ключи (нет окна stale-cache).

**Пароли:** argon2id (`m=65536, t=3, p=4`) в формате PHC string.
