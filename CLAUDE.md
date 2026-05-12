# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Authentication microservice built in Go, exposing both gRPC and REST (via gRPC-Gateway) APIs. Backed by PostgreSQL (user
storage) and Redis (sessions/tokens).

## Commands

```bash
# Generate Go code from .proto files (must run after editing api/**/*.proto)
make proto

# Start PostgreSQL + Redis in Docker (no app container)
make compose

# Start only PostgreSQL in Docker
make db

# Apply database migrations
make migrate-up

# Rollback latest migration
make migrate-down

# Build binary to ./bin/auth-service
make build

# Start PostgreSQL + Redis in Docker, build binary, run app locally
# (run migrations separately with make migrate-up on first run)
make run

# Lint
make lint

# Clean generated and compiled artifacts
make clean

# Run unit tests
make test

# Run integration tests (requires Docker)
make test-integration

# Run e2e tests (requires Docker)
make test-e2e

# Run all tests
make test-all

# Run unit tests with HTML coverage report → tests/coverage.html
make test-cover
```

Running a single test:

```bash
go test ./internal/service/auth/... -run TestName -v
```

## Architecture

Clean Architecture with three layers:

```
API (gRPC/HTTP) → Service (business logic) → Repository (data access) → PostgreSQL/Redis
```

**Request flow:**

- HTTP clients → gRPC-Gateway (`:8080`) → gRPC Server (`:8082`) → AuthService → UserRepository → pgx pool
- gRPC clients → gRPC Server directly (`:8082`)

**Key wiring:** `internal/app/app.go` is the dependency injection root — it constructs UserRepository → AuthService →
gRPC server + HTTP gateway and passes them all down.

**Two binaries:**

- `cmd/auth-service/` — main application
- `cmd/migrator/` — standalone migration runner (used in Docker entrypoint before app starts)

## Code Generation

Protocol Buffer definitions live in `api/auth/auth.proto`. Generated code goes to `gen/api/` (do not edit manually). Run
`make proto` after any `.proto` changes.

The gateway uses `google/api/annotations.proto` to map HTTP routes onto gRPC methods — HTTP bindings are defined inline
in the proto file.

## Configuration

Loaded from `.env` via `cleanenv`. Key variables:

| Variable                   | Default  | Notes                                                            |
|----------------------------|----------|------------------------------------------------------------------|
| `ENV`                      | `local`  | `local` (pretty logs), `dev`/`prod` (JSON)                       |
| `GRPC_PORT`                | `8081`   | gRPC listen port                                                 |
| `GATEWAY_PORT`             | `8080`   | HTTP gateway port                                                |
| `GRPC_TIMEOUT`             | `5s`     | Deadline for completing new connection handshakes (TLS + HTTP/2) |
| `JWT_SECRET`               | required | HMAC secret; min 32 chars recommended                            |
| `JWT_ACCESS_TTL`           | `15m`    | Access token lifetime                                            |
| `JWT_REFRESH_TTL`          | `720h`   | Refresh token lifetime (30 days)                                 |
| `JWT_ALGORITHM`            | `hs256`  | `hs256`, `rs256`, or `es256`                                     |
| `JWT_PRIVATE_KEY_PATH`     | `""`     | PEM private key path (required for `rs256`/`es256`)              |
| `POSTGRES_*`               | —        | Host, port, user, password, db                                   |
| `REDIS_*`                  | —        | Host, port, optional password                                    |
| `GATEWAY_GRPC_TARGET`      | `""`     | Override gRPC backend address (default: `localhost:<GRPC_PORT>`) |
| `GATEWAY_GRPC_TLS_CERT`    | `""`     | Path to gRPC server TLS cert; empty = insecure loopback (dev)    |
| `BRUTE_FORCE_MAX_ATTEMPTS` | `5`      | Failed logins before account lockout                             |
| `BRUTE_FORCE_WINDOW`       | `15m`    | Rolling window for counting failures                             |
| `BRUTE_FORCE_LOCKOUT_TTL`  | `15m`    | How long an account stays locked                                 |
| `RATE_LIMIT_GLOBAL_RPM`    | `300`    | Max requests/min per IP (all endpoints)                          |
| `RATE_LIMIT_LOGIN_RPM`     | `20`     | Stricter limit for Login and Register endpoints                  |

## API Docs

In `ENV=local` or `ENV=dev`, the gateway exposes:

- `GET /openapi.json` — OpenAPI spec (embedded from `docs/`)
- `GET /docs` — Scalar interactive UI at `http://localhost:8080/docs`

Both endpoints are disabled in `prod`.

## Interceptors

`internal/interceptor/` provides two gRPC unary interceptors wired in `app.go`:

- **`interceptor.Logging`** — logs every request with method, duration, and error code via `slog`.
- **`interceptor.RateLimit`** — enforces the global and login-specific limits via Redis sliding-window counters. IP is
  extracted from `x-forwarded-for` metadata (rightmost entry, set by gRPC-Gateway) or falls back to the gRPC peer
  address. **Fails open** on Redis error to prevent Redis outages from blocking all auth traffic.

Rate limiting runs at the gRPC layer, so it applies to both direct gRPC clients and HTTP clients proxied through
gRPC-Gateway.

## Input Validation

`internal/lib/validate/` is called at the top of `Register` and `Login` before any DB access:

- **Email** — must match `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
- **Password** — minimum 8 characters, at least one letter, at least one digit

Failures return `codes.InvalidArgument`.

## API Contracts

| Method        | HTTP                                    | Auth       | Notes                                                              |
|---------------|-----------------------------------------|------------|--------------------------------------------------------------------|
| Register      | `POST /v1/auth/register`                | —          |                                                                    |
| Login         | `POST /v1/auth/login`                   | —          | Returns access + refresh tokens. Optional `device_id` field.       |
| ValidateToken | `POST /v1/auth/validate`                | —          | Stateless JWT check; for inter-service use.                        |
| RefreshToken  | `POST /v1/auth/refresh`                 | —          | Rotates both tokens. Old refresh token is immediately invalidated. |
| Logout        | `POST /v1/auth/logout`                  | —          | Identified by `refresh_token` in body.                             |
| LogoutAll     | `POST /v1/auth/logout-all`              | Bearer JWT | Revokes all sessions for the user.                                 |
| ListSessions  | `GET /v1/auth/sessions`                 | Bearer JWT | Returns all active sessions with device info.                      |
| RevokeSession | `DELETE /v1/auth/sessions/{session_id}` | Bearer JWT | Revokes a specific session.                                        |

Protected endpoints (`LogoutAll`, `ListSessions`, `RevokeSession`) require `Authorization: Bearer <access_token>` —
works identically for HTTP and gRPC (via metadata).

## Database Schema

Initial schema in `migrations/0001_init.up.sql`. Subsequent migrations:

- `0002` — `sessions` table
- `0003` — `audit_events` table

Current effective `users` schema:

```sql
CREATE TABLE users
(
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ      DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ      DEFAULT CURRENT_TIMESTAMP
);
```

## Token Strategy

- **Access token** — JWT (HS256), 15 min TTL. Stateless; validated by signature alone. Parser enforces `exp` claim
  presence and `iss=auth-service` to reject tokens without expiry or from foreign services.
- **Refresh token** — random 32-byte URL-safe string. Stored as SHA-256 hex hash in `sessions` table and cached in
  Redis (`refresh:{hash}` → JSON). Redis is a write-through cache; DB is the source of truth.
- **Rotation** — `RefreshToken` atomically deletes the old session and inserts the new one in a single DB transaction (
  `RotateToken`). `RowsAffected() == 0` on the delete detects concurrent replay and returns `Unauthenticated`
  immediately.

## Session Redis Cache

Key: `refresh:{sha256_hex}` → JSON `{sid, uid, email, did, exp}`. TTL matches session `expires_at`. On cache miss, falls
back to DB. `Logout`, `LogoutAll`, and `RevokeSession` explicitly delete Redis keys (via `DEL`) in addition to removing
DB rows — no stale-cache window.

## Password Hashing

argon2id with params `m=65536, t=3, p=4`. Stored in PHC string format (`$argon2id$v=19$...`). See
`internal/lib/password/password.go`.

## Hexagonal Architecture

All business logic in `internal/service/auth/` depends exclusively on interfaces from
`internal/domain/ports/` — never on concrete types like `*pgxpool.Pool`, `*redis.Client`,
or `*jwt.Manager`. This makes every backend swappable without touching the service layer.

### internal/domain/ports/ — Domain interfaces

| File         | Interfaces / Types                                               |
|--------------|------------------------------------------------------------------|
| `audit.go`   | `AuditStore`, `AuditEvent`, `AuditEventType` + 8 event constants |
| `storage.go` | `UserStore`, `SessionStore` + 3 sentinel errors                  |
| `cache.go`   | `SessionCache`, `CachedSession`                                  |
| `token.go`   | `AccessTokenManager`, `Claims`                                   |
| `hooks.go`   | `EventHook`, `HookEvent`                                         |

### Concrete adapters

| Adapter                 | Package                              | Implements           |
|-------------------------|--------------------------------------|----------------------|
| PostgreSQL user repo    | `internal/adapters/storage/postgres` | `ports.UserStore`    |
| PostgreSQL session repo | `internal/adapters/storage/postgres` | `ports.SessionStore` |
| PostgreSQL audit repo   | `internal/adapters/storage/postgres` | `ports.AuditStore`   |
| Redis session cache     | `internal/adapters/cache/redis`      | `ports.SessionCache` |
| In-memory user store    | `internal/adapters/storage/memory`   | `ports.UserStore`    |
| In-memory session store | `internal/adapters/storage/memory`   | `ports.SessionStore` |
| In-memory session cache | `internal/adapters/cache/memory`     | `ports.SessionCache` |

### JWT signing strategies

Three strategies are available, selected via `JWT_ALGORITHM`:

| `JWT_ALGORITHM`   | Type             | Use case                                                     |
|-------------------|------------------|--------------------------------------------------------------|
| `hs256` (default) | Symmetric        | Single-service or shared-secret deployments                  |
| `rs256`           | Asymmetric RSA   | Distributed: other services validate without the private key |
| `es256`           | Asymmetric ECDSA | Same as RS256 but smaller tokens                             |

For `rs256`/`es256`, set `JWT_PRIVATE_KEY_PATH` to a PEM-encoded private key file.
Wiring is in `internal/app/app.go` — currently defaults to HS256; extend to read
`jwtCfg.Algorithm` and load the key file for asymmetric strategies.

### EventHook — extension point

`AuthService` accepts an optional `ports.EventHook`. After every auth operation the service
calls `hook.OnEvent(...)` in a background goroutine so hook logic never blocks the request path.
Errors from hooks are logged but do not abort the operation.

The default hook is `hooks.NoOp{}` (defined in `internal/adapters/hooks/noop.go`), which discards all events.
To add custom business logic (e.g. send a welcome email on registration):

```go
type MyHook struct{ mailer Mailer }

func (h *MyHook) OnEvent(ctx context.Context, e ports.HookEvent) error {
    if e.Type == ports.AuditEventRegister {
        return h.mailer.SendWelcome(ctx, e.UserEmail)
    }
    return nil
}
```

Wire it in `internal/app/app.go` by replacing `hooks.NoOp{}` with your implementation.

### In-memory adapters (testing & lightweight deploys)

`internal/adapters/storage/memory` and `internal/adapters/cache/memory` provide fully in-memory
implementations with no external dependencies. Use them in:

- **Unit tests** that need real repository behavior without Docker
- **Local dev** without PostgreSQL/Redis
- **Edge / embedded** deployments where a full DB stack is not feasible

```go
svc := auth.New(
    memory.NewUserStore(),
    memory.NewSessionStore(),
    jwtlib.NewHS256Manager(secret, 15*time.Minute),
    memcache.New(),
    nil, // audit disabled
    nil,   // brute-force disabled
    hooks.NoOp{},
    logger,
    24*time.Hour,
)
```
