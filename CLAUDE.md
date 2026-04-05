# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Authentication microservice built in Go, exposing both gRPC and REST (via gRPC-Gateway) APIs. Backed by PostgreSQL (user
storage) and Redis (sessions/tokens).

## Commands

```bash
# Generate Go code from .proto files (must run after editing api/**/*.proto)
make proto

# Start full stack in Docker (DB + Redis + app)
make compose

# Start only infrastructure (PostgreSQL + Redis) in Docker
make db

# Apply database migrations
make migrate-up

# Rollback latest migration
make migrate-down

# Build binary to ./bin/auth-service
make build

# Build + migrate + run locally (requires DB running)
make run

# Start DB in Docker, then build + migrate + run locally
make run-with-db-in-docker

# Lint
make lint

# Clean generated and compiled artifacts
make clean
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

| Variable       | Default | Notes                                      |
|----------------|---------|--------------------------------------------|
| `ENV`          | `local` | `local` (pretty logs), `dev`/`prod` (JSON) |
| `GRPC_PORT`    | `8082`  | gRPC listen port                           |
| `GATEWAY_PORT` | `8080`  | HTTP gateway port                          |
| `POSTGRES_*`   | —       | Host, port, user, password, db             |
| `REDIS_*`      | —       | Host, port, optional password              |

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

Single migration (`migrations/0001_init.up.sql`):

```sql
CREATE TABLE users
(
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMP        DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP        DEFAULT CURRENT_TIMESTAMP
);
```

## Token Strategy

- **Access token** — JWT (HS256), 15 min TTL. Stateless; validated by signature alone.
- **Refresh token** — random 32-byte URL-safe string. Stored as SHA-256 hex hash in `sessions` table and cached in
  Redis (`refresh:{hash}` → JSON). Redis is a write-through cache; DB is the source of truth.
- **Rotation** — every `RefreshToken` call invalidates the old token and issues a new pair.

## Session Redis Cache

Key: `refresh:{sha256_hex}` → JSON `{sid, uid, email, did, exp}`. TTL matches session `expires_at`. On cache miss, falls
back to DB. `LogoutAll` deletes DB rows; Redis keys expire naturally.

## Password Hashing

argon2id with params `m=65536, t=3, p=4`. Stored in PHC string format (`$argon2id$v=19$...`). See
`internal/lib/password/password.go`.
