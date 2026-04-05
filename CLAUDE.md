# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Authentication microservice built in Go, exposing both gRPC and REST (via gRPC-Gateway) APIs. Backed by PostgreSQL (user storage) and Redis (sessions/tokens).

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

**Key wiring:** `internal/app/app.go` is the dependency injection root — it constructs UserRepository → AuthService → gRPC server + HTTP gateway and passes them all down.

**Two binaries:**
- `cmd/auth-service/` — main application
- `cmd/migrator/` — standalone migration runner (used in Docker entrypoint before app starts)

## Code Generation

Protocol Buffer definitions live in `api/auth/auth.proto`. Generated code goes to `gen/api/` (do not edit manually). Run `make proto` after any `.proto` changes.

The gateway uses `google/api/annotations.proto` to map HTTP routes onto gRPC methods — HTTP bindings are defined inline in the proto file.

## Configuration

Loaded from `.env` via `cleanenv`. Key variables:

| Variable | Default | Notes |
|----------|---------|-------|
| `ENV` | `local` | `local` (pretty logs), `dev`/`prod` (JSON) |
| `GRPC_PORT` | `8082` | gRPC listen port |
| `GATEWAY_PORT` | `8080` | HTTP gateway port |
| `POSTGRES_*` | — | Host, port, user, password, db |
| `REDIS_*` | — | Host, port, optional password |

## API Contracts

Three RPC methods (HTTP + gRPC):

| Method | HTTP | Request | Response |
|--------|------|---------|----------|
| Register | `POST /v1/auth/register` | `{email, password}` | `{user_id}` |
| Login | `POST /v1/auth/login` | `{email, password}` | `{access_token, refresh_token}` |
| ValidateToken | `POST /v1/auth/validate` | `{token}` | `{valid, user_id, roles}` |

## Database Schema

Single migration (`migrations/0001_init.up.sql`):
```sql
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Implementation Status

All three service methods (`Register`, `Login`, `ValidateToken`) and the user repository are currently stubs with TODO comments. The infrastructure (DB pool, Redis client, gRPC server, HTTP gateway, migrations) is fully wired. Implementation work starts in:
- `internal/service/auth/auth.go` — business logic
- `internal/repository/user/user.go` — DB queries
