# GEMINI.md

This file provides project-specific instructions and context for Gemini CLI when working in this repository.

## Project Overview

`auth-service` is a microservice for authentication and authorization built with **Go 1.25+**. It exposes both **gRPC**
and **REST (gRPC-Gateway)** APIs.

### Architecture

The project follows **Clean Architecture** patterns:

- **API Layer**: gRPC and REST handlers (`internal/app/grpc`, `internal/app/gateway`).
- **Service Layer**: Business logic (`internal/service/auth`).
- **Repository Layer**: Data access for PostgreSQL and Redis (`internal/repository/...`).
- **Domain Models**: Shared data structures (`internal/domain/models`).

### Tech Stack

- **API**: gRPC + gRPC-Gateway (REST)
- **Database**: PostgreSQL 17 (using `pgx/v5`)
- **Cache**: Redis 7 (using `go-redis/v9`)
- **Migrations**: `golang-migrate`
- **Logging**: `slog` (structured logging)
- **Testing**: `testify`, `miniredis`, `testcontainers-go`
- **Security**: Argon2id for password hashing, JWT (HS256) for access tokens, SHA-256 hashed random strings for refresh
  tokens.

## Building and Running

### Key Commands

All major tasks are managed via `Makefile`:

```bash
# Generate gRPC code from .proto files
make proto

# Start infrastructure (PostgreSQL + Redis) in Docker
make compose

# Apply database migrations
make migrate-up

# Rollback latest migration
make migrate-down

# Build the main service binary
make build

# Run the service locally (includes infrastructure start)
make run

# Lint the codebase
make lint

# Clean generated files and binaries
make clean
```

### Testing

- **Unit Tests**: `make test`
- **Integration Tests**: `make test-integration` (Requires Docker/Testcontainers)
- **E2E Tests**: `make test-e2e` (Requires Docker/Testcontainers)
- **All Tests**: `make test-all`
- **Coverage Report**: `make test-cover`

## Development Conventions

### Coding Style

- Follow standard Go idioms and `golangci-lint` rules.
- Use `slog` for all logging. Avoid `fmt.Print` or standard `log`.
- Handle errors explicitly using `fmt.Errorf("...: %w", err)` for wrapping.
- Service methods should return gRPC status codes using `google.golang.org/grpc/status`.

### API Definition

- Define API contracts in `api/auth/auth.proto`.
- Always run `make proto` after modifying `.proto` files.
- REST mappings are defined inline in `.proto` files using `google.api.http` annotations.

### Database & Migrations

- Migrations are stored in `migrations/`.
- Use `cmd/migrator` for running migrations in production-like environments.
- Repositories should use `pgxpool.Pool` for PostgreSQL interactions.

### Security

- **Passwords**: Never store plain-text passwords. Use `internal/lib/password` for hashing/verification.
- **Tokens**: Access tokens are stateless. Refresh tokens are stored in DB and cached in Redis.
- **Audit**: Use `internal/repository/audit` to log security-sensitive events (Login, Register, Logout).
- **Protection**: Brute-force and rate-limiting logic resides in `internal/lib/bruteforce` and `internal/lib/ratelimit`.

## Key Directories

- `api/`: Protocol Buffer definitions.
- `cmd/`: Entry points for `auth-service` and `migrator`.
- `gen/`: Generated gRPC and gRPC-Gateway code (Do not edit manually).
- `internal/app/`: Application bootstrapping (gRPC and Gateway).
- `internal/lib/`: Utility libraries (JWT, Password, Rate-limiting, etc.).
- `internal/service/`: Core business logic.
- `internal/repository/`: Data access implementations.
- `migrations/`: SQL migration files.
- `tests/`: End-to-end and integration test suites.
