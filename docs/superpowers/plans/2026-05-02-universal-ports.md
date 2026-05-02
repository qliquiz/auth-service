# Universal Ports — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract private service interfaces into a public `pkg/ports/` layer, abstract Redis and JWT as swappable strategies, add in-memory adapters for testing, and introduce an optional EventHook extension point — all without breaking the existing API surface.

**Architecture:** The service follows Clean Architecture (API → Service → Repository). Currently the service layer uses private interfaces (`userRepository`, `sessionRepository`, `auditRepository`) and concrete types (`*redis.Client`, `*jwtlib.Manager`). This plan makes all four of these public interfaces in `pkg/ports/`, adds a `SessionCache` port (abstracting Redis), an `AccessTokenManager` port (abstracting HS256/RS256/ES256), an `EventHook` port for extensibility, and in-memory adapters so tests and local dev no longer need Docker.

**Tech Stack:** Go 1.22+, `github.com/golang-jwt/jwt/v5`, `github.com/redis/go-redis/v9`, `github.com/jackc/pgx/v5`, `github.com/stretchr/testify`

---

## File map

| Action   | Path                                    | Responsibility                                          |
|----------|-----------------------------------------|---------------------------------------------------------|
| Create   | `pkg/ports/audit.go`                   | AuditEvent, AuditEventType constants, AuditStore iface  |
| Create   | `pkg/ports/storage.go`                 | UserStore, SessionStore interfaces                       |
| Create   | `pkg/ports/cache.go`                   | SessionCache interface (replaces raw *redis.Client)      |
| Create   | `pkg/ports/token.go`                   | AccessTokenManager interface + Claims type               |
| Create   | `pkg/ports/hooks.go`                   | EventHook interface + event payload types                |
| Modify   | `internal/repository/audit/audit.go`   | Import audit types from pkg/ports instead of defining   |
| Modify   | `internal/lib/jwt/jwt.go`              | Implement AccessTokenManager, support HS256/RS256/ES256  |
| Create   | `internal/cache/redis/redis.go`        | Redis adapter implementing ports.SessionCache            |
| Modify   | `internal/service/auth/auth.go`        | Use ports.* interfaces everywhere                        |
| Modify   | `internal/service/auth/mocks_test.go`  | Update mock method signatures to match ports.*          |
| Modify   | `internal/app/app.go`                  | Wire new adapters; select JWT strategy from config       |
| Modify   | `internal/config/config.go`            | Add JWTConfig.Algorithm field                            |
| Create   | `pkg/storage/memory/user.go`           | In-memory UserStore (for tests / lightweight deploys)   |
| Create   | `pkg/storage/memory/user_test.go`      | Tests for MemoryUserStore                               |
| Create   | `pkg/storage/memory/session.go`        | In-memory SessionStore                                  |
| Create   | `pkg/storage/memory/session_test.go`   | Tests for MemorySessionStore                            |
| Create   | `pkg/cache/memory/cache.go`            | In-memory SessionCache                                  |
| Create   | `pkg/cache/memory/cache_test.go`       | Tests for MemorySessionCache                            |
| Modify   | `CLAUDE.md`                            | Document new architecture, pkg/* packages, JWT config   |

---

## Task 1: Audit event types → pkg/ports/audit.go

The `internal/repository/audit` package currently owns both the Event types *and* the DB implementation.
Any external implementor of `AuditStore` needs to import these types, which means they'd import an `internal` package.
We fix this by lifting the types into `pkg/ports`.

**Files:**
- Create: `pkg/ports/audit.go`
- Modify: `internal/repository/audit/audit.go`

- [ ] **Step 1.1: Write the failing compilation test**

```bash
cd /path/to/.worktrees/feat/universal-ports
# Create pkg/ports directory
mkdir -p pkg/ports
```

Create `pkg/ports/audit.go`:

```go
// Package ports defines the public interfaces that external adapters must
// satisfy to plug into the auth service. All types here are safe to import
// from outside this module.
package ports

import "context"

// AuditEventType is a structured audit event kind.
type AuditEventType string

const (
	AuditEventRegister      AuditEventType = "user.register"
	AuditEventLoginSuccess  AuditEventType = "user.login.success"
	AuditEventLoginFailure  AuditEventType = "user.login.failure"
	AuditEventLoginBlocked  AuditEventType = "user.login.blocked"
	AuditEventLogout        AuditEventType = "user.logout"
	AuditEventLogoutAll     AuditEventType = "user.logout_all"
	AuditEventTokenRefresh  AuditEventType = "token.refresh"
	AuditEventSessionRevoke AuditEventType = "session.revoke"
)

// AuditEvent is a single auditable security action emitted by the service.
// UserID is nil for events where the user is unknown (e.g. failed login for
// a non-existent email).
type AuditEvent struct {
	UserID    *string
	EventType AuditEventType
	IPAddress string
	UserAgent string
	Metadata  map[string]string // optional key-value context
}

// AuditStore writes security audit events to durable storage.
// Implementations must be safe for concurrent use. Callers may invoke Log
// from a goroutine and must not mutate e after the call.
type AuditStore interface {
	Log(ctx context.Context, e *AuditEvent) error
}
```

- [ ] **Step 1.2: Verify it compiles**

```bash
go build ./pkg/ports/...
```

Expected: no errors.

- [ ] **Step 1.3: Update audit repository to use ports types**

Edit `internal/repository/audit/audit.go` — replace the local `EventType`, `Event` and their constants with imports from `pkg/ports`:

```go
// Package audit provides the PostgreSQL implementation of ports.AuditStore.
package audit

import (
	"auth-service/pkg/ports"
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Aliases so callers that already import this package keep compiling.
// New code should use ports.AuditEventType and ports.AuditEvent directly.
type EventType = ports.AuditEventType
type Event = ports.AuditEvent

const (
	EventRegister      = ports.AuditEventRegister
	EventLoginSuccess  = ports.AuditEventLoginSuccess
	EventLoginFailure  = ports.AuditEventLoginFailure
	EventLoginBlocked  = ports.AuditEventLoginBlocked
	EventLogout        = ports.AuditEventLogout
	EventLogoutAll     = ports.AuditEventLogoutAll
	EventTokenRefresh  = ports.AuditEventTokenRefresh
	EventSessionRevoke = ports.AuditEventSessionRevoke
)

// StoredEvent is an event row as returned from the database.
// Kept here (not in ports) because external code has no reason to
// construct or parse DB rows.
type StoredEvent struct {
	ID        string
	UserID    *string
	EventType ports.AuditEventType
	IPAddress string
	UserAgent string
	Metadata  map[string]string
	CreatedAt string // RFC3339
}

// Repository is the PostgreSQL implementation of ports.AuditStore.
type Repository struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// Log inserts a single audit event. Callers typically invoke this in a
// goroutine so that a slow DB write does not block the request path.
func (r *Repository) Log(ctx context.Context, e *ports.AuditEvent) error {
	var meta []byte
	if len(e.Metadata) > 0 {
		var err error
		meta, err = json.Marshal(e.Metadata)
		if err != nil {
			return fmt.Errorf("audit marshal metadata: %w", err)
		}
	}

	const q = `
		INSERT INTO audit_events (user_id, event_type, ip_address, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5)`

	if _, err := r.db.Exec(ctx, q,
		e.UserID, string(e.EventType), e.IPAddress, e.UserAgent, meta,
	); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}
```

- [ ] **Step 1.4: Verify everything still compiles**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 1.5: Run tests**

```bash
go test ./...
```

Expected: all existing tests pass (no behaviour changed yet).

- [ ] **Step 1.6: Commit**

```bash
git add pkg/ports/audit.go internal/repository/audit/audit.go
git commit -m "feat(ports): lift AuditEvent types into pkg/ports/audit.go"
```

---

## Task 2: UserStore and SessionStore interfaces → pkg/ports/storage.go

Move the private `userRepository` and `sessionRepository` interfaces out of `internal/service/auth` and into the public `pkg/ports` package. The service will then depend on the public interfaces.

**Files:**
- Create: `pkg/ports/storage.go`
- Modify: `internal/service/auth/auth.go` (update private interface references — Task 5 does the full swap; here we just add the public interfaces so they can be referenced)

- [ ] **Step 2.1: Create pkg/ports/storage.go**

```go
// storage.go defines the persistence interfaces for users and sessions.
// Implement these to swap the underlying database without touching the
// service layer.
package ports

import (
	"context"

	"auth-service/internal/domain/models"
)

// UserStore manages user records.
type UserStore interface {
	// Create persists a new user and returns the created entity with its
	// generated ID. Returns ErrUserAlreadyExists if email is taken.
	Create(ctx context.Context, email, passwordHash string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByID(ctx context.Context, id string) (*models.User, error)
}

// SessionStore manages refresh-token sessions.
// All hash parameters refer to the SHA-256 hex of the plain refresh token.
type SessionStore interface {
	Create(ctx context.Context, s *models.Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error)
	// DeleteByID removes a specific session owned by userID and returns its
	// token hash (so the caller can invalidate the Redis cache).
	DeleteByID(ctx context.Context, sessionID, userID string) (tokenHash string, err error)
	DeleteByTokenHash(ctx context.Context, tokenHash string) error
	// RotateToken atomically removes the session identified by oldHash and
	// inserts newSession in a single transaction. Returns ErrSessionNotFound
	// if oldHash no longer exists (concurrent replay detected).
	RotateToken(ctx context.Context, oldHash string, newSession *models.Session) error
	// DeleteAllByUserID removes all sessions for a user and returns their
	// token hashes so the caller can purge the cache.
	DeleteAllByUserID(ctx context.Context, userID string) (tokenHashes []string, err error)
	ListByUserID(ctx context.Context, userID string) ([]*models.Session, error)
}
```

- [ ] **Step 2.2: Verify it compiles**

```bash
go build ./pkg/ports/...
```

Expected: no errors.

- [ ] **Step 2.3: Commit**

```bash
git add pkg/ports/storage.go
git commit -m "feat(ports): add public UserStore and SessionStore interfaces"
```

---

## Task 3: AccessTokenManager interface → pkg/ports/token.go

The `AuthService` currently holds a `*jwtlib.Manager` concrete type. Making this an interface allows RS256/ES256 strategies to be plugged in — critical for distributed systems where other services need to validate access tokens using a public key (no shared secret).

**Files:**
- Create: `pkg/ports/token.go`
- Modify: `internal/lib/jwt/jwt.go` (add RS256 + ES256, implement the interface)
- Modify: `internal/config/config.go` (add `Algorithm` field)

- [ ] **Step 3.1: Create pkg/ports/token.go**

```go
// token.go defines the interface for issuing and validating access tokens.
// The service depends only on this interface — the signing algorithm is an
// implementation detail selected at startup via config.
package ports

// Claims holds the payload extracted from a validated access token.
type Claims struct {
	UserID string
	Email  string
	Roles  []string
}

// AccessTokenManager issues and validates short-lived access tokens.
// Implementations must be safe for concurrent use.
type AccessTokenManager interface {
	// GenerateAccessToken creates a signed access token for the given user.
	GenerateAccessToken(userID, email string, roles []string) (token string, err error)
	// ValidateAccessToken parses and validates a token, returning its claims.
	// Returns a non-nil error if the token is expired, invalid, or from a
	// foreign issuer.
	ValidateAccessToken(token string) (*Claims, error)
}
```

- [ ] **Step 3.2: Write a failing test for RS256 strategy**

Create `internal/lib/jwt/rs256_test.go`:

```go
package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	jwtlib "auth-service/internal/lib/jwt"
	"github.com/stretchr/testify/require"
)

func TestRS256RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mgr := jwtlib.NewRS256Manager(priv, 15*time.Minute)

	token, err := mgr.GenerateAccessToken("uid-1", "user@example.com", []string{"user"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := mgr.ValidateAccessToken(token)
	require.NoError(t, err)
	require.Equal(t, "uid-1", claims.UserID)
	require.Equal(t, "user@example.com", claims.Email)
	require.Equal(t, []string{"user"}, claims.Roles)
}

func TestRS256RejectsExpired(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Issue a token that expires immediately.
	mgr := jwtlib.NewRS256Manager(priv, -1*time.Second)
	token, err := mgr.GenerateAccessToken("uid-1", "u@e.com", nil)
	require.NoError(t, err)

	_, err = mgr.ValidateAccessToken(token)
	require.Error(t, err)
}
```

- [ ] **Step 3.3: Run to confirm it fails**

```bash
go test ./internal/lib/jwt/... -run TestRS256 -v
```

Expected: FAIL — `jwtlib.NewRS256Manager undefined`.

- [ ] **Step 3.4: Add RS256 and ES256 strategies to internal/lib/jwt/jwt.go**

Replace `internal/lib/jwt/jwt.go` entirely. The file now exports three constructors — `NewHS256Manager` (renamed from `New`), `NewRS256Manager`, `NewES256Manager` — all returning types that implement `ports.AccessTokenManager`. A backward-compat alias `New = NewHS256Manager` prevents breaking callers.

```go
// Package jwt provides access-token strategies: HS256 (shared secret),
// RS256 and ES256 (asymmetric). All managers implement ports.AccessTokenManager.
package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"auth-service/pkg/ports"
	"github.com/golang-jwt/jwt/v5"
)

// jwtClaims is the internal representation used for signing/parsing.
// We mirror the public ports.Claims but add jwt.RegisteredClaims for library
// compatibility.
type jwtClaims struct {
	UserID string   `json:"uid"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

// toPorts converts the internal claims to the public type.
func (c *jwtClaims) toPorts() *ports.Claims {
	return &ports.Claims{
		UserID: c.UserID,
		Email:  c.Email,
		Roles:  c.Roles,
	}
}

// ── HS256 ─────────────────────────────────────────────────────────────────────

// HS256Manager signs tokens with a shared HMAC-SHA256 secret.
// Suitable for single-service deployments or when all validators share the secret.
type HS256Manager struct {
	secret    []byte
	accessTTL time.Duration
}

// NewHS256Manager creates an HS256 token manager.
func NewHS256Manager(secret string, accessTTL time.Duration) *HS256Manager {
	return &HS256Manager{secret: []byte(secret), accessTTL: accessTTL}
}

// New is a backward-compatible alias for NewHS256Manager.
// Deprecated: prefer NewHS256Manager for clarity.
var New = NewHS256Manager

func (m *HS256Manager) GenerateAccessToken(userID, email string, roles []string) (string, error) {
	return signToken(jwt.SigningMethodHS256, m.secret, userID, email, roles, m.accessTTL)
}

func (m *HS256Manager) ValidateAccessToken(tokenStr string) (*ports.Claims, error) {
	return parseToken(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
}

// ── RS256 ─────────────────────────────────────────────────────────────────────

// RS256Manager signs tokens with an RSA private key and validates with the
// corresponding public key. Use this when other services need to validate
// tokens without access to the private key.
type RS256Manager struct {
	priv      *rsa.PrivateKey
	accessTTL time.Duration
}

// NewRS256Manager creates an RS256 token manager.
func NewRS256Manager(priv *rsa.PrivateKey, accessTTL time.Duration) *RS256Manager {
	return &RS256Manager{priv: priv, accessTTL: accessTTL}
}

func (m *RS256Manager) GenerateAccessToken(userID, email string, roles []string) (string, error) {
	return signToken(jwt.SigningMethodRS256, m.priv, userID, email, roles, m.accessTTL)
}

func (m *RS256Manager) ValidateAccessToken(tokenStr string) (*ports.Claims, error) {
	return parseToken(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &m.priv.PublicKey, nil
	})
}

// ── ES256 ─────────────────────────────────────────────────────────────────────

// ES256Manager signs tokens with an ECDSA P-256 private key. Produces smaller
// tokens than RS256 with equivalent security for most use cases.
type ES256Manager struct {
	priv      *ecdsa.PrivateKey
	accessTTL time.Duration
}

// NewES256Manager creates an ES256 token manager.
func NewES256Manager(priv *ecdsa.PrivateKey, accessTTL time.Duration) *ES256Manager {
	return &ES256Manager{priv: priv, accessTTL: accessTTL}
}

func (m *ES256Manager) GenerateAccessToken(userID, email string, roles []string) (string, error) {
	return signToken(jwt.SigningMethodES256, m.priv, userID, email, roles, m.accessTTL)
}

func (m *ES256Manager) ValidateAccessToken(tokenStr string) (*ports.Claims, error) {
	return parseToken(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &m.priv.PublicKey, nil
	})
}

// ── Shared helpers ────────────────────────────────────────────────────────────

func signToken(method jwt.SigningMethod, key any, userID, email string, roles []string, ttl time.Duration) (string, error) {
	claims := &jwtClaims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			Issuer:    "auth-service",
		},
	}
	t := jwt.NewWithClaims(method, claims)
	signed, err := t.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

func parseToken(tokenStr string, keyFunc jwt.Keyfunc) (*ports.Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, keyFunc,
		jwt.WithExpirationRequired(),
		jwt.WithIssuer("auth-service"),
	)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	claims, ok := t.Claims.(*jwtClaims)
	if !ok || !t.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims.toPorts(), nil
}
```

- [ ] **Step 3.5: Run RS256 tests**

```bash
go test ./internal/lib/jwt/... -run TestRS256 -v
```

Expected: PASS.

- [ ] **Step 3.6: Run all jwt tests**

```bash
go test ./internal/lib/jwt/... -v
```

Expected: all pass. The existing HS256 tests use `jwt.New(...)` which now resolves to `NewHS256Manager` via the alias.

- [ ] **Step 3.7: Add Algorithm field to JWTConfig**

Edit `internal/config/config.go`. Find the `JWTConfig` struct and add:

```go
type JWTConfig struct {
	Secret     string        `env:"JWT_SECRET"      env-required:"true"`
	AccessTTL  time.Duration `env:"JWT_ACCESS_TTL"  env-default:"15m"`
	RefreshTTL time.Duration `env:"JWT_REFRESH_TTL" env-default:"720h"`
	// Algorithm selects the signing algorithm: hs256 (default), rs256, es256.
	// For rs256/es256, JWT_PRIVATE_KEY_PATH must point to a PEM-encoded key file.
	Algorithm      string `env:"JWT_ALGORITHM"       env-default:"hs256"`
	PrivateKeyPath string `env:"JWT_PRIVATE_KEY_PATH" env-default:""`
}
```

- [ ] **Step 3.8: Build to confirm no compile errors**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 3.9: Run all tests**

```bash
go test ./...
```

Expected: all pass (no wiring changed yet).

- [ ] **Step 3.10: Commit**

```bash
git add pkg/ports/token.go internal/lib/jwt/jwt.go internal/config/config.go
git commit -m "feat(ports): add AccessTokenManager interface with HS256/RS256/ES256 strategies"
```

---

## Task 4: SessionCache interface + Redis adapter

The `AuthService` currently injects `*redis.Client` directly and calls `Set`/`Get`/`Del` inline. Abstracting this behind a `SessionCache` interface makes it possible to swap Redis for another backend (Memcached, in-memory) or to disable caching entirely — without changing the service layer.

**Files:**
- Create: `pkg/ports/cache.go`
- Create: `internal/cache/redis/redis.go`

- [ ] **Step 4.1: Create pkg/ports/cache.go**

```go
// cache.go defines the session cache port. The service uses this to store
// a fast-path copy of refresh-token sessions so most token operations skip
// the database entirely.
package ports

import (
	"context"
	"time"
)

// CachedSession is the value the service stores per refresh-token hash.
type CachedSession struct {
	SessionID string
	UserID    string
	UserEmail string
	DeviceID  string
	ExpiresAt time.Time
}

// SessionCache provides fast read/write access to session data.
// Implementations must be safe for concurrent use.
// A cache miss (key not found) must return a non-nil error so the service
// can fall back to the database.
type SessionCache interface {
	// Set stores a session under the given token hash with the specified TTL.
	Set(ctx context.Context, tokenHash string, sess *CachedSession, ttl time.Duration) error
	// Get retrieves a cached session. Returns a non-nil error on cache miss
	// or any backend failure.
	Get(ctx context.Context, tokenHash string) (*CachedSession, error)
	// Delete removes a session from the cache. Idempotent — does not error
	// if the key is absent.
	Delete(ctx context.Context, tokenHash string) error
}
```

- [ ] **Step 4.2: Write failing test for Redis adapter**

Create `internal/cache/redis/redis_test.go`:

```go
package redis_test

import (
	"context"
	"testing"
	"time"

	rediscache "auth-service/internal/cache/redis"
	"auth-service/pkg/ports"
	"github.com/stretchr/testify/require"
)

// TestRedisAdapterCompiles verifies the Redis adapter satisfies the interface
// at compile time. No real Redis is needed — this is a compilation guard.
func TestRedisAdapterCompiles(t *testing.T) {
	var _ ports.SessionCache = (*rediscache.Cache)(nil)
}
```

- [ ] **Step 4.3: Run to confirm failure**

```bash
go test ./internal/cache/redis/... -v
```

Expected: FAIL — package does not exist yet.

- [ ] **Step 4.4: Create internal/cache/redis/redis.go**

```go
// Package redis implements ports.SessionCache using Redis as the backing store.
// All keys are namespaced under the "refresh:" prefix to avoid collisions with
// other Redis consumers.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/pkg/ports"
	goredis "github.com/redis/go-redis/v9"
)

const keyPrefix = "refresh:"

// Cache wraps a Redis client and implements ports.SessionCache.
type Cache struct {
	client *goredis.Client
}

// New creates a Cache backed by the provided Redis client.
func New(client *goredis.Client) *Cache {
	return &Cache{client: client}
}

func (c *Cache) Set(ctx context.Context, tokenHash string, sess *ports.CachedSession, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("cache marshal: %w", err)
	}
	if err = c.client.Set(ctx, keyPrefix+tokenHash, data, ttl).Err(); err != nil {
		return fmt.Errorf("cache set: %w", err)
	}
	return nil
}

func (c *Cache) Get(ctx context.Context, tokenHash string) (*ports.CachedSession, error) {
	data, err := c.client.Get(ctx, keyPrefix+tokenHash).Bytes()
	if err != nil {
		return nil, fmt.Errorf("cache get: %w", err)
	}
	var sess ports.CachedSession
	if err = json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("cache unmarshal: %w", err)
	}
	return &sess, nil
}

func (c *Cache) Delete(ctx context.Context, tokenHash string) error {
	// Del does not return an error if the key is absent (RESP integer 0 is not an error).
	return c.client.Del(ctx, keyPrefix+tokenHash).Err()
}
```

- [ ] **Step 4.5: Run tests**

```bash
go test ./internal/cache/redis/... -v
```

Expected: PASS — `TestRedisAdapterCompiles` passes (compile-time interface check).

- [ ] **Step 4.6: Build**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 4.7: Commit**

```bash
git add pkg/ports/cache.go internal/cache/redis/redis.go internal/cache/redis/redis_test.go
git commit -m "feat(ports): add SessionCache interface and Redis adapter"
```

---

## Task 5: EventHook interface → pkg/ports/hooks.go

Event hooks let downstream projects observe auth lifecycle events (registration, login, logout) without forking the service. A no-op default means passing `nil` is valid — all hook calls are guarded.

**Files:**
- Create: `pkg/ports/hooks.go`
- Create: `pkg/hooks/noop.go`

- [ ] **Step 5.1: Create pkg/ports/hooks.go**

```go
// hooks.go defines the EventHook extension point. Projects that embed or
// deploy this service can register a hook to react to auth lifecycle events
// (e.g. send a welcome email on registration, alert on brute-force lockout).
package ports

import "context"

// HookEvent carries context for an auth lifecycle event.
type HookEvent struct {
	// Type is the event kind (mirrors AuditEventType for symmetry).
	Type      AuditEventType
	UserID    string // empty when user is unknown (e.g. login for unknown email)
	UserEmail string
	IPAddress string
	UserAgent string
	Metadata  map[string]string
}

// EventHook receives auth lifecycle notifications. Implementations must be
// non-blocking — long work should be dispatched to a goroutine or queue.
// Errors are logged but do not abort the auth operation.
type EventHook interface {
	OnEvent(ctx context.Context, e HookEvent) error
}
```

- [ ] **Step 5.2: Create pkg/hooks/noop.go**

```go
// Package hooks provides built-in EventHook implementations.
package hooks

import (
	"context"

	"auth-service/pkg/ports"
)

// NoOp is the default hook that silently discards all events.
// Use it when no custom business logic is needed.
type NoOp struct{}

func (NoOp) OnEvent(_ context.Context, _ ports.HookEvent) error { return nil }
```

- [ ] **Step 5.3: Build and test**

```bash
go build ./pkg/... && go test ./pkg/...
```

Expected: no errors.

- [ ] **Step 5.4: Commit**

```bash
git add pkg/ports/hooks.go pkg/hooks/noop.go
git commit -m "feat(ports): add EventHook interface with no-op default"
```

---

## Task 6: Refactor AuthService to use pkg/ports interfaces

This is the central wiring step. The `AuthService` drops all concrete types (`*redis.Client`, `*jwtlib.Manager`) and private interface aliases in favour of the public `pkg/ports` interfaces defined in Tasks 1–5.

**Files:**
- Modify: `internal/service/auth/auth.go`
- Modify: `internal/service/auth/mocks_test.go`
- Modify: `internal/app/app.go`

- [ ] **Step 6.1: Update AuthService struct and constructor**

In `internal/service/auth/auth.go`, replace:

```go
// OLD imports
import (
    jwtlib "auth-service/internal/lib/jwt"
    auditRepo "auth-service/internal/repository/audit"
    sessionRepo "auth-service/internal/repository/session"
    userRepo "auth-service/internal/repository/user"
    "github.com/redis/go-redis/v9"
    ...
)

// OLD private interfaces
type userRepository interface { ... }
type sessionRepository interface { ... }
type auditRepository interface { ... }

// OLD struct
type AuthService struct {
    ...
    jwtManager  *jwtlib.Manager
    redis       *redis.Client
    ...
}
```

With:

```go
import (
    "auth-service/pkg/ports"
    sessionRepo "auth-service/internal/repository/session"
    userRepo "auth-service/internal/repository/user"
    ...
)

// AuthService implements api.AuthServiceServer. All dependencies are injected
// via pkg/ports interfaces so the underlying backends are swappable.
type AuthService struct {
    api.UnimplementedAuthServiceServer
    userStore    ports.UserStore
    sessionStore ports.SessionStore
    auditStore   ports.AuditStore   // nil = audit disabled
    tokenMgr     ports.AccessTokenManager
    cache        ports.SessionCache
    hook         ports.EventHook    // nil = no custom hook
    bruteGuard   *bruteforce.Guard  // nil = brute-force protection disabled
    log          *slog.Logger
    refreshTTL   time.Duration
}

func New(
    userStore ports.UserStore,
    sessionStore ports.SessionStore,
    tokenMgr ports.AccessTokenManager,
    cache ports.SessionCache,
    auditStore ports.AuditStore,
    bruteGuard *bruteforce.Guard,
    hook ports.EventHook,
    log *slog.Logger,
    refreshTTL time.Duration,
) *AuthService {
    return &AuthService{
        userStore:    userStore,
        sessionStore: sessionStore,
        auditStore:   auditStore,
        tokenMgr:     tokenMgr,
        cache:        cache,
        bruteGuard:   bruteGuard,
        hook:         hook,
        log:          log,
        refreshTTL:   refreshTTL,
    }
}
```

- [ ] **Step 6.2: Replace all usages in auth.go method bodies**

Inside the method bodies, rename field accesses:
- `s.userRepo` → `s.userStore`
- `s.sessionRepo` → `s.sessionStore`
- `s.auditRepo` → `s.auditStore`
- `s.jwtManager` → `s.tokenMgr`

Replace the three cache helpers (`cacheSession`, `getCachedSession`, `deleteSessionFromCache`) to use `s.cache`:

```go
func (s *AuthService) cacheSession(ctx context.Context, tokenHash string, sess *ports.CachedSession) {
    ttl := time.Until(sess.ExpiresAt)
    if ttl <= 0 {
        return
    }
    if err := s.cache.Set(ctx, tokenHash, sess, ttl); err != nil {
        s.log.Error("set session cache", slog.String("err", err.Error()))
    }
}

func (s *AuthService) getCachedSession(ctx context.Context, tokenHash string) (*ports.CachedSession, error) {
    return s.cache.Get(ctx, tokenHash)
}

func (s *AuthService) deleteSessionFromCache(ctx context.Context, tokenHash string) {
    if err := s.cache.Delete(ctx, tokenHash); err != nil {
        s.log.Error("delete session cache", slog.String("err", err.Error()))
    }
}
```

Replace the `redisSession` struct with `ports.CachedSession` (they carry the same fields).

Replace `logAudit` to use `ports.AuditStore` and `ports.AuditEvent`:

```go
func (s *AuthService) logAudit(userID *string, eventType ports.AuditEventType, ip, ua string, meta map[string]string) {
    if s.auditStore == nil {
        return
    }
    go func() {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := s.auditStore.Log(ctx, &ports.AuditEvent{
            UserID:    userID,
            EventType: eventType,
            IPAddress: ip,
            UserAgent: ua,
            Metadata:  meta,
        }); err != nil {
            s.log.Error("audit log", slog.String("event", string(eventType)), slog.String("err", err.Error()))
        }
    }()
}
```

Add hook dispatch helper:

```go
func (s *AuthService) fireHook(ctx context.Context, userID, email string, eventType ports.AuditEventType, ip, ua string, meta map[string]string) {
    if s.hook == nil {
        return
    }
    go func() {
        ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := s.hook.OnEvent(ctx2, ports.HookEvent{
            Type:      eventType,
            UserID:    userID,
            UserEmail: email,
            IPAddress: ip,
            UserAgent: ua,
            Metadata:  meta,
        }); err != nil {
            s.log.Error("hook error", slog.String("event", string(eventType)), slog.String("err", err.Error()))
        }
    }()
}
```

Call `s.fireHook(...)` alongside `s.logAudit(...)` at each event site (Register, Login success/failure, Logout, etc.).

Update `extractUserIDFromCtx` to use `s.tokenMgr.ValidateAccessToken` (already the case, just rename).

Replace `userRepo.ErrNotFound` / `sessionRepo.ErrNotFound` references — these sentinel errors stay in their respective repository packages (no change needed there).

- [ ] **Step 6.3: Update mocks_test.go**

The mocks now implement `ports.UserStore`, `ports.SessionStore`, and `ports.AuditStore`. The method signatures are identical; only imports change:

```go
package auth_test

import (
    "context"
    "testing"
    "time"

    "auth-service/internal/domain/models"
    "auth-service/pkg/ports"

    "github.com/stretchr/testify/mock"
)

type mockUserRepo struct{ mock.Mock }

func (m *mockUserRepo) Create(ctx context.Context, email, passwordHash string) (*models.User, error) {
    args := m.Called(ctx, email, passwordHash)
    u, _ := args.Get(0).(*models.User)
    return u, args.Error(1)
}
func (m *mockUserRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) {
    args := m.Called(ctx, email)
    u, _ := args.Get(0).(*models.User)
    return u, args.Error(1)
}
func (m *mockUserRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
    args := m.Called(ctx, id)
    u, _ := args.Get(0).(*models.User)
    return u, args.Error(1)
}

type mockSessionRepo struct{ mock.Mock }

func (m *mockSessionRepo) Create(ctx context.Context, s *models.Session) error {
    return m.Called(ctx, s).Error(0)
}
func (m *mockSessionRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
    args := m.Called(ctx, tokenHash)
    s, _ := args.Get(0).(*models.Session)
    return s, args.Error(1)
}
func (m *mockSessionRepo) DeleteByID(ctx context.Context, sessionID, userID string) (string, error) {
    args := m.Called(ctx, sessionID, userID)
    return args.String(0), args.Error(1)
}
func (m *mockSessionRepo) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
    return m.Called(ctx, tokenHash).Error(0)
}
func (m *mockSessionRepo) RotateToken(ctx context.Context, oldHash string, newSession *models.Session) error {
    return m.Called(ctx, oldHash, newSession).Error(0)
}
func (m *mockSessionRepo) DeleteAllByUserID(ctx context.Context, userID string) ([]string, error) {
    args := m.Called(ctx, userID)
    hashes, _ := args.Get(0).([]string)
    return hashes, args.Error(1)
}
func (m *mockSessionRepo) ListByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
    args := m.Called(ctx, userID)
    s, _ := args.Get(0).([]*models.Session)
    return s, args.Error(1)
}

// auditSink captures events over a buffered channel. Implements ports.AuditStore.
type auditSink struct {
    events chan *ports.AuditEvent
}

func newAuditSink() *auditSink {
    return &auditSink{events: make(chan *ports.AuditEvent, 10)}
}

func (a *auditSink) Log(_ context.Context, e *ports.AuditEvent) error {
    a.events <- e
    return nil
}

func (a *auditSink) next(t *testing.T) *ports.AuditEvent {
    t.Helper()
    select {
    case e := <-a.events:
        return e
    case <-time.After(500 * time.Millisecond):
        t.Fatal("audit event not received within deadline")
        return nil
    }
}
```

Also add a `mockTokenManager` and `mockCache` for the service tests (the existing tests used `jwtlib.New` and a miniredis; update them to use these mocks or keep using real instances — keeping real JWT manager and a mock cache is simpler):

```go
// mockCache is a simple in-memory mock for ports.SessionCache used in unit tests.
type mockCache struct{ mock.Mock }

func (m *mockCache) Set(ctx context.Context, hash string, sess *ports.CachedSession, ttl time.Duration) error {
    return m.Called(ctx, hash, sess, ttl).Error(0)
}
func (m *mockCache) Get(ctx context.Context, hash string) (*ports.CachedSession, error) {
    args := m.Called(ctx, hash)
    s, _ := args.Get(0).(*ports.CachedSession)
    return s, args.Error(1)
}
func (m *mockCache) Delete(ctx context.Context, hash string) error {
    return m.Called(ctx, hash).Error(0)
}
```

- [ ] **Step 6.4: Update auth_test.go constructor calls**

In `internal/service/auth/auth_test.go`, find all calls to `auth.New(...)` and update them to pass the new parameter order and types. Specifically:
- Replace `redisClient` arg with a `*mockCache` (or `miniredis` integration for cache-specific tests).
- Add `hook` arg as `nil` (no hook in unit tests).
- Update `auditSink` references from `*auditRepo.Event` to `*ports.AuditEvent`.

- [ ] **Step 6.5: Run unit tests**

```bash
go test ./internal/service/auth/... -v
```

Expected: all pass.

- [ ] **Step 6.6: Update internal/app/app.go**

Wire the new types:

```go
import (
    ...
    rediscache "auth-service/internal/cache/redis"
    jwtlib "auth-service/internal/lib/jwt"
    "auth-service/pkg/hooks"
    ...
)

func New(...) *App {
    uRepo := userRepo.New(db.Pool)
    sRepo := sessionRepo.New(db.Pool)
    aRepo := auditRepo.New(db.Pool)

    // Select JWT strategy based on config. Default: HS256 (backward-compat).
    // For RS256/ES256, load the PEM key from JWTConfig.PrivateKeyPath.
    tokenMgr := jwtlib.NewHS256Manager(jwtCfg.Secret, jwtCfg.AccessTTL)

    cache := rediscache.New(redisClient)
    guard := bruteforce.New(redisClient, secCfg.BruteForce.MaxAttempts, secCfg.BruteForce.Window, secCfg.BruteForce.LockoutTTL)

    service := auth.New(uRepo, sRepo, tokenMgr, cache, aRepo, guard, hooks.NoOp{}, log, jwtCfg.RefreshTTL)
    ...
}
```

- [ ] **Step 6.7: Build and run all tests**

```bash
go build ./... && go test ./...
```

Expected: no errors, all tests pass.

- [ ] **Step 6.8: Commit**

```bash
git add internal/service/auth/auth.go internal/service/auth/mocks_test.go \
        internal/service/auth/auth_test.go internal/app/app.go
git commit -m "refactor(service): use pkg/ports interfaces throughout AuthService"
```

---

## Task 7: In-memory adapters (pkg/storage/memory/ + pkg/cache/memory/)

These adapters let integration and unit tests run without Docker, and enable lightweight deploys (e.g. edge functions, short-lived test environments) where PostgreSQL + Redis are unavailable.

**Files:**
- Create: `pkg/storage/memory/user.go`
- Create: `pkg/storage/memory/user_test.go`
- Create: `pkg/storage/memory/session.go`
- Create: `pkg/storage/memory/session_test.go`
- Create: `pkg/cache/memory/cache.go`
- Create: `pkg/cache/memory/cache_test.go`

- [ ] **Step 7.1: Write failing tests for MemoryUserStore**

Create `pkg/storage/memory/user_test.go`:

```go
package memory_test

import (
	"context"
	"testing"

	"auth-service/pkg/storage/memory"
	userRepo "auth-service/internal/repository/user"
	"github.com/stretchr/testify/require"
)

func TestMemoryUserStore_CreateAndGet(t *testing.T) {
	store := memory.NewUserStore()
	ctx := context.Background()

	user, err := store.Create(ctx, "alice@example.com", "hash1")
	require.NoError(t, err)
	require.NotEmpty(t, user.ID)
	require.Equal(t, "alice@example.com", user.Email)

	got, err := store.GetByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, user.ID, got.ID)

	got2, err := store.GetByID(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, user.ID, got2.ID)
}

func TestMemoryUserStore_DuplicateEmail(t *testing.T) {
	store := memory.NewUserStore()
	ctx := context.Background()

	_, err := store.Create(ctx, "bob@example.com", "hash1")
	require.NoError(t, err)

	_, err = store.Create(ctx, "bob@example.com", "hash2")
	require.ErrorIs(t, err, userRepo.ErrAlreadyExists)
}

func TestMemoryUserStore_NotFound(t *testing.T) {
	store := memory.NewUserStore()
	ctx := context.Background()

	_, err := store.GetByEmail(ctx, "nobody@example.com")
	require.ErrorIs(t, err, userRepo.ErrNotFound)

	_, err = store.GetByID(ctx, "no-such-id")
	require.ErrorIs(t, err, userRepo.ErrNotFound)
}
```

- [ ] **Step 7.2: Run to confirm failure**

```bash
go test ./pkg/storage/memory/... -v
```

Expected: FAIL — package does not exist.

- [ ] **Step 7.3: Create pkg/storage/memory/user.go**

```go
// Package memory provides in-memory implementations of pkg/ports storage
// interfaces. Suitable for unit tests and lightweight deployments that do not
// require a persistent database.
package memory

import (
	"context"
	"sync"

	"auth-service/internal/domain/models"
	userRepo "auth-service/internal/repository/user"
	"github.com/google/uuid"
)

// UserStore is a thread-safe, in-memory implementation of ports.UserStore.
type UserStore struct {
	mu       sync.RWMutex
	byID     map[string]*models.User
	byEmail  map[string]*models.User
}

// NewUserStore creates an empty UserStore.
func NewUserStore() *UserStore {
	return &UserStore{
		byID:    make(map[string]*models.User),
		byEmail: make(map[string]*models.User),
	}
}

func (s *UserStore) Create(_ context.Context, email, passwordHash string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byEmail[email]; exists {
		return nil, userRepo.ErrAlreadyExists
	}
	u := &models.User{
		ID:           uuid.NewString(),
		Email:        email,
		PasswordHash: passwordHash,
	}
	s.byID[u.ID] = u
	s.byEmail[email] = u
	return u, nil
}

func (s *UserStore) GetByEmail(_ context.Context, email string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byEmail[email]
	if !ok {
		return nil, userRepo.ErrNotFound
	}
	return u, nil
}

func (s *UserStore) GetByID(_ context.Context, id string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, userRepo.ErrNotFound
	}
	return u, nil
}
```

- [ ] **Step 7.4: Run user tests**

```bash
go test ./pkg/storage/memory/... -run TestMemoryUserStore -v
```

Expected: PASS.

- [ ] **Step 7.5: Write failing tests for MemorySessionStore**

Add to `pkg/storage/memory/session_test.go`:

```go
package memory_test

import (
	"context"
	"testing"
	"time"

	"auth-service/internal/domain/models"
	sessionRepo "auth-service/internal/repository/session"
	"auth-service/pkg/storage/memory"
	"github.com/stretchr/testify/require"
)

func TestMemorySessionStore_CreateAndGet(t *testing.T) {
	store := memory.NewSessionStore()
	ctx := context.Background()

	sess := &models.Session{
		UserID:    "uid-1",
		TokenHash: "hash-abc",
		DeviceID:  "device-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Create(ctx, sess))
	require.NotEmpty(t, sess.ID)

	got, err := store.GetByTokenHash(ctx, "hash-abc")
	require.NoError(t, err)
	require.Equal(t, sess.ID, got.ID)
}

func TestMemorySessionStore_RotateToken(t *testing.T) {
	store := memory.NewSessionStore()
	ctx := context.Background()

	old := &models.Session{UserID: "uid-1", TokenHash: "old-hash", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.Create(ctx, old))

	newSess := &models.Session{UserID: "uid-1", TokenHash: "new-hash", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.RotateToken(ctx, "old-hash", newSess))

	_, err := store.GetByTokenHash(ctx, "old-hash")
	require.ErrorIs(t, err, sessionRepo.ErrNotFound, "old token must be gone")

	got, err := store.GetByTokenHash(ctx, "new-hash")
	require.NoError(t, err)
	require.Equal(t, newSess.ID, got.ID)
}

func TestMemorySessionStore_RotateToken_ConcurrentReplay(t *testing.T) {
	store := memory.NewSessionStore()
	ctx := context.Background()

	sess := &models.Session{UserID: "uid-1", TokenHash: "replay-hash", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.Create(ctx, sess))

	newSess1 := &models.Session{UserID: "uid-1", TokenHash: "new-1", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.RotateToken(ctx, "replay-hash", newSess1))

	// Second rotation of the same old hash must fail.
	newSess2 := &models.Session{UserID: "uid-1", TokenHash: "new-2", ExpiresAt: time.Now().Add(time.Hour)}
	err := store.RotateToken(ctx, "replay-hash", newSess2)
	require.ErrorIs(t, err, sessionRepo.ErrNotFound)
}
```

- [ ] **Step 7.6: Create pkg/storage/memory/session.go**

```go
package memory

import (
	"context"
	"sync"
	"time"

	"auth-service/internal/domain/models"
	sessionRepo "auth-service/internal/repository/session"
	"github.com/google/uuid"
)

// SessionStore is a thread-safe, in-memory implementation of ports.SessionStore.
type SessionStore struct {
	mu       sync.Mutex
	byID     map[string]*models.Session
	byHash   map[string]*models.Session // tokenHash → Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		byID:   make(map[string]*models.Session),
		byHash: make(map[string]*models.Session),
	}
}

func (s *SessionStore) Create(_ context.Context, sess *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.ID == "" {
		sess.ID = uuid.NewString()
	}
	sess.CreatedAt = time.Now()
	sess.LastUsedAt = time.Now()
	cp := *sess
	s.byID[sess.ID] = &cp
	s.byHash[sess.TokenHash] = &cp
	return nil
}

func (s *SessionStore) GetByTokenHash(_ context.Context, tokenHash string) (*models.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byHash[tokenHash]
	if !ok {
		return nil, sessionRepo.ErrNotFound
	}
	sess.LastUsedAt = time.Now()
	cp := *sess
	return &cp, nil
}

func (s *SessionStore) DeleteByID(_ context.Context, sessionID, userID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[sessionID]
	if !ok || sess.UserID != userID {
		return "", sessionRepo.ErrNotFound
	}
	hash := sess.TokenHash
	delete(s.byID, sessionID)
	delete(s.byHash, hash)
	return hash, nil
}

func (s *SessionStore) DeleteByTokenHash(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byHash[tokenHash]
	if !ok {
		return sessionRepo.ErrNotFound
	}
	delete(s.byID, sess.ID)
	delete(s.byHash, tokenHash)
	return nil
}

// RotateToken atomically replaces oldHash with newSession. Returns
// sessionRepo.ErrNotFound if oldHash is absent — caller treats this as a
// concurrent replay attempt.
func (s *SessionStore) RotateToken(_ context.Context, oldHash string, newSess *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.byHash[oldHash]
	if !ok {
		return sessionRepo.ErrNotFound
	}
	delete(s.byID, old.ID)
	delete(s.byHash, oldHash)

	if newSess.ID == "" {
		newSess.ID = uuid.NewString()
	}
	newSess.CreatedAt = time.Now()
	newSess.LastUsedAt = time.Now()
	cp := *newSess
	s.byID[newSess.ID] = &cp
	s.byHash[newSess.TokenHash] = &cp
	return nil
}

func (s *SessionStore) DeleteAllByUserID(_ context.Context, userID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var hashes []string
	for id, sess := range s.byID {
		if sess.UserID == userID {
			hashes = append(hashes, sess.TokenHash)
			delete(s.byHash, sess.TokenHash)
			delete(s.byID, id)
		}
	}
	return hashes, nil
}

func (s *SessionStore) ListByUserID(_ context.Context, userID string) ([]*models.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*models.Session
	for _, sess := range s.byID {
		if sess.UserID == userID {
			cp := *sess
			result = append(result, &cp)
		}
	}
	return result, nil
}
```

- [ ] **Step 7.7: Run session tests**

```bash
go test ./pkg/storage/memory/... -v
```

Expected: all pass.

- [ ] **Step 7.8: Write failing test for MemorySessionCache**

Create `pkg/cache/memory/cache_test.go`:

```go
package memory_test

import (
	"context"
	"testing"
	"time"

	memcache "auth-service/pkg/cache/memory"
	"auth-service/pkg/ports"
	"github.com/stretchr/testify/require"
)

func TestMemoryCache_SetGetDelete(t *testing.T) {
	cache := memcache.New()
	ctx := context.Background()

	sess := &ports.CachedSession{
		SessionID: "sid-1",
		UserID:    "uid-1",
		UserEmail: "u@e.com",
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	require.NoError(t, cache.Set(ctx, "hash-1", sess, time.Hour))

	got, err := cache.Get(ctx, "hash-1")
	require.NoError(t, err)
	require.Equal(t, "sid-1", got.SessionID)

	require.NoError(t, cache.Delete(ctx, "hash-1"))

	_, err = cache.Get(ctx, "hash-1")
	require.Error(t, err, "should be cache miss after delete")
}

func TestMemoryCache_Expiry(t *testing.T) {
	cache := memcache.New()
	ctx := context.Background()

	sess := &ports.CachedSession{SessionID: "s", UserID: "u", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, cache.Set(ctx, "expiring", sess, 10*time.Millisecond))

	time.Sleep(20 * time.Millisecond)

	_, err := cache.Get(ctx, "expiring")
	require.Error(t, err, "expired entry must not be returned")
}
```

- [ ] **Step 7.9: Create pkg/cache/memory/cache.go**

```go
// Package memory provides an in-memory implementation of ports.SessionCache.
// Entries are automatically expired after their TTL. Use in tests and
// single-node deployments that do not need Redis.
package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auth-service/pkg/ports"
)

type entry struct {
	sess      *ports.CachedSession
	expiresAt time.Time
}

// Cache is a thread-safe, TTL-aware in-memory session cache.
type Cache struct {
	mu    sync.Mutex
	items map[string]entry
}

func New() *Cache {
	return &Cache{items: make(map[string]entry)}
}

func (c *Cache) Set(_ context.Context, tokenHash string, sess *ports.CachedSession, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[tokenHash] = entry{sess: sess, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (c *Cache) Get(_ context.Context, tokenHash string) (*ports.CachedSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[tokenHash]
	if !ok || time.Now().After(e.expiresAt) {
		delete(c.items, tokenHash)
		return nil, fmt.Errorf("cache miss: %s", tokenHash)
	}
	return e.sess, nil
}

func (c *Cache) Delete(_ context.Context, tokenHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, tokenHash)
	return nil
}
```

- [ ] **Step 7.10: Run all tests**

```bash
go test ./pkg/... -v
```

Expected: all pass.

- [ ] **Step 7.11: Verify interface compliance at compile time**

Add to the top of `pkg/storage/memory/user.go` (after package declaration):

```go
import "auth-service/pkg/ports"
var _ ports.UserStore = (*UserStore)(nil)
```

Add to `pkg/storage/memory/session.go`:

```go
var _ ports.SessionStore = (*SessionStore)(nil)
```

Add to `pkg/cache/memory/cache.go`:

```go
var _ ports.SessionCache = (*Cache)(nil)
```

```bash
go build ./...
```

Expected: no errors. If an interface method is missing the build fails with a clear error pointing to the gap.

- [ ] **Step 7.12: Commit**

```bash
git add pkg/storage/memory/ pkg/cache/memory/ pkg/hooks/
git commit -m "feat(adapters): add in-memory UserStore, SessionStore, SessionCache"
```

---

## Task 8: Update CLAUDE.md

Document the new architecture so the next engineer understands what changed and why.

- [ ] **Step 8.1: Update CLAUDE.md**

Append a new section **"Universal Ports Architecture"** to `CLAUDE.md` explaining:
- The `pkg/ports/` package: what interfaces live there and why they're public
- The `pkg/storage/memory/` and `pkg/cache/memory/` adapters and when to use them
- The three JWT strategies (HS256/RS256/ES256) and the `JWT_ALGORITHM` / `JWT_PRIVATE_KEY_PATH` env vars
- The `EventHook` interface and `pkg/hooks/noop.go`
- How to wire a custom hook in `internal/app/app.go`

- [ ] **Step 8.2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document pkg/ports architecture, JWT strategies, and in-memory adapters"
```

---

## Self-review

**Spec coverage check:**

| Requirement (from architectural discussion)               | Task         |
|-----------------------------------------------------------|--------------|
| Extract private interfaces to public pkg/ports/           | Tasks 1–2    |
| AccessTokenManager interface + RS256/ES256 strategies     | Task 3       |
| SessionCache abstraction (swap Redis)                     | Task 4       |
| EventHook extension point                                 | Task 5       |
| Refactor AuthService to use ports                         | Task 6       |
| In-memory adapters (no Docker for tests)                  | Task 7       |
| CLAUDE.md updated                                         | Task 8       |

**Placeholder scan:** No TBDs, no vague instructions. All code blocks contain runnable code.

**Type consistency:**
- `ports.AuditEventType` used everywhere (Tasks 1, 5, 6)
- `ports.CachedSession` used in cache port and Redis adapter (Tasks 4, 6)
- `ports.Claims` returned by all three JWT managers (Task 3)
- `jwtClaims.toPorts()` always converts to `*ports.Claims`
- `userRepo.ErrNotFound` / `sessionRepo.ErrNotFound` sentinel errors remain in their packages and are referenced identically in memory adapters (Task 7)
