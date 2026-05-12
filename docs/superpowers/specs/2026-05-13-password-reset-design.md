# PasswordReset — Design Spec

**Date:** 2026-05-13
**Status:** Approved

## Overview

Three-step OTP-based password reset flow for users who have forgotten their password.
No email is sent by the auth service itself — it fires a hook event carrying the plain OTP,
and an external consumer is responsible for delivering the email.

---

## API Contract

**Proto** (`api/auth/auth.proto`):

```protobuf
rpc RequestPasswordReset(RequestPasswordResetRequest) returns (RequestPasswordResetResponse) {
  option (google.api.http) = {
    post: "/v1/auth/password-reset/request"
    body: "*"
  };
}

rpc VerifyResetCode(VerifyResetCodeRequest) returns (VerifyResetCodeResponse) {
  option (google.api.http) = {
    post: "/v1/auth/password-reset/verify"
    body: "*"
  };
}

rpc ResetPassword(ResetPasswordRequest) returns (ResetPasswordResponse) {
  option (google.api.http) = {
    post: "/v1/auth/password-reset/confirm"
    body: "*"
  };
}

message RequestPasswordResetRequest  { string email = 1; }
message RequestPasswordResetResponse {}  // always empty — never reveal whether email exists

message VerifyResetCodeRequest  { string email = 1; string otp = 2; }
message VerifyResetCodeResponse { string reset_token = 1; }

message ResetPasswordRequest  { string reset_token = 1; string new_password = 2; }
message ResetPasswordResponse {}
```

**Auth:** all three endpoints are unauthenticated (no Bearer token required).

---

## Storage — Redis only

No new DB table. Two key namespaces:

| Key | Value (JSON) | TTL |
|-----|-------------|-----|
| `pwreset:{sha256hex(email)}` | `{user_id, otp_hash, attempts}` | 15 min |
| `pwreset_token:{sha256hex(token)}` | `{user_id, email}` | 15 min |

OTP is a 6-digit numeric string. Stored as SHA-256 hex hash — the plain value only appears
in the hook event payload and is never persisted.

`reset_token` is a random 32-byte URL-safe string (same generation as refresh token).
It is one-use: deleted immediately on successful `ResetPassword`.

---

## Port Changes

### `internal/domain/ports/reset.go` — new file

```go
package ports

import (
    "context"
    "time"
)

var ErrResetCodeNotFound  = errors.New("reset code not found or expired")
var ErrResetTokenNotFound = errors.New("reset token not found or expired")

type OTPRecord struct {
    UserID   string
    OTPHash  string
    Attempts int
}

type ResetTokenRecord struct {
    UserID string
    Email  string
}

type PasswordResetStore interface {
    SaveOTP(ctx context.Context, userID, email, otpHash string, ttl time.Duration) error
    GetOTP(ctx context.Context, email string) (*OTPRecord, error)
    IncrOTPAttempts(ctx context.Context, email string) (int, error)
    DeleteOTP(ctx context.Context, email string) error

    SaveResetToken(ctx context.Context, tokenHash, userID, email string, ttl time.Duration) error
    GetResetToken(ctx context.Context, tokenHash string) (*ResetTokenRecord, error)
    DeleteResetToken(ctx context.Context, tokenHash string) error
}
```

### `internal/domain/ports/audit.go`

```go
AuditEventPasswordResetRequest AuditEventType = "user.password_reset_request"
AuditEventPasswordReset        AuditEventType = "user.password_reset"
```

### `internal/domain/ports/hooks.go`

The existing `HookEvent` struct already carries arbitrary fields via `Meta map[string]string`.
No struct change needed — `otp_code` is passed via Meta in the `user.password_reset_requested` event.

---

## Adapter Implementations

### `internal/adapters/cache/redis/reset.go` — new file

Implements `ports.PasswordResetStore` using the existing `*redis.Client`.

| Method | Redis op |
|--------|----------|
| `SaveOTP` | `SET pwreset:{key} <json> EX <ttl>` |
| `GetOTP` | `GET pwreset:{key}` → unmarshal |
| `IncrOTPAttempts` | `GET` → unmarshal → increment attempts → `SET` with remaining TTL via `TTL` then `SET … EXAT` |
| `DeleteOTP` | `DEL pwreset:{key}` |
| `SaveResetToken` | `SET pwreset_token:{key} <json> EX <ttl>` |
| `GetResetToken` | `GET pwreset_token:{key}` → unmarshal |
| `DeleteResetToken` | `DEL pwreset_token:{key}` |

Key derivation: `sha256hex(email)` and `sha256hex(token)` — same `token.Hash()` helper used elsewhere.

### `internal/adapters/cache/memory/reset.go` — new file

In-memory implementation for unit tests. Mutex-guarded map with expiry timestamps checked on read.

---

## Service Logic

**File:** `internal/service/auth/auth.go`

### `RequestPasswordReset`

1. `validate.Email(req.Email)` — `InvalidArgument` if malformed.
2. `userStore.GetByEmail(ctx, req.Email)` — if `ErrUserNotFound`, **return empty response silently** (anti-enumeration). On other errors → `Internal`.
3. Generate 6-digit OTP: `fmt.Sprintf("%06d", rand.IntN(1_000_000))` (crypto/rand via `math/rand` seeded from crypto/rand, or direct `crypto/rand`-based generation).
4. `resetStore.SaveOTP(ctx, user.ID, req.Email, token.Hash(otp), 15*time.Minute)` — overwrites any existing code (implicit re-request).
5. `fireHook` in background: event `AuditEventPasswordResetRequest`, Meta `{"otp_code": otp}`.
6. `logAudit(AuditEventPasswordResetRequest, ...)`.
7. Return empty response.

### `VerifyResetCode`

1. `validate.Email(req.Email)` — `InvalidArgument` if malformed.
2. `resetStore.GetOTP(ctx, req.Email)` — `Unauthenticated` ("invalid or expired code") if `ErrResetCodeNotFound`.
3. `attempts = resetStore.IncrOTPAttempts(ctx, req.Email)` — if `attempts > 5`, delete code and return `Unauthenticated` ("too many attempts").
4. Compare `token.Hash(req.OTP)` with `record.OTPHash` — if mismatch, return `Unauthenticated` ("invalid or expired code").
5. `resetStore.DeleteOTP(ctx, req.Email)` — consumed.
6. Generate reset token: `plain, hash = token.Generate()`.
7. `resetStore.SaveResetToken(ctx, hash, record.UserID, req.Email, 15*time.Minute)`.
8. Return `{reset_token: plain}`.

**Note:** IncrOTPAttempts happens before hash comparison so every attempt (including correct ones with replay) is counted.

### `ResetPassword`

1. `validate.Password(req.NewPassword)` — `InvalidArgument` if weak.
2. `resetStore.GetResetToken(ctx, token.Hash(req.ResetToken))` — `Unauthenticated` if `ErrResetTokenNotFound`.
3. `resetStore.DeleteResetToken(ctx, token.Hash(req.ResetToken))` — invalidate immediately (one-use).
4. `password.Hash(req.NewPassword)`.
5. `userStore.UpdatePasswordHash(ctx, record.UserID, newHash)` — `Internal` on error.
6. `sessionStore.DeleteAllByUserID(ctx, record.UserID)` — revoke all sessions. On error → log, do not abort.
7. `deleteSessionFromCache` for each deleted hash.
8. `logAudit(AuditEventPasswordReset, ...)` + `fireHook(AuditEventPasswordReset, ...)` in background.
9. Return empty response.

---

## Rate Limiting

Add all three methods to `sensitiveMethods` in `internal/interceptor/ratelimit.go`:

```go
"RequestPasswordReset": true,
"VerifyResetCode":      true,
"ResetPassword":        true,
```

---

## OTP Generation

Use `crypto/rand` directly:

```go
func generateOTP() (string, error) {
    b := make([]byte, 4)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    n := binary.BigEndian.Uint32(b) % 1_000_000
    return fmt.Sprintf("%06d", n), nil
}
```

Lives in `internal/lib/otp/otp.go`.

---

## Wiring

`AuthService` gets a new field `resetStore ports.PasswordResetStore`.
`auth.New(...)` gains one more parameter. Wired in `internal/app/app.go` with `redisreset.New(redisClient)`.

---

## Testing

- **Unit tests** (`internal/service/auth/auth_test.go`): happy paths for all three RPCs; anti-enumeration (unknown email returns 200); wrong OTP; OTP attempt lockout (>5); expired reset token; weak new password; `UpdatePasswordHash` failure.
- **Memory adapter tests**: `SaveOTP`/`GetOTP`/`IncrOTPAttempts`/`DeleteOTP`; `SaveResetToken`/`GetResetToken`/`DeleteResetToken`; TTL expiry.
- **E2E tests** (`tests/e2e/auth_test.go`): full flow register→request→verify→reset→login with new password; wrong OTP returns Unauthenticated; unknown email returns OK; sessions revoked after reset.

---

## Out of Scope

- SMS / push OTP delivery.
- Admin-triggered password reset.
- "Magic link" (token in email URL instead of OTP).
- Throttling per email address (only per-IP via existing rate limiter).
