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
