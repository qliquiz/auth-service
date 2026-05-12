package ports

import "context"

type AuditEventType string

const (
	AuditEventRegister       AuditEventType = "user.register"
	AuditEventLoginSuccess   AuditEventType = "user.login.success"
	AuditEventLoginFailure   AuditEventType = "user.login.failure"
	AuditEventLoginBlocked   AuditEventType = "user.login.blocked"
	AuditEventLogout         AuditEventType = "user.logout"
	AuditEventLogoutAll      AuditEventType = "user.logout_all"
	AuditEventTokenRefresh   AuditEventType = "token.refresh"
	AuditEventSessionRevoke  AuditEventType = "session.revoke"
	AuditEventPasswordChange AuditEventType = "user.password_change"
	AuditEventPasswordResetRequest AuditEventType = "user.password_reset_request"
	AuditEventPasswordReset        AuditEventType = "user.password_reset"
)

type AuditEvent struct {
	UserID    *string
	EventType AuditEventType
	IPAddress string
	UserAgent string
	Metadata  map[string]string
}

type AuditStore interface {
	Log(ctx context.Context, e *AuditEvent) error
}
