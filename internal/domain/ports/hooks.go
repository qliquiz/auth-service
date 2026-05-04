package ports

import "context"

type HookEvent struct {
	Type      AuditEventType
	UserID    string
	UserEmail string
	IPAddress string
	UserAgent string
	Metadata  map[string]string
}

type EventHook interface {
	OnEvent(ctx context.Context, e HookEvent) error
}
