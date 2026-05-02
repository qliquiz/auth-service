// Package ports defines the public interfaces that external adapters must
// satisfy to plug into the auth service. All types here are safe to import
// from outside this module.
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
