// Package audit provides the repository for writing security audit events
// to the audit_events table.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EventType is a structured audit event kind.
type EventType string

const (
	EventRegister      EventType = "user.register"
	EventLoginSuccess  EventType = "user.login.success"
	EventLoginFailure  EventType = "user.login.failure"
	EventLoginBlocked  EventType = "user.login.blocked"
	EventLogout        EventType = "user.logout"
	EventLogoutAll     EventType = "user.logout_all"
	EventTokenRefresh  EventType = "token.refresh"
	EventSessionRevoke EventType = "session.revoke"
)

// Event is a single auditable action.
type Event struct {
	UserID    *string // nil for events where the user is unknown (e.g. failed login for non-existent email)
	EventType EventType
	IPAddress string
	UserAgent string
	Metadata  map[string]string // optional key-value context (email, device_id, session_id, …)
}

// StoredEvent is an event as returned from the database.
type StoredEvent struct {
	ID        string
	UserID    *string
	EventType EventType
	IPAddress string
	UserAgent string
	Metadata  map[string]string
	CreatedAt time.Time
}

type Repository struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// Log inserts a single audit event. Callers typically invoke this in a goroutine
// so that a slow DB write does not block the request path.
func (r *Repository) Log(ctx context.Context, e *Event) error {
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
