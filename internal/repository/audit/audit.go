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
