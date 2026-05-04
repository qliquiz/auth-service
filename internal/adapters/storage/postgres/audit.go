package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"auth-service/internal/domain/ports"
)

var _ ports.AuditStore = (*AuditRepository)(nil)

type AuditRepository struct {
	db *pgxpool.Pool
}

func NewAuditRepository(db *pgxpool.Pool) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Log(ctx context.Context, e *ports.AuditEvent) error {
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
