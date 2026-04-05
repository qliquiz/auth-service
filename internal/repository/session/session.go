package session

import (
	"auth-service/internal/domain/models"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("session not found")

type SessionRepository struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, s *models.Session) error {
	const q = `
		INSERT INTO sessions (user_id, token_hash, device_id, user_agent, ip_address, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, last_used_at`

	return r.db.QueryRow(ctx, q,
		s.UserID, s.TokenHash, s.DeviceID, s.UserAgent, s.IPAddress, s.ExpiresAt,
	).Scan(&s.ID, &s.CreatedAt, &s.LastUsedAt)
}

func (r *SessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	const q = `
		SELECT s.id, s.user_id, u.email, s.token_hash, s.device_id, s.user_agent,
		       s.ip_address, s.expires_at, s.last_used_at, s.created_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1`

	var s models.Session
	err := r.db.QueryRow(ctx, q, tokenHash).Scan(
		&s.ID, &s.UserID, &s.UserEmail, &s.TokenHash, &s.DeviceID, &s.UserAgent,
		&s.IPAddress, &s.ExpiresAt, &s.LastUsedAt, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session by token hash: %w", err)
	}
	return &s, nil
}

func (r *SessionRepository) DeleteByID(ctx context.Context, sessionID, userID string) error {
	const q = `DELETE FROM sessions WHERE id = $1 AND user_id = $2`
	tag, err := r.db.Exec(ctx, q, sessionID, userID)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *SessionRepository) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	const q = `DELETE FROM sessions WHERE token_hash = $1`
	_, err := r.db.Exec(ctx, q, tokenHash)
	return err
}

func (r *SessionRepository) DeleteAllByUserID(ctx context.Context, userID string) (int64, error) {
	const q = `DELETE FROM sessions WHERE user_id = $1`
	tag, err := r.db.Exec(ctx, q, userID)
	if err != nil {
		return 0, fmt.Errorf("delete all sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *SessionRepository) ListByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	const q = `
		SELECT id, user_id, token_hash, device_id, user_agent, ip_address, expires_at, last_used_at, created_at
		FROM sessions
		WHERE user_id = $1
		ORDER BY last_used_at DESC`

	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*models.Session
	for rows.Next() {
		var s models.Session
		if err = rows.Scan(
			&s.ID, &s.UserID, &s.TokenHash, &s.DeviceID, &s.UserAgent,
			&s.IPAddress, &s.ExpiresAt, &s.LastUsedAt, &s.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, &s)
	}

	return sessions, rows.Err()
}
