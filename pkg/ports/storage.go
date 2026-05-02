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
