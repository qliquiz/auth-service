// storage.go defines the persistence interfaces for users and sessions.
// Implement these to swap the underlying database without touching the
// service layer.
package ports

import (
	"context"

	"auth-service/internal/domain/models"
)

// UserStore manages user records.
type UserStore interface {
	// Create persists a new user and returns the created entity with its
	// generated ID. Returns userrepo.ErrAlreadyExists if the email is taken.
	Create(ctx context.Context, email, passwordHash string) (*models.User, error)
	// GetByEmail returns the user with the given email, or userrepo.ErrNotFound.
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	// GetByID returns the user with the given ID, or userrepo.ErrNotFound.
	GetByID(ctx context.Context, id string) (*models.User, error)
}

// SessionStore manages refresh-token sessions.
// All hash parameters refer to the SHA-256 hex of the plain refresh token.
type SessionStore interface {
	// Create persists a new session; sets s.ID if it is empty.
	Create(ctx context.Context, s *models.Session) error
	// GetByTokenHash returns the session for the given hash, or sessionrepo.ErrNotFound.
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error)
	// DeleteByID removes a specific session owned by userID and returns its
	// token hash (so the caller can invalidate the cache).
	DeleteByID(ctx context.Context, sessionID, userID string) (tokenHash string, err error)
	// DeleteByTokenHash removes the session for the given hash. Idempotent.
	DeleteByTokenHash(ctx context.Context, tokenHash string) error
	// RotateToken atomically removes the session identified by oldHash and
	// inserts newSession in a single transaction. Returns sessionrepo.ErrNotFound
	// if oldHash no longer exists (concurrent replay detected).
	RotateToken(ctx context.Context, oldHash string, newSession *models.Session) error
	// DeleteAllByUserID removes all sessions for a user and returns their
	// token hashes so the caller can purge the cache.
	DeleteAllByUserID(ctx context.Context, userID string) (tokenHashes []string, err error)
	// ListByUserID returns all active sessions for the given user.
	ListByUserID(ctx context.Context, userID string) ([]*models.Session, error)
}
