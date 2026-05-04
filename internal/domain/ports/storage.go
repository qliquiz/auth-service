package ports

import (
	"context"
	"errors"

	"auth-service/internal/domain/models"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrSessionNotFound   = errors.New("session not found")
)

// UserStore manages user records.
type UserStore interface {
	Create(ctx context.Context, email, passwordHash string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByID(ctx context.Context, id string) (*models.User, error)
}

// SessionStore manages refresh-token sessions.
type SessionStore interface {
	Create(ctx context.Context, s *models.Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error)
	DeleteByID(ctx context.Context, sessionID, userID string) (tokenHash string, err error)
	DeleteByTokenHash(ctx context.Context, tokenHash string) error
	RotateToken(ctx context.Context, oldHash string, newSession *models.Session) error
	DeleteAllByUserID(ctx context.Context, userID string) (tokenHashes []string, err error)
	ListByUserID(ctx context.Context, userID string) ([]*models.Session, error)
}
