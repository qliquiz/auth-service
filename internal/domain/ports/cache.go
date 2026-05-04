package ports

import (
	"context"
	"time"
)

type CachedSession struct {
	SessionID string
	UserID    string
	UserEmail string
	DeviceID  string
	ExpiresAt time.Time
}

type SessionCache interface {
	Set(ctx context.Context, tokenHash string, sess *CachedSession, ttl time.Duration) error
	Get(ctx context.Context, tokenHash string) (*CachedSession, error)
	Delete(ctx context.Context, tokenHash string) error
}
