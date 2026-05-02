// Package ports defines the port interfaces for the service.
package ports

import (
	"context"
	"time"
)

// CachedSession is the value the service stores per refresh-token hash.
type CachedSession struct {
	SessionID string
	UserID    string
	UserEmail string
	DeviceID  string
	ExpiresAt time.Time
}

// SessionCache provides fast read/write access to session data.
// Implementations must be safe for concurrent use.
// A cache miss (key not found) must return a non-nil error so the service
// can fall back to the database.
type SessionCache interface {
	// Set stores a session under the given token hash with the specified TTL.
	Set(ctx context.Context, tokenHash string, sess *CachedSession, ttl time.Duration) error
	// Get retrieves a cached session. Returns a non-nil error on cache miss
	// or any backend failure.
	Get(ctx context.Context, tokenHash string) (*CachedSession, error)
	// Delete removes a session from the cache. Idempotent — does not error
	// if the key is absent.
	Delete(ctx context.Context, tokenHash string) error
}
