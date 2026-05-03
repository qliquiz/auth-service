// Package memory provides an in-memory implementation of ports.SessionCache.
// Entries are automatically expired upon access after their TTL.
// Use in tests and single-node deployments that do not need Redis.
package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auth-service/pkg/ports"
)

// Compile-time assertion: Cache must implement ports.SessionCache.
var _ ports.SessionCache = (*Cache)(nil)

type entry struct {
	sess      *ports.CachedSession
	expiresAt time.Time
}

// Cache is a thread-safe, TTL-aware in-memory session cache.
type Cache struct {
	mu    sync.Mutex
	items map[string]entry
}

// New creates an empty Cache.
func New() *Cache {
	return &Cache{items: make(map[string]entry)}
}

func (c *Cache) Set(_ context.Context, tokenHash string, sess *ports.CachedSession, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[tokenHash] = entry{sess: sess, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (c *Cache) Get(_ context.Context, tokenHash string) (*ports.CachedSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[tokenHash]
	if !ok || time.Now().After(e.expiresAt) {
		delete(c.items, tokenHash)
		return nil, fmt.Errorf("cache miss: %s", tokenHash)
	}
	return e.sess, nil
}

func (c *Cache) Delete(_ context.Context, tokenHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, tokenHash)
	return nil
}
