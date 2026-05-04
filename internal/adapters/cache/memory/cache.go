package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/domain/ports"
)

var _ ports.SessionCache = (*Cache)(nil)

type entry struct {
	sess      *ports.CachedSession
	expiresAt time.Time
}

type Cache struct {
	mu    sync.Mutex
	items map[string]entry
}

func New() *Cache {
	return &Cache{items: make(map[string]entry)}
}

func (c *Cache) Set(_ context.Context, tokenHash string, sess *ports.CachedSession, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := *sess
	c.items[tokenHash] = entry{sess: &cp, expiresAt: time.Now().Add(ttl)}
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
	cp := *e.sess
	return &cp, nil
}

func (c *Cache) Delete(_ context.Context, tokenHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, tokenHash)
	return nil
}
