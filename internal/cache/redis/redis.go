// Package redis implements ports.SessionCache using Redis as the backing store.
// All keys are namespaced under the "refresh:" prefix to avoid collisions with
// other Redis consumers.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"auth-service/pkg/ports"
)

const keyPrefix = "refresh:"

// Cache wraps a Redis client and implements ports.SessionCache.
type Cache struct {
	client *redis.Client
}

// New creates a Cache backed by the provided Redis client.
func New(client *redis.Client) *Cache {
	return &Cache{client: client}
}

// Compile-time assertion: Cache must implement ports.SessionCache.
var _ ports.SessionCache = (*Cache)(nil)

func (c *Cache) Set(ctx context.Context, tokenHash string, sess *ports.CachedSession, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("cache marshal: %w", err)
	}
	if err = c.client.Set(ctx, keyPrefix+tokenHash, data, ttl).Err(); err != nil {
		return fmt.Errorf("cache set: %w", err)
	}
	return nil
}

func (c *Cache) Get(ctx context.Context, tokenHash string) (*ports.CachedSession, error) {
	data, err := c.client.Get(ctx, keyPrefix+tokenHash).Bytes()
	if err != nil {
		return nil, fmt.Errorf("cache get: %w", err)
	}
	var sess ports.CachedSession
	if err = json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("cache unmarshal: %w", err)
	}
	return &sess, nil
}

func (c *Cache) Delete(ctx context.Context, tokenHash string) error {
	// Del does not return an error if the key is absent (RESP integer 0 is not an error).
	return c.client.Del(ctx, keyPrefix+tokenHash).Err()
}
