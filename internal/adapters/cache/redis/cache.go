package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"auth-service/internal/domain/ports"
)

const keyPrefix = "refresh:"

var _ ports.SessionCache = (*Cache)(nil)

type Cache struct {
	client *redis.Client
}

func New(client *redis.Client) *Cache {
	return &Cache{client: client}
}

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
	return c.client.Del(ctx, keyPrefix+tokenHash).Err()
}
