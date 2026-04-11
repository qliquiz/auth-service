// Package ratelimit provides a Redis-backed fixed-window rate limiter.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const keyPrefix = "rl:"

// Limiter implements a fixed-window rate limiter backed by Redis.
// Each IP (or other key) gets `limit` requests per `window`.
type Limiter struct {
	redis  *redis.Client
	limit  int
	window time.Duration
}

// New creates a Limiter.
//   - limit: maximum number of requests per window
//   - window: length of the time window (e.g. time.Minute)
func New(redisClient *redis.Client, limit int, window time.Duration) *Limiter {
	return &Limiter{
		redis:  redisClient,
		limit:  limit,
		window: window,
	}
}

// luaIncrExpire atomically increments a counter and sets its TTL on the first
// increment. Without atomicity, a crash between INCR and EXPIRE would leave a
// counter with no TTL, causing it to persist indefinitely.
const luaIncrExpire = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count`

// Allow returns true if the key is within the rate limit for the current window.
// On Redis failure it fails open (returns true) to avoid blocking legitimate traffic.
func (l *Limiter) Allow(ctx context.Context, key string) (bool, error) {
	windowStart := time.Now().Truncate(l.window).Unix()
	redisKey := fmt.Sprintf("%s%s:%d", keyPrefix, key, windowStart)

	// Use 2× window for TTL so the key is cleaned up after the window closes.
	ttlSecs := int64(l.window * 2 / time.Second)
	count, err := l.redis.Eval(ctx, luaIncrExpire, []string{redisKey}, ttlSecs).Int64()
	if err != nil {
		// Fail open: Redis is unavailable, let the request through.
		return true, fmt.Errorf("rate limiter redis error: %w", err)
	}

	return count <= int64(l.limit), nil
}

// Limit returns the configured request limit per window.
func (l *Limiter) Limit() int { return l.limit }

// Window returns the configured window duration.
func (l *Limiter) Window() time.Duration { return l.window }
