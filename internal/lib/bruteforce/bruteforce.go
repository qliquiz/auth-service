// Package bruteforce provides Redis-backed protection against credential stuffing
// and brute-force login attacks, with an in-process fallback for Redis outages.
package bruteforce

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	attemptsKeyPrefix = "bf:attempts:"
	lockedKeyPrefix   = "bf:locked:"
)

// localEntry is an in-process fallback record used when Redis is unavailable.
type localEntry struct {
	mu          sync.Mutex
	count       int
	windowEnd   time.Time
	lockedUntil time.Time
}

func (e *localEntry) isLocked(now time.Time) bool {
	return now.Before(e.lockedUntil)
}

func (e *localEntry) recordFailure(now time.Time, maxAttempts int, window, lockoutTTL time.Duration) bool {
	if now.After(e.windowEnd) {
		e.count = 0
		e.windowEnd = now.Add(window)
	}
	e.count++
	if e.count >= maxAttempts {
		e.lockedUntil = now.Add(lockoutTTL)
		e.count = 0
		return true
	}
	return false
}

// Guard tracks failed login attempts per email and enforces temporary account lockout.
// Redis is the primary store; the in-process map is a fallback activated only when
// Redis is unreachable, providing best-effort protection with no persistence guarantee.
type Guard struct {
	redis       *redis.Client
	maxAttempts int
	window      time.Duration
	lockoutTTL  time.Duration
	local       sync.Map // map[string]*localEntry — fallback when Redis is down
}

// New creates a Guard.
//   - maxAttempts: number of consecutive failures before lockout
//   - window: sliding window for counting attempts (resets if no failures occur)
//   - lockoutTTL: how long the account stays locked after threshold is reached
func New(redisClient *redis.Client, maxAttempts int, window, lockoutTTL time.Duration) *Guard {
	return &Guard{
		redis:       redisClient,
		maxAttempts: maxAttempts,
		window:      window,
		lockoutTTL:  lockoutTTL,
	}
}

func (g *Guard) localEntry(email string) *localEntry {
	v, _ := g.local.LoadOrStore(email, &localEntry{})
	return v.(*localEntry)
}

// IsLocked returns true if the email is currently subject to a lockout.
// Falls back to the in-process map when Redis is unavailable.
func (g *Guard) IsLocked(ctx context.Context, email string) (bool, error) {
	n, err := g.redis.Exists(ctx, lockedKeyPrefix+email).Result()
	if err != nil {
		// Redis unavailable: consult the in-process fallback.
		e := g.localEntry(email)
		e.mu.Lock()
		locked := e.isLocked(time.Now())
		e.mu.Unlock()
		return locked, nil
	}
	return n > 0, nil
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

// RecordFailure increments the failure counter for the email.
// Returns (true, nil) when the threshold is reached and the account is now locked.
// The caller should still return an Unauthenticated or ResourceExhausted error to the client.
// Falls back to the in-process map when Redis is unavailable.
func (g *Guard) RecordFailure(ctx context.Context, email string) (locked bool, err error) {
	attemptsKey := attemptsKeyPrefix + email

	count, err := g.redis.Eval(ctx, luaIncrExpire, []string{attemptsKey}, int64(g.window.Seconds())).Int64()
	if err != nil {
		// Redis unavailable: record failure in the in-process fallback.
		e := g.localEntry(email)
		e.mu.Lock()
		wasLocked := e.recordFailure(time.Now(), g.maxAttempts, g.window, g.lockoutTTL)
		e.mu.Unlock()
		return wasLocked, nil
	}

	if count >= int64(g.maxAttempts) {
		if err = g.redis.Set(ctx, lockedKeyPrefix+email, 1, g.lockoutTTL).Err(); err != nil {
			return false, fmt.Errorf("bruteforce lock: %w", err)
		}
		// Remove the counter — the lock key is now the authority.
		_ = g.redis.Del(ctx, attemptsKey).Err()
		return true, nil
	}

	return false, nil
}

// Reset clears both the failure counter and any existing lock for the email.
// Call this after a successful authentication.
func (g *Guard) Reset(ctx context.Context, email string) {
	_ = g.redis.Del(ctx, attemptsKeyPrefix+email, lockedKeyPrefix+email).Err()
	// Also clear the in-process fallback so a Redis recovery doesn't leave a
	// ghost counter that was accumulated during the outage.
	g.local.Delete(email)
}

// AttemptsRemaining returns how many more failures are allowed before lockout.
// Returns 0 if already locked.
func (g *Guard) AttemptsRemaining(ctx context.Context, email string) (int, error) {
	locked, err := g.IsLocked(ctx, email)
	if err != nil || locked {
		return 0, err
	}

	count, err := g.redis.Get(ctx, attemptsKeyPrefix+email).Int()
	if err != nil {
		if err == redis.Nil {
			return g.maxAttempts, nil
		}
		return 0, fmt.Errorf("bruteforce remaining: %w", err)
	}

	return max(g.maxAttempts-count, 0), nil
}
