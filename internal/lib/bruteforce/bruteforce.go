// Package bruteforce provides Redis-backed protection against credential stuffing
// and brute-force login attacks.
package bruteforce

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	attemptsKeyPrefix = "bf:attempts:"
	lockedKeyPrefix   = "bf:locked:"
)

// Guard tracks failed login attempts per email and enforces temporary account lockout.
type Guard struct {
	redis       *redis.Client
	maxAttempts int
	window      time.Duration
	lockoutTTL  time.Duration
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

// IsLocked returns true if the email is currently subject to a lockout.
func (g *Guard) IsLocked(ctx context.Context, email string) (bool, error) {
	n, err := g.redis.Exists(ctx, lockedKeyPrefix+email).Result()
	if err != nil {
		return false, fmt.Errorf("bruteforce check: %w", err)
	}
	return n > 0, nil
}

// RecordFailure increments the failure counter for the email.
// Returns (true, nil) when the threshold is reached and the account is now locked.
// The caller should still return an Unauthenticated or ResourceExhausted error to the client.
func (g *Guard) RecordFailure(ctx context.Context, email string) (locked bool, err error) {
	attemptsKey := attemptsKeyPrefix + email

	count, err := g.redis.Incr(ctx, attemptsKey).Result()
	if err != nil {
		return false, fmt.Errorf("bruteforce record: %w", err)
	}

	// On the first increment start the window TTL.
	if count == 1 {
		// Ignore error — the key is already set, worst case it has no TTL.
		_ = g.redis.Expire(ctx, attemptsKey, g.window).Err()
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

	remaining := g.maxAttempts - count
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}
