package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"auth-service/internal/lib/ratelimit"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLimiter(t *testing.T, limit int, window time.Duration) (*ratelimit.Limiter, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	return ratelimit.New(client, limit, window), mr
}

func TestAllow_BelowLimit(t *testing.T) {
	t.Parallel()
	l, _ := newLimiter(t, 5, time.Minute)
	ctx := context.Background()

	for i := range 5 {
		allowed, err := l.Allow(ctx, "127.0.0.1")
		require.NoError(t, err)
		assert.True(t, allowed, "request %d should be allowed", i+1)
	}
}

func TestAllow_ExceedsLimit(t *testing.T) {
	t.Parallel()
	l, _ := newLimiter(t, 3, time.Minute)
	ctx := context.Background()

	for range 3 {
		allowed, _ := l.Allow(ctx, "10.0.0.1")
		require.True(t, allowed)
	}

	// 4th request must be denied.
	allowed, err := l.Allow(ctx, "10.0.0.1")
	require.NoError(t, err)
	assert.False(t, allowed, "request beyond limit must be denied")
}

func TestAllow_DifferentKeysIsolated(t *testing.T) {
	t.Parallel()
	l, _ := newLimiter(t, 2, time.Minute)
	ctx := context.Background()

	// Exhaust limit for IP-A.
	_, _ = l.Allow(ctx, "192.168.1.1")
	_, _ = l.Allow(ctx, "192.168.1.1")
	allowed, _ := l.Allow(ctx, "192.168.1.1")
	require.False(t, allowed)

	// IP-B should still be allowed.
	allowed, err := l.Allow(ctx, "192.168.1.2")
	require.NoError(t, err)
	assert.True(t, allowed, "different key must not be affected by another key's limit")
}

func TestAllow_WindowReset(t *testing.T) {
	t.Parallel()
	l, mr := newLimiter(t, 2, time.Minute)
	ctx := context.Background()

	// Exhaust limit.
	_, _ = l.Allow(ctx, "1.2.3.4")
	_, _ = l.Allow(ctx, "1.2.3.4")
	allowed, _ := l.Allow(ctx, "1.2.3.4")
	require.False(t, allowed)

	// Advance clock past the window.
	mr.FastForward(2 * time.Minute)

	// Counter should reset — first request in new window is allowed.
	allowed, err := l.Allow(ctx, "1.2.3.4")
	require.NoError(t, err)
	assert.True(t, allowed, "request must be allowed after window resets")
}

func TestAllow_ExactLimitBoundary(t *testing.T) {
	t.Parallel()
	l, _ := newLimiter(t, 1, time.Minute)
	ctx := context.Background()
	ip := "5.5.5.5"

	allowed, err := l.Allow(ctx, ip)
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = l.Allow(ctx, ip)
	require.NoError(t, err)
	assert.False(t, allowed, "second request when limit=1 must be denied")
}
