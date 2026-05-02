package bruteforce_test

import (
	"context"
	"testing"
	"time"

	"auth-service/internal/lib/bruteforce"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testMax    = 3
	testWindow = 5 * time.Minute
	testTTL    = 10 * time.Minute
)

func newGuard(t *testing.T) (*bruteforce.Guard, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	return bruteforce.New(client, testMax, testWindow, testTTL), mr
}

func TestIsLocked_InitiallyFalse(t *testing.T) {
	t.Parallel()
	g, _ := newGuard(t)

	locked, err := g.IsLocked(context.Background(), "user@example.com")
	require.NoError(t, err)
	assert.False(t, locked)
}

func TestRecordFailure_BelowThreshold_NotLocked(t *testing.T) {
	t.Parallel()
	g, _ := newGuard(t)
	ctx := context.Background()
	email := "user@example.com"

	for i := 0; i < testMax-1; i++ {
		locked, err := g.RecordFailure(ctx, email)
		require.NoError(t, err)
		assert.False(t, locked, "should not be locked after attempt %d", i+1)
	}

	isLocked, err := g.IsLocked(ctx, email)
	require.NoError(t, err)
	assert.False(t, isLocked)
}

func TestRecordFailure_ReachesThreshold_Locks(t *testing.T) {
	t.Parallel()
	g, _ := newGuard(t)
	ctx := context.Background()
	email := "target@example.com"

	// First N-1 attempts don't lock.
	for i := 0; i < testMax-1; i++ {
		locked, err := g.RecordFailure(ctx, email)
		require.NoError(t, err)
		require.False(t, locked)
	}

	// Nth attempt triggers lockout.
	locked, err := g.RecordFailure(ctx, email)
	require.NoError(t, err)
	assert.True(t, locked, "account must be locked after %d failures", testMax)

	isLocked, err := g.IsLocked(ctx, email)
	require.NoError(t, err)
	assert.True(t, isLocked)
}

func TestRecordFailure_AttemptsRemaining(t *testing.T) {
	t.Parallel()
	g, _ := newGuard(t)
	ctx := context.Background()
	email := "counter@example.com"

	remaining, err := g.AttemptsRemaining(ctx, email)
	require.NoError(t, err)
	assert.Equal(t, testMax, remaining)

	_, _ = g.RecordFailure(ctx, email)
	remaining, err = g.AttemptsRemaining(ctx, email)
	require.NoError(t, err)
	assert.Equal(t, testMax-1, remaining)
}

func TestReset_ClearsLock(t *testing.T) {
	t.Parallel()
	g, _ := newGuard(t)
	ctx := context.Background()
	email := "reset@example.com"

	// Lock the account.
	for i := 0; i < testMax; i++ {
		_, _ = g.RecordFailure(ctx, email)
	}
	isLocked, _ := g.IsLocked(ctx, email)
	require.True(t, isLocked)

	// Reset must clear the lock.
	g.Reset(ctx, email)

	isLocked, err := g.IsLocked(ctx, email)
	require.NoError(t, err)
	assert.False(t, isLocked)

	remaining, err := g.AttemptsRemaining(ctx, email)
	require.NoError(t, err)
	assert.Equal(t, testMax, remaining)
}

func TestReset_ClearsAttemptCounter(t *testing.T) {
	t.Parallel()
	g, _ := newGuard(t)
	ctx := context.Background()
	email := "partialreset@example.com"

	_, _ = g.RecordFailure(ctx, email)
	_, _ = g.RecordFailure(ctx, email)

	g.Reset(ctx, email)

	remaining, err := g.AttemptsRemaining(ctx, email)
	require.NoError(t, err)
	assert.Equal(t, testMax, remaining, "counter must be cleared after Reset")
}

func TestIsLocked_ExpiresAfterTTL(t *testing.T) {
	t.Parallel()
	g, mr := newGuard(t)
	ctx := context.Background()
	email := "expire@example.com"

	for i := 0; i < testMax; i++ {
		_, _ = g.RecordFailure(ctx, email)
	}

	isLocked, _ := g.IsLocked(ctx, email)
	require.True(t, isLocked)

	// Fast-forward miniredis clock past lockout TTL.
	mr.FastForward(testTTL + time.Second)

	isLocked, err := g.IsLocked(ctx, email)
	require.NoError(t, err)
	assert.False(t, isLocked, "lock must expire after TTL")
}

// ── Redis-down fallback ────────────────────────────────────────────────────────

func newGuardWithDeadRedis(t *testing.T) *bruteforce.Guard {
	t.Helper()
	// Point at a port nothing is listening on so every Redis call errors.
	client := redis.NewClient(&redis.Options{Addr: "localhost:1"})
	t.Cleanup(func() { _ = client.Close() })
	return bruteforce.New(client, testMax, testWindow, testTTL)
}

func TestIsLocked_RedisDown_FallsBackToLocal(t *testing.T) {
	t.Parallel()
	g := newGuardWithDeadRedis(t)
	ctx := context.Background()
	email := "fallback@example.com"

	locked, err := g.IsLocked(ctx, email)
	require.NoError(t, err, "Redis down must not surface an error")
	assert.False(t, locked, "fresh account must not appear locked")
}

func TestRecordFailure_RedisDown_LocalFallbackLocks(t *testing.T) {
	t.Parallel()
	g := newGuardWithDeadRedis(t)
	ctx := context.Background()
	email := "fallback-lock@example.com"

	for i := 0; i < testMax-1; i++ {
		locked, err := g.RecordFailure(ctx, email)
		require.NoError(t, err)
		assert.False(t, locked)
	}

	locked, err := g.RecordFailure(ctx, email)
	require.NoError(t, err)
	assert.True(t, locked, "local fallback must lock after maxAttempts failures")

	// IsLocked must also reflect the local lock.
	isLocked, err := g.IsLocked(ctx, email)
	require.NoError(t, err)
	assert.True(t, isLocked)
}

func TestReset_RedisDown_ClearsLocalLock(t *testing.T) {
	t.Parallel()
	g := newGuardWithDeadRedis(t)
	ctx := context.Background()
	email := "fallback-reset@example.com"

	for i := 0; i < testMax; i++ {
		_, _ = g.RecordFailure(ctx, email)
	}
	isLocked, _ := g.IsLocked(ctx, email)
	require.True(t, isLocked)

	g.Reset(ctx, email)

	isLocked, err := g.IsLocked(ctx, email)
	require.NoError(t, err)
	assert.False(t, isLocked, "Reset must clear the local lock when Redis is down")
}

func TestAttemptsRemaining_RedisDown_FallsBackToLocal(t *testing.T) {
	t.Parallel()
	g := newGuardWithDeadRedis(t)
	ctx := context.Background()
	email := "remaining-fallback@example.com"

	remaining, err := g.AttemptsRemaining(ctx, email)
	require.NoError(t, err)
	assert.Equal(t, testMax, remaining, "no failures yet — full attempts remaining")

	_, _ = g.RecordFailure(ctx, email)
	remaining, err = g.AttemptsRemaining(ctx, email)
	require.NoError(t, err)
	assert.Equal(t, testMax-1, remaining, "one failure recorded locally")
}

func TestMultipleEmails_Isolated(t *testing.T) {
	t.Parallel()
	g, _ := newGuard(t)
	ctx := context.Background()

	// Lock alice.
	for i := 0; i < testMax; i++ {
		_, _ = g.RecordFailure(ctx, "alice@example.com")
	}

	// Bob should not be affected.
	bobLocked, err := g.IsLocked(ctx, "bob@example.com")
	require.NoError(t, err)
	assert.False(t, bobLocked, "bob must not be locked when alice is")
}
